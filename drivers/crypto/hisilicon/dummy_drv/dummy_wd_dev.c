/*
 *	WrapDriver Accelerator Dummy Driver
 *
 *	Copyright (C) 2016 Kenneth Lee
 */

/**
 * This module is used to test the framework of WrapDrive.
 *
 * It creates MAX_DEV platform devices with MAX_QUEUE queue for each. When the queue
 * is gotten, a kernel thread is created and handle request put into the queue
 * by the user application.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <asm/page.h>
#include <linux/vfio_spimdev.h>
#include "wd_dummy_usr_if.h"
#include "dummy_hw_usr_if.h"

#define MAX_DEV 3
#define MAX_QUEUE 4

static DEFINE_MUTEX(qsmutex);

struct dummy_hw;

struct dummy_hw_queue {
	bool used;
	struct task_struct *tsk;
	__u32 tail;
	int updated;

	struct vfio_spimdev_queue wdq;
	struct dummy_hw_queue_reg *reg;
	struct dummy_hw *hw;
};

static struct dummy_hw {
	int max_copy_size;
	int aflags;
	struct dummy_hw_queue qs[MAX_QUEUE];
	struct platform_device *pdev;
} hws[MAX_DEV];

static ssize_t
aflags_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev->parent);
	struct dummy_hw *hw = (struct dummy_hw *)spimdev->priv;

	pr_err("todo: merge with queue_flags in the future\n");
	return sprintf(buf, "%d", hw->aflags);
}

static ssize_t aflags_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	char *end;
	int value;
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev->parent);
	struct dummy_hw *hw = (struct dummy_hw *)spimdev->priv;

	value = simple_strtol(buf, &end, 0);
	if (end == buf || value != 0)
		return -EINVAL;

	hw->aflags = value;
	return len;
}

static DEVICE_ATTR_RW(aflags);

static ssize_t
max_copy_size_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev->parent);
	struct dummy_hw *hw = (struct dummy_hw *)spimdev->priv;

	return sprintf(buf, "%d", hw->max_copy_size);
}

static ssize_t max_copy_size_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	char *end;
	int value;
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev->parent);
	struct dummy_hw *hw = (struct dummy_hw *)spimdev->priv;

	value = simple_strtol(buf, &end, 0);
	if (end == buf)
		return -EINVAL;

	hw->max_copy_size = value;
	return len;
}

static DEVICE_ATTR_RW(max_copy_size);

static struct attribute *mdev_dev_attrs[] = {
	&dev_attr_max_copy_size.attr,
	&dev_attr_aflags.attr,
	NULL,
};

static const struct attribute_group mdev_dev_group = {
	.name  = VFIO_SPIMDEV_PDEV_ATTRS_GRP_NAME,
	.attrs = mdev_dev_attrs,
};

static const  struct attribute_group *mdev_dev_groups[] = {
	&mdev_dev_group,
	NULL,
};

static struct attribute *mdev_type_attrs[] = {
	VFIO_SPIMDEV_DEFAULT_MDEV_TYPE_ATTRS,
	NULL,
};

static struct attribute_group mdev_type_group = {
	.name = AN_DUMMY_MEMCPY,
	.attrs = mdev_type_attrs,
};

static struct attribute_group *mdev_type_groups[] = {
	&mdev_type_group,
	NULL,
};

/* This function will only work in the requesting process context */
static int _do_user_copy(void *tgt, void *src, size_t len)
{
	void *tmp = kmalloc(len, GFP_KERNEL);
	int ret = 0;

	if (!tmp)
		return -ENOMEM;

	if (copy_from_user(tmp, src, len)) {
		pr_info("fail copy_from_user(%p, %p, %ld)\n",
				tmp, src, len);
		ret = -EFAULT;
		goto out_with_mem;
	}

	if (copy_to_user(tgt, tmp, len)) {
		pr_info("fail copy_to_user(%p, %p, %ld)\n",
				tgt, tmp, len);
		ret = -EFAULT;
		goto out_with_mem;
	}

out_with_mem:
	kfree(tmp);
	return ret;
}

static void _queue_work(struct dummy_hw_queue *hwq)
{
	int bd_num = hwq->reg->ring_bd_num;
	__u32 head = readl(&hwq->reg->head);
	__u32 tail;

	if (head >= bd_num) {
		pr_err("dummy_wd io error, head=%d\n", head);
		return;
	}

	tail = hwq->tail;
	while (hwq->tail != head) {
		if(hwq->reg->ring[hwq->tail].size > hwq->hw->max_copy_size)
			hwq->reg->ring[hwq->tail].ret = -EINVAL;
		else
			hwq->reg->ring[hwq->tail].ret =
			_do_user_copy(hwq->reg->ring[hwq->tail].tgt_addr,
					hwq->reg->ring[hwq->tail].src_addr,
					hwq->reg->ring[hwq->tail].size);
		pr_info("memcpy(%p, %p, %ld) = %d",
			hwq->reg->ring[hwq->tail].tgt_addr,
			hwq->reg->ring[hwq->tail].src_addr,
			hwq->reg->ring[hwq->tail].size,
			hwq->reg->ring[hwq->tail].ret);
		hwq->reg->ring[hwq->tail].ret = 0;
		hwq->tail = (hwq->tail+1)%bd_num;
	}

	if (tail != hwq->tail) {
		pr_info("write back tail %d\n", hwq->tail);
		writel(hwq->tail, &hwq->reg->tail);
		hwq->updated = 1;
		vfio_spimdev_wake_up(&hwq->wdq);
	}
}

static int dummy_is_q_updated(struct vfio_spimdev_queue *q)
{
	struct dummy_hw_queue *hwq = q->priv;
	_queue_work(hwq);
	return hwq->updated;
}

static void dummy_init_hw_queue(struct dummy_hw_queue *hwq, int used)
{
	if (hwq->used == used)
		return;

	hwq->used = used;
	if (used) {
		hwq->reg = (struct dummy_hw_queue_reg *)
			__get_free_page(GFP_KERNEL);
		memcpy(hwq->reg->hw_tag, DUMMY_HW_TAG, DUMMY_HW_TAG_SZ);
		hwq->reg->ring_bd_num = Q_BDS;
		writel(0, &hwq->reg->head);
		writel(0, &hwq->reg->tail);
		hwq->tail = 0;
		hwq->updated = 0;
	} else
		free_page((unsigned long)hwq->reg);
}

static int dummy_get_queue(struct vfio_spimdev *spimdev, unsigned long arg,
			struct vfio_spimdev_queue **q)
{
	int i;
	struct dummy_hw *hw = (struct dummy_hw *)spimdev->priv;
	struct dummy_hw_queue *devqs = hw->qs;

	assert(devqs);

	mutex_lock(&qsmutex);
	for (i = 0; i < MAX_QUEUE; i++) {
		if (!devqs[i].used) {
			dummy_init_hw_queue(&devqs[i], 1);
			*q = &devqs[i].wdq;
			devqs[i].wdq.priv = &devqs[i];
			__module_get(THIS_MODULE);
			break;
		}
	}
	mutex_unlock(&qsmutex);

	if (i < MAX_QUEUE)
		return 0;

	return -ENODEV;
}

static int dummy_put_queue(struct vfio_spimdev_queue *q)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	mutex_lock(&qsmutex);
	dummy_init_hw_queue(hwq, 0);
	mutex_unlock(&qsmutex);
	pr_info("queue released\n");

	module_put(THIS_MODULE);

	return 0;
}

static int dummy_mmap(struct vfio_spimdev_queue *q, struct vm_area_struct *vma)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	if (vma->vm_pgoff != 0 || vma->vm_end - vma->vm_start > PAGE_SIZE)
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start, __pa(hwq->reg)>>PAGE_SHIFT,
		PAGE_SIZE, PAGE_SHARED);
}

static long dummy_ioctl(struct vfio_spimdev_queue *q, unsigned int cmd,
				unsigned long arg)
{
	struct dummy_hw_queue *hwq = q->priv;

	switch (cmd) {
	case DUMMY_CMD_FLUSH:
		_queue_work(hwq);
		return 0;

	default:
		return -EINVAL;
	}
}

static const struct vfio_spimdev_ops dummy_ops = {
	.get_queue = dummy_get_queue,
	.put_queue = dummy_put_queue,
	.is_q_updated = dummy_is_q_updated,
	.mmap = dummy_mmap,
	.ioctl = dummy_ioctl,
};

static int dummy_wd_probe(struct platform_device *pdev)
{
	struct vfio_spimdev *spimdev;
	struct dummy_hw *hw;
	int i;

	if (pdev->id >= MAX_DEV) {
		dev_err(&pdev->dev, "invalid id (%d) for dummy_wd\n", pdev->id);
		return -EINVAL;
	}

	hw = &hws[pdev->id];
	hw->aflags = 0;
	hw->max_copy_size = 4096;

	spimdev = devm_kzalloc(&pdev->dev, sizeof(struct vfio_spimdev), GFP_KERNEL);
	if (!spimdev)
		return -ENOMEM;

	for (i = 0; i < MAX_QUEUE; i++) {
		dummy_init_hw_queue(&hw->qs[i], 0);
		hw->qs[i].wdq.spimdev = spimdev;
		hw->qs[i].hw = hw;
	}

	platform_set_drvdata(pdev, spimdev);
	spimdev->iommu_type = VFIO_NOIOMMU_IOMMU;
	spimdev->owner = THIS_MODULE;
	spimdev->name = DUMMY_WD;
	spimdev->dev = &pdev->dev;
	spimdev->is_vf = 0;
	spimdev->priv = hw;
	spimdev->api_ver = "wd_dummy_v1";
	spimdev->flags = 0;

	spimdev->mdev_fops.supported_type_groups = mdev_type_groups;
	spimdev->mdev_fops.mdev_attr_groups = mdev_dev_groups;

	spimdev->ops = &dummy_ops;

	return vfio_spimdev_register(spimdev);
}

static int dummy_wd_remove(struct platform_device *pdev)
{
	struct vfio_spimdev *spimdev = (struct vfio_spimdev *)pdev->dev.driver_data;
	vfio_spimdev_unregister(spimdev);
	return 0;
}

static struct platform_driver dummy_pdrv = {
	.probe		= dummy_wd_probe,
	.remove		= dummy_wd_remove,
	.driver		= {
		.name		= DUMMY_WD,
	},
};

static int __init dummy_vfio_spimdev_init(void)
{
	int i, j;
	int ret = platform_driver_register(&dummy_pdrv);

	if (ret)
		return ret;

	for (i = 0; i < MAX_DEV; i++) {
		hws[i].pdev = platform_device_alloc(DUMMY_WD, i);
		assert(hws[i]->pdev);
		ret = platform_device_add(hws[i].pdev);
		if (ret)
			goto dev_reg_fail;
	}

	return 0;


dev_reg_fail:
	for (j = i - 1; j >= 0; j--) {
		if(hws[i].pdev)
			platform_device_put(hws[i].pdev);
	}

	platform_driver_unregister(&dummy_pdrv);

	return ret;
}

static void __exit dummy_vfio_spimdev_exit(void)
{
	int i;

	for (i = MAX_DEV - 1; i >= 0; i--)
		platform_device_unregister(hws[i].pdev);

	platform_driver_unregister(&dummy_pdrv);
}

module_init(dummy_vfio_spimdev_init);
module_exit(dummy_vfio_spimdev_exit);

MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
MODULE_LICENSE("GPL");
