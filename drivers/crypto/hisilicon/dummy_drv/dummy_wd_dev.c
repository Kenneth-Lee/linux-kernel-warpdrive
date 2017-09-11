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
#include "../wd/wd.h"
#include "../wd/wd_dummy_usr_if.h"
#include "dummy_hw_usr_if.h"

#define MAX_DEV 3
#define MAX_QUEUE 4

/* this macro enable the req handling in kernel thread. it is risky. because
 * the kernel thread do not own the user context. it can be used for trying
 * only
 */
#undef WD_DUMMY_RISKY_TRY_OUT

static DEFINE_MUTEX(qsmutex);
static struct dummy_hw_queue {
	bool used;
	struct task_struct *tsk;
	__u32 tail;
	int updated;

	//params
	int max_copy_size;
	int aflags;

	struct wd_queue wdq;

	struct dummy_hw_queue_reg *reg;
} qs[MAX_DEV][MAX_QUEUE];

static ssize_t
max_copy_size_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct wd_queue *q = wd_queue(dev);
	struct dummy_hw_queue *dq = (struct dummy_hw_queue *)q->priv;

	return sprintf(buf, "%d", dq->max_copy_size);
}

static ssize_t max_copy_size_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	char *end;
	int value;
	struct wd_queue *q = wd_queue(dev);
	struct dummy_hw_queue *dq = (struct dummy_hw_queue *)q->priv;

	value = simple_strtol(buf, &end, 0);
	if (end == buf)
		return -EINVAL;

	dq->max_copy_size = value;
	return len;
}

static DEVICE_ATTR_RW(max_copy_size);

static ssize_t
aflags_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct wd_queue *q = wd_queue(dev);
	struct dummy_hw_queue *dq = (struct dummy_hw_queue *)q->priv;

	pr_err("todo: merge with queue_flags in the future\n");
	return sprintf(buf, "%d", dq->aflags);
}

static ssize_t aflags_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	char *end;
	int value;
	struct wd_queue *q = wd_queue(dev);
	struct dummy_hw_queue *dq = (struct dummy_hw_queue *)q->priv;

	value = simple_strtol(buf, &end, 0);
	if (end == buf || value != 0)
		return -EINVAL;

	dq->aflags = value;
	return len;
}

static DEVICE_ATTR_RW(aflags);

static struct attribute *mdev_dev_attrs[] = {
	WD_DEFAULT_MDEV_DEV_ATTRS
	&dev_attr_max_copy_size.attr,
	&dev_attr_aflags.attr,
	NULL,
};

static const struct attribute_group mdev_dev_group = {
	.name  = WD_QUEUE_PARAM_GRP_NAME,
	.attrs = mdev_dev_attrs,
};

static const  struct attribute_group *mdev_dev_groups[] = {
	&mdev_dev_group,
	NULL,
};

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, AN_DUMMY_MEMCPY);
}
MDEV_TYPE_ATTR_RO(name);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	int num = 0, i;
	struct wd_dev *wdev = (struct wd_dev *)dev->driver_data;
	struct dummy_hw_queue *devqs;

	assert(wdev);

	devqs = (struct dummy_hw_queue *)wdev->priv;
	for (i = 0; i < MAX_QUEUE; i++)
		if (!devqs[i].used)
			num++;
	return sprintf(buf, "%d", num);
}
MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	struct wd_dev *wdev = (struct wd_dev *)dev->driver_data;
	assert(wdev);

	return sprintf(buf, "%s\n", DUMMY_WD);
}
MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *mdev_type_attrs[] = {
	WD_DEFAULT_MDEV_TYPE_ATTRS
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
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
		if(hwq->reg->ring[hwq->tail].size > hwq->max_copy_size)
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
		wd_wake_up(&hwq->wdq);
	}
}

static int dummy_is_q_updated(struct wd_queue *q)
{
	struct dummy_hw_queue *hwq = q->priv;

#ifndef WD_DUMMY_RISKY_TRY_OUT
	_queue_work(hwq);
#endif

	return hwq->updated;
}

#ifdef WD_DUMMY_RISKY_TRY_OUT
static int hwq_tsk(void *data)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)data;
	__u32 head;

	pr_info("hwq_tsk start, tail=%d\n", hwq->tail);

	while (1) {
		if (kthread_should_stop()) {
			pr_info("dummy tsk stop\n");
			return 0;
		}

		_queue_work(hwq);

		head = readl(&hwq->reg->head);
		if (head == hwq->tail)
			schedule_timeout_interruptible(HZ);
	}

	return 0;
}
#endif

static void dummy_init_hw_queue(struct dummy_hw_queue *hwq, int used)
{
	if (hwq->used == used)
		return;

	hwq->used = used;
	if (used) {
		hwq->reg =
		(struct dummy_hw_queue_reg *)__get_free_page(GFP_KERNEL);
		memcpy(hwq->reg->hw_tag, DUMMY_HW_TAG, DUMMY_HW_TAG_SZ);
		hwq->reg->ring_bd_num = Q_BDS;
		writel(0, &hwq->reg->head);
		writel(0, &hwq->reg->tail);
		hwq->tail = 0;
		hwq->updated = 0;

		hwq->aflags = 0;
		hwq->max_copy_size = 4096;
	} else
		free_page((unsigned long)hwq->reg);
}

static int dummy_get_queue(struct wd_dev *wdev,
			const char *devalgo_name, struct wd_queue **q)
{
	int i;
	struct dummy_hw_queue *devqs = (struct dummy_hw_queue *)wdev->priv;

	assert(devqs);

	pr_info("get queue for algorithm %s\n", devalgo_name);
	//todo: check the devalgo_name with memcpy

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

static int dummy_start_queue(struct wd_queue *q)
{
#ifdef WD_DUMMY_RISKY_TRY_OUT
	static int id=0;

	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;
	hwq->tsk = kthread_run(hwq_tsk, hwq, "hwq_tsk%d", id++);
#endif

	return 0;
}

static int dummy_stop_queue(struct wd_queue *q)
{
#ifdef WD_DUMMY_RISKY_TRY_OUT
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;
	kthread_stop(hwq->tsk);
#endif

	return 0;
}

static int dummy_put_queue(struct wd_queue *q)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;
	mutex_lock(&qsmutex);
	dummy_init_hw_queue(hwq, 0);
	mutex_unlock(&qsmutex);
	pr_info("queue released\n");

	module_put(THIS_MODULE);

	return 0;
}

static int dummy_mmap(struct wd_queue *q, struct vm_area_struct *vma)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	if (vma->vm_pgoff != 0 || vma->vm_end - vma->vm_start > PAGE_SIZE)
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start, __pa(hwq->reg)>>PAGE_SHIFT,
		PAGE_SIZE, PAGE_SHARED);
}

static long dummy_ioctl(struct wd_queue *q, unsigned int cmd,
				unsigned long arg)
{
	struct ring_bd req;

	/**
	 * This is a useless case: it show that the user application can make
	 * some tiny request by ioctl to the hardware. But in most case, you
	 * cannot adopted this for main data flow. That need dma and async
	 * request to form a pipeline. But if you do dma here, it cannot keep
	 * the vma-page mapping for long. it is not safe. We suggest keep this
	 * channel for maintainence only.
	 */
	switch (cmd) {
	case DUMMY_REQ_CMD:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		req.ret = _do_user_copy(req.tgt_addr, req.src_addr, req.size);

		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
	default:
		return -EINVAL;
	}
}

static int default_priorioty[MAX_DEV] = {10, 30, 20};
static int dummy_wd_probe(struct platform_device *pdev)
{
	struct wd_dev *wdev;
	int i;

	if (pdev->id >= MAX_DEV) {
		dev_err(&pdev->dev, "invalid id (%d) for dummy_wd\n", pdev->id);
		return -EINVAL;
	}

	wdev = devm_kzalloc(&pdev->dev, sizeof(struct wd_dev), GFP_KERNEL);
	if (!wdev)
		return -ENOMEM;

	for (i = 0; i < MAX_QUEUE; i++) {
		dummy_init_hw_queue(&qs[pdev->id][i], 0);
		qs[pdev->id][i].wdq.wdev = wdev;
	}

	platform_set_drvdata(pdev, wdev);
	wdev->iommu_type = VFIO_NOIOMMU_IOMMU;
	wdev->owner = THIS_MODULE;
	wdev->name = DUMMY_WD;
	wdev->dev = &pdev->dev;
	wdev->is_vf = 0;
	wdev->priv = qs[pdev->id];
	wdev->node_id = -1;
	wdev->priority = 0;
	wdev->api_ver = "wd_dummy_v1";
	wdev->throughput_level = 10;
	wdev->latency_level = 10;
	wdev->flags = 0;

	wdev->mdev_fops.supported_type_groups = mdev_type_groups;
	wdev->mdev_fops.mdev_attr_groups = mdev_dev_groups;

	wdev->ops.get_queue = dummy_get_queue;
	wdev->ops.put_queue = dummy_put_queue;
	wdev->ops.open = dummy_start_queue;
	wdev->ops.close = dummy_stop_queue;
	wdev->ops.is_q_updated = dummy_is_q_updated;
	wdev->ops.mmap = dummy_mmap;
	wdev->ops.ioctl = dummy_ioctl;

	/* set predefined priority for test */
	wdev->priority = default_priorioty[pdev->id];

	return wd_dev_register(wdev);
}

static int dummy_wd_remove(struct platform_device *pdev)
{
	struct wd_dev *wdev = (struct wd_dev *)pdev->dev.driver_data;
	wd_dev_unregister(wdev);
	return 0;
}

static struct platform_driver dummy_pdrv = {
	.probe		= dummy_wd_probe,
	.remove		= dummy_wd_remove,
	.driver		= {
		.name		= DUMMY_WD,
	},
};

static struct platform_device *dummy_pdev[MAX_DEV];

static int __init dummy_wd_dev_init(void)
{
	int i, j;
	int ret = platform_driver_register(&dummy_pdrv);

	if (ret)
		return ret;

	for (i = 0; i < MAX_DEV; i++) {
		dummy_pdev[i] = platform_device_alloc(DUMMY_WD, i);
		assert(dummy_pdev[i]);
		ret = platform_device_add(dummy_pdev[i]);
		if (ret)
			goto dev_reg_fail;
	}

	return 0;


dev_reg_fail:
	for (j = i - 1; j >= 0; j--) {
		if(dummy_pdev[i])
			platform_device_put(dummy_pdev[j]);
	}

	platform_driver_unregister(&dummy_pdrv);

	return ret;
}

static void __exit dummy_wd_dev_exit(void)
{
	int i;

	for (i = MAX_DEV - 1; i >= 0; i--)
		platform_device_unregister(dummy_pdev[i]);

	platform_driver_unregister(&dummy_pdrv);
}

module_init(dummy_wd_dev_init);
module_exit(dummy_wd_dev_exit);

MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
MODULE_LICENSE("GPL");
