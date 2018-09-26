/*
 *	WrapDriver Accelerator Dummy Driver
 *
 *	Copyright (C) 2016-2018 Kenneth Lee
 */

/**
 * This module is used to test the framework of WrapDrive.
 *
 * It creates MAX_DEV platform devices with MAX_QUEUE queue for each. When the
 * queue is gotten, a kernel thread is created and handle request put into the
 * queue by the user application.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <asm/page.h>
#include <linux/uacce.h>
#include <linux/uaccess.h>
#include "wd_dummy_usr_if.h"
#include "dummy_hw_usr_if.h"

#define MAX_DEV 3
#define MAX_QUEUE 4
#define QUEUE_YEILD_MS 50
#undef VERBOSE_LOG

#ifdef VERBOSE_LOG
#define dummy_log(msg, ...) pr_info("dummy log: " msg, ##__VA_ARGS__)
#else
#define dummy_log(msg, ...)
#endif

static DEFINE_MUTEX(qsmutex);

struct dummy_hw;

struct dummy_hw_queue {
	bool used;
	struct task_struct *tsk;
	__u32 tail;
	int updated;
	void *vmap;

	struct uacce_queue wdq;
	struct dummy_hw_queue_reg *reg;
	struct dummy_hw *hw;
	struct task_struct *work_thread;
	struct mutex mutex;
	int devid, qid;
};

static struct dummy_hw {
	int max_copy_size;
	int aflags;
	struct dummy_hw_queue qs[MAX_QUEUE];
	struct platform_device *pdev;
} hws[MAX_DEV];

static int _do_copy(struct uacce_queue *q, void *tgt, void *src, size_t len)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	size_t ktgt = (unsigned long)tgt - q->as->va;
	size_t ksrc = (unsigned long)src - q->as->va;
	size_t range = q->as->nr_pages << PAGE_SHIFT;

	if (ktgt > range || ktgt + len> range)
		return -EINVAL;

	if (ksrc > range || ksrc + len > range)
		return -EINVAL;

	ktgt += (unsigned long)hwq->vmap;
	ksrc += (unsigned long)hwq->vmap;
	dummy_log("memcpy(%lx, %lx, %lx), va=%lx, kva=%lx\n", ktgt, ksrc, len,
		q->as->va, (unsigned long)hwq->vmap);
	memcpy((void *)ktgt, (void *)ksrc, len);

	return 0;
}

static void _queue_work(struct dummy_hw_queue *hwq)
{
	int bd_num;
	__u32 head;
	__u32 tail;


	mutex_lock(&hwq->mutex);

	bd_num = hwq->reg->ring_bd_num;
	head = readl(&hwq->reg->head);

	if (head >= bd_num) {
		pr_err("dummy_wd io error, head=%d\n", head);
		mutex_unlock(&hwq->mutex);
		return;
	}

	tail = hwq->tail;
	while (hwq->tail != head) {
		if(hwq->reg->ring[hwq->tail].size > hwq->hw->max_copy_size)
			hwq->reg->ring[hwq->tail].ret = -EINVAL;
		else
			hwq->reg->ring[hwq->tail].ret = _do_copy(&hwq->wdq, 
				 hwq->reg->ring[hwq->tail].tgt_addr,
				 hwq->reg->ring[hwq->tail].src_addr,
				 hwq->reg->ring[hwq->tail].size);
		dummy_log("memcpy(%p, %p, %ld) = %d",
			hwq->reg->ring[hwq->tail].tgt_addr,
			hwq->reg->ring[hwq->tail].src_addr,
			hwq->reg->ring[hwq->tail].size,
			hwq->reg->ring[hwq->tail].ret);
		hwq->reg->ring[hwq->tail].ret = 0;
		hwq->tail = (hwq->tail+1)%bd_num;
	}

	if (tail != hwq->tail) {
		dummy_log("write back tail %d\n", hwq->tail);
		writel(hwq->tail, &hwq->reg->tail);
		hwq->updated = 1;
		uacce_wake_up(&hwq->wdq);
	}

	mutex_unlock(&hwq->mutex);
}

static int dummy_is_q_updated(struct uacce_queue *q)
{
	struct dummy_hw_queue *hwq = q->priv;
	return hwq->updated;
}

static void dummy_init_hw_queue(struct dummy_hw_queue *hwq, int used, int devid,
				int qid)
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
		if (devid >= 0)
			hwq->devid = devid;
		if (qid >= 0)
			hwq->qid = qid;

		mutex_init(&hwq->mutex);
	} else {
		free_page((unsigned long)hwq->reg);
	}
}

static int dummy_get_queue(struct uacce *uacce, unsigned long arg,
			   struct uacce_queue **q)
{
	int i;
	struct dummy_hw *hw = (struct dummy_hw *)uacce->priv;
	struct dummy_hw_queue *devqs = hw->qs;

	BUG_ON(!devqs);

	mutex_lock(&qsmutex);
	for (i = 0; i < MAX_QUEUE; i++) {
		if (!devqs[i].used) {
			dummy_init_hw_queue(&devqs[i], 1, -1, -1);
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

static void dummy_put_queue(struct uacce_queue *q)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	mutex_lock(&qsmutex);
	dummy_init_hw_queue(hwq, 0, -1, -1);
	mutex_unlock(&qsmutex);

	module_put(THIS_MODULE);
}

static int dummy_mmap(struct uacce_queue *q, struct vm_area_struct *vma)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	if (vma->vm_pgoff != 0 ||
	    vma->vm_end - vma->vm_start > PAGE_SIZE ||
	    !(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start, __pa(hwq->reg)>>PAGE_SHIFT,
		PAGE_SIZE, vma->vm_page_prot);
}

static int dummy_map(struct uacce_queue *q) {
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;
	struct uacce_as *as = q->as;

	hwq->vmap = vmap(as->pages, as->nr_pages, VM_MAP, PAGE_KERNEL);
	if (!hwq->vmap)
		return -ENOMEM;

	return 0;
}

static void dummy_unmap(struct uacce_queue *q) {
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	vunmap(hwq->vmap);
}

static long dummy_ioctl(struct uacce_queue *q, unsigned int cmd,
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

static void dummy_mask_notify(struct uacce_queue *q, int event_mask)
{
	dummy_log("mask notify: %x\n", event_mask);
}

int queue_worker(void *data) {
	struct dummy_hw_queue *hwq = data;

	do {
		_queue_work(hwq);
		schedule_timeout_interruptible(msecs_to_jiffies(QUEUE_YEILD_MS));
	} while (!kthread_should_stop());
	return 0;
}

static int dummy_start_queue(struct uacce_queue *q)
{
	struct dummy_hw_queue *hwq = q->priv;
	hwq->work_thread = kthread_run(queue_worker, hwq,
				       "dummy_queue_worker %d-%d",
				       hwq->devid, hwq->qid);
	if (IS_ERR(hwq->work_thread))
		return PTR_ERR(hwq->work_thread);

	return 0;
}

int dummy_stop_queue(struct uacce_queue *q) {
	struct dummy_hw_queue *hwq = q->priv;
	int ret;

	ret = kthread_stop(hwq->work_thread);
	dummy_log("queue worker (%d, %d) stopped (ret=%d)\n",
		hwq->devid, hwq->qid, ret);
	return 0;
}

static const struct uacce_ops dummy_ops = {
	.get_queue = dummy_get_queue,
	.put_queue = dummy_put_queue,
	.start_queue = dummy_start_queue,
	.stop_queue = dummy_stop_queue,
	.is_q_updated = dummy_is_q_updated,
	.mmap = dummy_mmap,
	.map = dummy_map,
	.unmap = dummy_unmap,
	.ioctl = dummy_ioctl,
	.mask_notify = dummy_mask_notify,
};

static int dummy_wd_probe(struct platform_device *pdev)
{
	struct uacce *uacce;
	struct dummy_hw *hw;
	int i;

	if (pdev->id >= MAX_DEV) {
		dev_err(&pdev->dev, "invalid id (%d) for dummy_wd\n", pdev->id);
		return -EINVAL;
	}

	hw = &hws[pdev->id];
	hw->aflags = 0;
	hw->max_copy_size = 4096;

	uacce = devm_kzalloc(&pdev->dev, sizeof(struct uacce), GFP_KERNEL);
	if (!uacce)
		return -ENOMEM;

	for (i = 0; i < MAX_QUEUE; i++) {
		dummy_init_hw_queue(&hw->qs[i], 0, pdev->id, i);
		hw->qs[i].wdq.uacce = uacce;
		hw->qs[i].hw = hw;
	}

	platform_set_drvdata(pdev, uacce);
	uacce->name = DUMMY_WD;
	uacce->dev = &pdev->dev;
	uacce->priv = hw;
	uacce->flags = 0;
	uacce->io_nr_pages = 1;
	uacce->ops = &dummy_ops;

	return uacce_register(uacce);
}

static int dummy_wd_remove(struct platform_device *pdev)
{
	struct uacce *uacce = (struct uacce *)pdev->dev.driver_data;
	uacce_unregister(uacce);
	return 0;
}

static struct platform_driver dummy_pdrv = {
	.probe		= dummy_wd_probe,
	.remove		= dummy_wd_remove,
	.driver		= {
		.name		= DUMMY_WD,
	},
};

static int __init dummy_uacce_init(void)
{
	int i, j;
	int ret = platform_driver_register(&dummy_pdrv);

	if (ret)
		return ret;

	for (i = 0; i < MAX_DEV; i++) {
		hws[i].pdev = platform_device_alloc(DUMMY_WD, i);
		BUG_ON(!hws[i].pdev);
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

static void __exit dummy_uacce_exit(void)
{
	int i;

	for (i = MAX_DEV - 1; i >= 0; i--)
		platform_device_unregister(hws[i].pdev);

	platform_driver_unregister(&dummy_pdrv);
}

module_init(dummy_uacce_init);
module_exit(dummy_uacce_exit);

MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
MODULE_LICENSE("GPL");
