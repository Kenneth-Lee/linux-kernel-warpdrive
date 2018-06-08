/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/vfio_wdev.h>

#define DEFAULT_MAX_PRIORITY 99
#define _VFIO_WDEV_INDEX(vm_pgoff)      ((u16)(vm_pgoff >> 4) & 0xffff)

struct wdev_mdev_state {
	int state;
	int pid;
	struct vfio_wdev *wdev;
	struct mutex lock;
	struct list_head queue_list;
	void *priv;
};

static struct class *wdev_class;

int vfio_wdev_pasid_pri_check(int pasid)
{
#ifdef CONFIG_IOMMU_SVA
	struct mm_struct *mm;

	mm = iommu_sva_find(pasid);
	if (mm) {
		mmput(mm);
		return mm == current->mm;
	} else
		return 0;
#else
	return 1;
#endif
}
EXPORT_SYMBOL(vfio_wdev_pasid_pri_check);

static int __dev_exist(struct device *dev, void *data)
{
	return !strcmp(dev_name(dev), dev_name((struct device *)data));
}

/* Check if the device is a mediated device belongs to vfio_wdev */
int is_vfio_wdev_mdev(struct device *dev)
{
	struct mdev_device *mdev;
	struct device *pdev;

	mdev = mdev_from_dev(dev);
	if (!mdev)
		return 0;
	pdev = mdev_parent_dev(mdev);
	if (!pdev)
		return 0;

	return class_for_each_device(wdev_class, NULL, pdev, __dev_exist);
}
EXPORT_SYMBOL(is_vfio_wdev_mdev);

struct vfio_wdev *vfio_wdev_pdev_wdev(struct device *dev)
{
	struct device *class_dev;

	if (!dev)
		return ERR_PTR(-EINVAL);

	class_dev = class_find_device(wdev_class, NULL, dev,
		       (int(*)(struct device *, const void *))__dev_exist);
	if (!class_dev)
		return ERR_PTR(-ENODEV);

	return container_of(class_dev, struct vfio_wdev, cls_dev);
}
EXPORT_SYMBOL(vfio_wdev_pdev_wdev);

int vfio_wdev_get(struct device *dev)
{
	struct vfio_wdev *wdev;

	wdev = vfio_wdev_pdev_wdev(dev);
	if (IS_ERR(wdev))
		return PTR_ERR(wdev);

	return atomic_inc_return(&wdev->ref);
}
EXPORT_SYMBOL(vfio_wdev_get);

int vfio_wdev_put(struct device *dev)
{
	struct vfio_wdev *wdev;

	wdev = vfio_wdev_pdev_wdev(dev);
	if (IS_ERR(wdev))
		return PTR_ERR(wdev);

	return atomic_dec_return(&wdev->ref);
}
EXPORT_SYMBOL(vfio_wdev_put);

struct vfio_wdev *mdev_wdev(struct mdev_device *mdev)
{
	struct device *pdev = mdev_parent_dev(mdev);

	return vfio_wdev_pdev_wdev(pdev);
}
EXPORT_SYMBOL(mdev_wdev);

static ssize_t node_id_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct vfio_wdev *wdev = vfio_wdev_pdev_wdev(dev);

	if (wdev)
		return sprintf(buf, "%d\n", wdev->node_id);
	else
		return -ENODEV;
}

static ssize_t node_id_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t len)
{
	int ret;
	long value;
	struct vfio_wdev *wdev = vfio_wdev_pdev_wdev(dev);

	if (!wdev)
		return -ENODEV;

	ret = kstrtol(buf, 10, &value);
	if (ret)
		return -EINVAL;

	wdev->node_id = value;
	return len;
}
static DEVICE_ATTR_RW(node_id);

static ssize_t priority_show(struct device *dev,
			     struct device_attribute *attr,
			     char *buf)
{
	struct vfio_wdev *wdev = vfio_wdev_pdev_wdev(dev);

	if (wdev)
		return sprintf(buf, "%d\n", wdev->priority);
	else
		return -ENODEV;
}

static ssize_t priority_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t len)
{
	long value;
	int ret;
	struct vfio_wdev *wdev = vfio_wdev_pdev_wdev(dev);

	if (!wdev)
		return -ENODEV;

	ret = kstrtol(buf, 10, &value);
	if (ret || value > DEFAULT_MAX_PRIORITY) {
		dev_err(dev, "priority (%zd) should be in [0, %d], or negative value to disable the device\n",
			value, DEFAULT_MAX_PRIORITY);
		return -EINVAL;
	}

	wdev->priority = value;
	return len;
}
static DEVICE_ATTR_RW(priority);

static ssize_t iommu_type_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct vfio_wdev *wdev = vfio_wdev_pdev_wdev(dev);

	if (!wdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", wdev->iommu_type);
}

static DEVICE_ATTR_RO(iommu_type);

static ssize_t dma_flag_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct vfio_wdev *wdev = vfio_wdev_pdev_wdev(dev);

	if (!wdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", wdev->dma_flag);
}

static DEVICE_ATTR_RO(dma_flag);

/* The following attributions will be showed in the parent device directory. */
static struct attribute *vfio_wdev_attrs[] = {
	&dev_attr_node_id.attr,
	&dev_attr_priority.attr,
	&dev_attr_iommu_type.attr,
	&dev_attr_dma_flag.attr,
	NULL,
};

static const struct attribute_group vfio_wdev_group = {
	.name  = VFIO_WDEV_PDEV_ATTRS_GRP_NAME,
	.attrs = vfio_wdev_attrs,
};

const struct attribute_group *vfio_wdev_groups[] = {
	&vfio_wdev_group,
	NULL,
};

#define DEVICE_ATTR_RO_EXPORT(name) 		\
		DEVICE_ATTR_RO(name);		\
		EXPORT_SYMBOL(dev_attr_##name);

#define MDEV_TYPE_ATTR_RO_EXPORT(name)			\
		MDEV_TYPE_ATTR_RO(name); 		\
		EXPORT_SYMBOL(mdev_type_attr_##name);

/* PID attribute is used by the mdev object in the accelerator driver */
static ssize_t pid_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct wdev_mdev_state *mdev_state;
	struct mdev_device *mdev;

	mdev = mdev_from_dev(dev);
	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -ENODEV;

	return sprintf(buf, "%d\n", mdev_state->pid);
}
DEVICE_ATTR_RO_EXPORT(pid);

#define DEF_SIMPLE_WDEV_ATTR(_name, wdev_member) \
static ssize_t _name##_show(struct kobject *kobj, struct device *dev, \
			    char *buf) \
{ \
	struct vfio_wdev *wdev = vfio_wdev_pdev_wdev(dev); \
	if (!wdev) \
		return -ENODEV; \
	return sprintf(buf, "%d\n", wdev->wdev_member); \
} \
MDEV_TYPE_ATTR_RO_EXPORT(_name)

DEF_SIMPLE_WDEV_ATTR(latency, latency_level);
DEF_SIMPLE_WDEV_ATTR(throughput, throughput_level);
DEF_SIMPLE_WDEV_ATTR(flags, flags);

static int vfio_wdev_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct device *dev;
	struct wdev_mdev_state *mdev_state;
	struct vfio_wdev *wdev;

	wdev = mdev_wdev(mdev);
	if (!wdev->ops->get_queue)
		return -ENODEV;
	mdev_state = kzalloc(sizeof(struct wdev_mdev_state), GFP_KERNEL);
	if (!mdev_state)
		return -ENOMEM;
	mutex_init(&mdev_state->lock);
	mdev_set_drvdata(mdev, mdev_state);
	mdev_state->wdev = wdev;
	INIT_LIST_HEAD(&mdev_state->queue_list);
	dev = mdev_dev(mdev);
	dev->iommu_fwspec = mdev_parent_dev(mdev)->iommu_fwspec;
	pr_info("Create Mdev:%s\n", dev_name(dev));

	__module_get(wdev->owner);

	return 0;
}

static int vfio_wdev_mdev_remove(struct mdev_device *mdev)
{
	struct wdev_mdev_state *mdev_state;
	struct vfio_wdev *wdev;
	struct device *dev;

	mdev_state = mdev_get_drvdata(mdev);
	wdev = mdev_wdev(mdev);
	dev = mdev_dev(mdev);
	dev->iommu_fwspec = NULL;
	mdev_set_drvdata(mdev, NULL);
	kfree(mdev_state);
	module_put(wdev->owner);

	return 0;
}

static int vfio_wdev_mdev_open(struct mdev_device *mdev)
{
	struct wdev_mdev_state *mdev_state;

	mdev_state = mdev_get_drvdata(mdev);
	if (!list_empty(&mdev_state->queue_list))
		return -EBUSY;

	mdev_state->pid = current->tgid;

	return 0;
}

static void vfio_wdev_mdev_close(struct mdev_device *mdev)
{
	struct wdev_mdev_state *mdev_state;
	struct vfio_wdev *wdev;
	struct vfio_wdev_queue *lqueue, *queue;

	wdev = mdev_wdev(mdev);
	mdev_state = mdev_get_drvdata(mdev);

	mutex_lock(&mdev_state->lock);
	list_for_each_entry_safe(lqueue, queue,
			        &mdev_state->queue_list, next) {
		(void)wdev->ops->unset_pasid(lqueue);
		wdev->ops->put_queue(lqueue);
		list_del(&lqueue->next);
	}
	INIT_LIST_HEAD(&mdev_state->queue_list);
	mutex_unlock(&mdev_state->lock);
	mdev_state->pid = -1;

	return;

}
/* Wake up the process who is waiting this queue */
void vfio_wdev_wake_up(struct vfio_wdev_queue *q)
{
	wake_up(&q->wait);
}
EXPORT_SYMBOL(vfio_wdev_wake_up);

/* This is for user space accessing hardware accelerators directly */
static int vfio_wdev_mdev_mmap(struct mdev_device *mdev,
			     struct vm_area_struct *vma)
{
	struct vfio_wdev_queue *q;
	struct vfio_wdev *wdev = mdev_wdev(mdev);
	u16 index;

	index = _VFIO_WDEV_INDEX(vma->vm_pgoff);
	q = wdev->ops->index_queue(wdev, index);
	if (!q) {
		dev_err(mdev_dev(mdev), "\nindex queue fail!");
		return -ENODEV;
	}

	if (wdev->ops->mmap)
		return wdev->ops->mmap(q, vma);

	dev_err(mdev_dev(mdev), "\nno driver mmap!");

	return -EINVAL;
}

/* This is for user space controlling hardware accelerators */
static long vfio_wdev_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			       unsigned long arg)
{
	struct wdev_mdev_state *mdev_state;
	struct vfio_wdev *wdev;
	struct vfio_wdev_queue *q;
	int ret;
	u16  index;
	char alg[VFIO_WDEV_ALG_NAME_SIZE];

	if (!mdev)
		return -ENODEV;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -ENODEV;

	wdev = mdev_wdev(mdev);
	if (!wdev)
		return -ENODEV;

	if (cmd == VFIO_WDEV_CMD_WAIT) {
		u16 timeout = msecs_to_jiffies(arg & 0xffff);

		index = (u16)((arg & 0xffffffff) >> 16);
		q =  wdev->ops->index_queue(wdev, index);
		if (!q)
			return -ENODEV;
		if (wdev->ops->mask_notify)
			wdev->ops->mask_notify(q, _VFIO_WDEV_EVENT_NOTIFY);
		if (timeout) {
			ret = wdev->ops->is_q_updated(q);
			ret = wait_event_interruptible_timeout(q->wait, ret, timeout);
		} else {
			ret = wdev->ops->is_q_updated(q);
			ret = wait_event_interruptible(q->wait, ret);
		}
		if (wdev->ops->mask_notify)
			wdev->ops->mask_notify(q, _VFIO_WDEV_EVENT_DISABLE);

		return ret;
	} else if (cmd == VFIO_WDEV_CMD_GET_Q) {
		ret = copy_from_user(alg, (char *)arg, VFIO_WDEV_ALG_NAME_SIZE);
		if (ret) {
			pr_err("copy_from_user failed\n");
			return -EIO;
		}
		if (strlen(alg) > VFIO_WDEV_ALG_NAME_SIZE - 1)
			return -EINVAL;
		ret = wdev->ops->get_queue(wdev, alg, &q);
		if (ret < 0) {
			pr_err("get_queue failed\n");
			return -ENODEV;
		}
		ret = (int)q->qid;
		mutex_lock(&mdev_state->lock);
		list_add(&q->next, &mdev_state->queue_list);
		mutex_unlock(&mdev_state->lock);
		q->pid = mdev_state->pid;

		return ret;

	} else if (cmd == VFIO_WDEV_CMD_PUT_Q) {
		index = (u16)arg;
		q =  wdev->ops->index_queue(wdev, index);
		if (!q) {
			pr_err("index no queue!\n");
			return -ENODEV;
		}
		mutex_lock(&mdev_state->lock);
		list_del(&q->next);
		mutex_unlock(&mdev_state->lock);

		ret = wdev->ops->put_queue(q);
		if (ret) {
			pr_err("drv put queue fail!\n");
			return ret;
		}

		return 0;
	} else if (cmd == VFIO_WDEV_CMD_SET_PASID) {
		u16 index = (u16)(arg >> 32);
		int pasid = (int)(arg & 0xffffffff);

		q = wdev->ops->index_queue(wdev, index);
		if (!q)
			return -ENODEV;
		ret = vfio_wdev_pasid_pri_check(pasid);
		if (!ret || q->pid != mdev_state->pid)
			return -EPERM;

		return wdev->ops->set_pasid(q, pasid);
	} else if (cmd == VFIO_WDEV_CMD_CLR_PASID) {
		u16 index = (u16)(arg >> 32);

		q = wdev->ops->index_queue(wdev, index);
		if (!q)
			return -ENODEV;
		if (q->pid != mdev_state->pid)
			return -EPERM;

		return wdev->ops->unset_pasid(q);
	}

	if (wdev->ops->ioctl)
		return wdev->ops->ioctl(wdev, cmd, arg);

	pr_err("ioctl cmd not supported!\n");

	return -EINVAL;
}

static void vfio_wdev_release(struct device *dev)
{

}

/**
 * vfio_wdev_register - register a warpdrive device, so it will be exported to the
 * user space
 *
 * @wdev: the warpdrive device to be registered
 */
int vfio_wdev_register(struct vfio_wdev *wdev)
{
	static atomic_t id = ATOMIC_INIT(-1);
	int ret;
	const char *drv_name;

	if (!wdev->dev)
		return -ENODEV;

	drv_name = dev_driver_string(wdev->dev);
	if (strstr(drv_name, "-")) {
		pr_err("WrapDrive: parent driver name cannot include char of '-'!\n");
		return -EINVAL;
	}

	wdev->dev_id = (int)atomic_inc_return(&id);
	atomic_set(&wdev->ref, 0);
	wdev->cls_dev.parent = wdev->dev;
	wdev->cls_dev.class = wdev_class;
	wdev->cls_dev.release = vfio_wdev_release;

	dev_set_name(&wdev->cls_dev, "%s", dev_name(wdev->dev));
	ret = device_register(&wdev->cls_dev);
	if (ret)
		return ret;

	/* Call back operations from accelerator drivers */
	wdev->mdev_fops.owner			= wdev->owner;
	wdev->mdev_fops.dev_attr_groups		= vfio_wdev_groups;
	wdev->mdev_fops.create			= vfio_wdev_mdev_create;
	wdev->mdev_fops.remove			= vfio_wdev_mdev_remove;
	wdev->mdev_fops.open			= vfio_wdev_mdev_open;
	wdev->mdev_fops.release			= vfio_wdev_mdev_close;
	wdev->mdev_fops.ioctl			= vfio_wdev_mdev_ioctl;
	wdev->mdev_fops.mmap			= vfio_wdev_mdev_mmap;

	ret = mdev_register_device(wdev->dev, &wdev->mdev_fops);
	if (ret)
		goto fail_with_cls;

	return ret;

fail_with_cls:
	device_unregister(&wdev->cls_dev);
	return ret;
}
EXPORT_SYMBOL(vfio_wdev_register);

/**
 * vfio_wdev_unregister - unregisters a wd device
 *
 * @wdev: the warpdrive device to unregister
 */
void vfio_wdev_unregister(struct vfio_wdev *wdev)
{
	mdev_unregister_device(wdev->dev);
	device_unregister(&wdev->cls_dev);
}
EXPORT_SYMBOL(vfio_wdev_unregister);

static int __init vfio_wdev_init(void)
{
	wdev_class = class_create(THIS_MODULE, VFIO_WDEV_CLASS_NAME);

	return PTR_ERR_OR_ZERO(wdev_class);
}

static __exit void vfio_wdev_exit(void)
{
	class_destroy(wdev_class);
}

module_init(vfio_wdev_init);
module_exit(vfio_wdev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("VFIO Wrap Drive Framework for Accelerators");
