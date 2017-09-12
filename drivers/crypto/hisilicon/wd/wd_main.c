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
#include "wd_usr_if.h"
#include "wd.h"

#define WD_MOD_VERSION		"v1.0"

struct wd_mdev_state {
	int state;
	struct list_head next;
	struct wd_queue *q;
	wait_queue_head_t wait;
	void *priv;
};

static struct class *wd_class;

static struct wd_dev *mdev_wdev(struct mdev_device *mdev)
{
	return (struct wd_dev *)mdev_parent_dev(mdev)->driver_data;
}

static int __dev_exist(struct device *dev, void *data)
{
	return !strcmp(dev_name(dev), dev_name((struct device *)data));
}

int parent_is_wdev(struct device *dev)
{
	struct mdev_device *mdev;
	struct device *parent;

	mdev = mdev_from_dev(dev);
	if (!mdev)
		return 0;
	parent = mdev_parent_dev(mdev);
	if (!parent)
		return 0;
	return class_for_each_device(wd_class, NULL, parent, __dev_exist);
}

EXPORT_SYMBOL(parent_is_wdev);

int parent_is_noiommu(struct device *dev)
{
	struct mdev_device *mdev;
	struct wd_dev *wdev;

	mdev = mdev_from_dev(dev);
	if (!mdev)
		return 0;
	wdev = mdev_wdev(mdev);
	if (!wdev)
		return 0;
	return wdev->iommu_type == VFIO_NOIOMMU_IOMMU ? 1 : 0;
}

EXPORT_SYMBOL(parent_is_noiommu);

static ssize_t node_id_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct wd_dev *wdev = dev->driver_data;

	if (wdev)
		return sprintf(buf, "%d\n", wdev->node_id);
	else
		return sprintf(buf, "no device!\n");
}

static ssize_t node_id_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	char *end;
	int value;
	struct wd_dev *wdev = (struct wd_dev *)dev->driver_data;

	assert(wdev);

	value = simple_strtol(buf, &end, 0);
	if (end == buf)
		return -EINVAL;

	wdev->node_id = value;
	return len;
}
static DEVICE_ATTR_RW(node_id);

static ssize_t priority_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct wd_dev *wdev = dev->driver_data;

	if (wdev)
		return sprintf(buf, "%d\n", wdev->priority);
	else
		return sprintf(buf, "no device!\n");
}

static ssize_t priority_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	char *end;
	int value;
	struct wd_dev *wdev = dev->driver_data;

	if (!wdev) {
		dev_err(dev, "no devcie!\n");
		return -EINVAL;
	}
	value = simple_strtol(buf, &end, 0);
	if (end == buf || value > 99) {
		dev_err(dev, "priority (%d) should be in [0, 99], or"
			" minus value to disable the device\n", value);
		return -EINVAL;
	}

	wdev->priority = value;
	return len;
}
static DEVICE_ATTR_RW(priority);

static ssize_t iommu_type_show(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	struct wd_dev *wdev = dev->driver_data;

	if (!wdev)
		return sprintf(buf, "no device!\n");

	return sprintf(buf, "%d\n", wdev->iommu_type);
}

static DEVICE_ATTR_RO(iommu_type);

/* The following attributions will be showed in the parent device directory. */
static struct attribute *wd_dev_attrs[] = {
	&dev_attr_node_id.attr,
	&dev_attr_priority.attr,
	&dev_attr_iommu_type.attr,
	NULL,
};

static const struct attribute_group wd_dev_group = {
	.name  = WD_PDEV_ATTRS_GRP_NAME,
	.attrs = wd_dev_attrs,
};

const struct attribute_group *wd_dev_groups[] = {
	&wd_dev_group,
	NULL,
};

#define DEVICE_ATTR_RO_EXPORT(_name) \
	DEVICE_ATTR_RO(_name); \
	EXPORT_SYMBOL(dev_attr_##_name)

#define MDEV_TYPE_ATTR_RO_EXPORT(_name) \
	MDEV_TYPE_ATTR_RO(_name); \
	EXPORT_SYMBOL(mdev_type_attr_##_name);

/* Attribute pid is used by the mdev object in the accelerator driver */
static ssize_t
pid_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	struct wd_mdev_state *mdev_state;
	struct mdev_device *mdev;

	mdev = mdev_from_dev(dev);
	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return sprintf(buf, "no mdev!\n");
	/* fix me */
	return sprintf(buf, "%d\n", mdev_state->q->pid);
}
DEVICE_ATTR_RO_EXPORT(pid);

#define DEF_SIMPLE_WDEV_ATTR(_name, wdev_member) \
static ssize_t _name##_show(struct kobject *kobj, struct device *dev, \
			    char *buf) \
{ \
	struct wd_dev *wdev = dev->driver_data; \
	if (!wdev) \
		return sprintf(buf, "no device!\n"); \
	return sprintf(buf, "%d\n", wdev->wdev_member); \
} \
MDEV_TYPE_ATTR_RO_EXPORT(_name)

DEF_SIMPLE_WDEV_ATTR(latency, latency_level);
DEF_SIMPLE_WDEV_ATTR(throughput, throughput_level);
DEF_SIMPLE_WDEV_ATTR(flags, flags);

static int wd_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct device *dev;
	struct wd_mdev_state *mdev_state;
	struct wd_dev *wdev;
	struct wd_queue *q;
	int ret;

	assert(mdev);

	wdev = mdev_wdev(mdev);
	assert(wdev);

	if (!wdev->ops.get_queue)
		return -ENODEV;

	ret = wdev->ops.get_queue(wdev, kobj->name, &q);
	if (ret)
		return ret;

	q->mdev = mdev;
	q->pid = task_pid_nr(current);

	mdev_state = kzalloc(sizeof(struct wd_mdev_state), GFP_KERNEL);
	if (!mdev_state) {
		pr_err("Fail to alloc wd mdev state mem!\n");
		ret = -ENOMEM;
		goto fail_with_queue;
	}
	mdev_set_drvdata(mdev, mdev_state);
	mdev_state->q = q;
	init_waitqueue_head(&mdev_state->wait);
	dev = mdev_dev(mdev);
	dev->iommu_fwspec = mdev_parent_dev(mdev)->iommu_fwspec;
	pr_info("Create Mdev:%s\n", dev_name(dev));

	__module_get(wdev->owner);

	return 0;

fail_with_queue:
	(void)wdev->ops.put_queue(q);

	return ret;
}

static int wd_mdev_remove(struct mdev_device *mdev)
{
	struct wd_mdev_state *mdev_state;
	struct wd_queue *q;
	struct wd_dev *wdev;
	struct device *dev;

	mdev_state = mdev_get_drvdata(mdev);
	q = mdev_state->q;
	wdev = mdev_wdev(mdev);
	assert(wdev);
	dev = mdev_dev(mdev);

	wdev->ops.put_queue(q);

	mdev_set_drvdata(mdev, NULL);
	kfree(mdev_state);
	module_put(wdev->owner);

	return 0;
}

static int wd_mdev_open(struct mdev_device *mdev)
{
	struct wd_mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct wd_queue *q = mdev_state->q;
	struct wd_dev *wdev;

	wdev = mdev_wdev(mdev);

	if (wdev->ops.open)
		wdev->ops.open(q);

	return 0;
}

static void wd_mdev_close(struct mdev_device *mdev)
{
	struct wd_mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct wd_queue *q = mdev_state->q;
	struct wd_dev *wdev;

	wdev = mdev_wdev(mdev);

	if (wdev->ops.close)
		wdev->ops.close(q);
}

void wd_wake_up(struct wd_queue *q)
{
	struct wd_mdev_state *mdev_state = mdev_get_drvdata(q->mdev);
	wake_up(&mdev_state->wait);
}
EXPORT_SYMBOL(wd_wake_up);

static int wd_mdev_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	struct wd_mdev_state *mdev_state = mdev_get_drvdata(mdev);
	struct wd_queue *q = mdev_state->q;
	struct wd_dev *wdev = mdev_wdev(mdev);

	if (wdev->ops.mmap)
		return wdev->ops.mmap(q, vma);

	return -EINVAL;
}

static long wd_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			unsigned long arg)
{
	struct wd_mdev_state *mdev_state;
	struct wd_dev *wdev;
	int ret;

	if (!mdev)
		return -ENODEV;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -ENODEV;

	wdev = mdev_wdev(mdev);
	if (!wdev)
		return -ENODEV;

	if (cmd == WD_CMD_WAIT) {
		unsigned long timeout = msecs_to_jiffies(arg);
		if (wdev->ops.mask_notification)
			wdev->ops.mask_notification(mdev_state->q,
				_WD_EVENT_NOTIFY);
		if (timeout)
			ret = wait_event_interruptible_timeout(mdev_state->wait,
				wdev->ops.is_q_updated(mdev_state->q), timeout);
		else
			ret = wait_event_interruptible(mdev_state->wait,
				wdev->ops.is_q_updated(mdev_state->q));
		if (wdev->ops.mask_notification)
			wdev->ops.mask_notification(mdev_state->q,
				_WD_EVENT_DISABLE);

		return ret;
	}

	if (wdev->ops.ioctl)
		return wdev->ops.ioctl(mdev_state->q, cmd, arg);
	else {
		pr_err("ioctl cmd not supported!\n");
		return -EINVAL;
	}
}

static void wd_device_release(struct device *dev)
{
	return;
}

/**
 * wd_dev_register - register a wrapdrive device, so it will be exported to the
 * user space
 *
 * @wdev: the wrapdrive device to be registered
 */
int wd_dev_register(struct wd_dev *wdev)
{
	static atomic_t id = ATOMIC_INIT(-1);
	int ret;
	const char *drv_name;

	if (!wdev->dev)
		return -ENODEV;

	/* Currently, WD has some limits on driver name */
	drv_name = dev_driver_string(wdev->dev);
	if (strstr(drv_name, "-")){
		pr_err("WrapDrive: parent driver name cannot include char of '-'!\n");
		return -EINVAL;
	}

	/* Driver should be initiated with this driver data */
	if (wdev->dev->driver_data != wdev) {
		pr_err("WrapDrive: driver_data of parent device is mismatching!\n");
		return -EINVAL;
	}



	//todo: check the existence of necessary callback functions

	wdev->dev_id = (int)atomic_inc_return(&id);
	wdev->cls_dev.parent = wdev->dev;
	wdev->cls_dev.class = wd_class;
	wdev->cls_dev.release = wd_device_release;

	(void)dev_set_name(&wdev->cls_dev, "%s", dev_name(wdev->dev));
	ret = device_register(&wdev->cls_dev);
	if (ret)
		return ret;

	wdev->mdev_fops.owner			= wdev->owner;
	wdev->mdev_fops.dev_attr_groups		= wd_dev_groups;
	assert(wdev->mdev_fops.mdev_attr_groups);
	assert(wdev->mdev_fops.supported_type_groups);
	wdev->mdev_fops.create			= wd_mdev_create;
	wdev->mdev_fops.remove			= wd_mdev_remove;
	wdev->mdev_fops.open			= wd_mdev_open;
	wdev->mdev_fops.release			= wd_mdev_close;
	wdev->mdev_fops.ioctl			= wd_mdev_ioctl;
	wdev->mdev_fops.mmap			= wd_mdev_mmap;

	/* Zaibo: As only one domain is supported in one device, we should
	 * dettach as register here. After this, kernel crypto algorithms on
	 * this device will not work any more. As IOMMU supporting multiple
	 * substream_id, we need to fix this here. After this detaching, all
	 * the algorithms registered Crypto will not work while IOMMU enabled.
	 * Actually, as multiple subtream-id is Okay, we need to alloc domain
	 * for each queue while alloc queue from parent device.
	 */
	wdev->domain = iommu_get_domain_for_dev(wdev->dev);
	if (wdev->domain)
		iommu_detach_device(wdev->domain, wdev->dev);

	ret = mdev_register_device(wdev->dev, &wdev->mdev_fops);
	if (ret)
		goto fail_with_cls;

	return ret;

fail_with_cls:
	device_unregister(&wdev->cls_dev);
	return ret;
}
EXPORT_SYMBOL(wd_dev_register);

/**
 * wd_dev_unregister - unregisters a wd device
 *
 * @wdev: the wrapdrive device to unregister
 */
void wd_dev_unregister(struct wd_dev *wdev)
{
	mdev_unregister_device(wdev->dev);
	if (wdev->domain)
		iommu_attach_device(wdev->domain, wdev->dev);
	device_unregister(&wdev->cls_dev);
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL(wd_dev_unregister);

struct wd_queue *wd_queue(struct device *dev)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct wd_mdev_state *mdev_state = mdev_get_drvdata(mdev);

	return mdev_state->q;
}
EXPORT_SYMBOL(wd_queue);

static int __init wd_init(void)
{
	wd_class = class_create(THIS_MODULE, WD_CLASS_NAME);
	if (IS_ERR(wd_class))
		return PTR_ERR(wd_class);

	return 0;
}

static __exit void wd_exit(void)
{
	class_destroy(wd_class);
}

module_init(wd_init);
module_exit(wd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Wrap Drive Framework for Accelerators");
MODULE_VERSION(WD_MOD_VERSION);
