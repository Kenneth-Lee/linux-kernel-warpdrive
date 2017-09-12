/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __WD_H
#define __WD_H

#include <linux/device.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <linux/iommu.h>

#include "wd_usr_if.h"

#define WD_DEBUG


struct wd_queue;
struct wd_dev;

/* @get_queue to get the queue with required capabilities
 * @put_queue put back the requested queue
 * @wait_on_queue wait for the queue to be ready with data
 */
struct wd_dev_ops {
	int (*get_queue)(struct wd_dev *wdev, const char *alg, struct wd_queue **q);
	int (*put_queue)(struct wd_queue *q);
	int (*is_q_updated)(struct wd_queue *q);
	void (*mask_notification)(struct wd_queue *q, int event_mask);
	int (*mmap)(struct wd_queue *q, struct vm_area_struct *vma);
	int (*open)(struct wd_queue *q);
	int (*close)(struct wd_queue *q);
	int (*reset)(struct wd_dev *wdev);
	int (*reset_queue)(struct wd_queue *q);
	long (*ioctl)(struct wd_queue *q, unsigned int cmd,
				unsigned long arg);
};

struct wd_queue {
	struct mutex mutex;
	struct wd_dev *wdev;
	int pid; /* allocated to the pid */
	__u32 flags;
	struct mdev_device *mdev;
	void *priv; /* used for low level drv, such as hardware queue status */
	struct vfio_device_info vdi;
	int status; /* WD status */
};

struct wd_dev {
	char *name;
	int status;
	atomic_t ref;
	struct module *owner;
	struct wd_dev_ops ops;
	struct device *dev; /* the presented dev */
	struct device cls_dev; /* the class dev */
	bool is_vf;

	/* I think this is at device unit */
	u32 iommu_type;
	u32 dev_id;
	void *priv;
	int node_id;
	int priority;
	int latency_level;
	int throughput_level;
	int flags;
	const char *api_ver;
	struct mdev_parent_ops mdev_fops;

	/* parent device domain */
	struct iommu_domain *domain;
};
int parent_is_wdev(struct device *dev);
int parent_is_noiommu(struct device *dev);
int wd_dev_register(struct wd_dev *wdev);
void wd_dev_unregister(struct wd_dev *wdev);
struct wd_queue *wd_queue(struct device *dev);
void wd_wake_up(struct wd_queue *q);

extern struct device_attribute dev_attr_pid;
#define WD_DEFAULT_MDEV_DEV_ATTRS \
	&dev_attr_pid.attr,

extern struct mdev_type_attribute mdev_type_attr_latency;
extern struct mdev_type_attribute mdev_type_attr_throughput;
extern struct mdev_type_attribute mdev_type_attr_flags;
#define WD_DEFAULT_MDEV_TYPE_ATTRS \
	&mdev_type_attr_latency.attr, \
	&mdev_type_attr_throughput.attr, \
	&mdev_type_attr_flags.attr,

#ifdef WD_DEBUG
#define assert(expr) \
	if (!(expr)) { \
		printk("Assertion failed! %s,%s,%s,line=%d\n", \
			#expr, __FILE__, __func__, __LINE__); \
	}
#else
#define assert(...)
#endif
#define _WD_EVENT_NOTIFY		(1 << 0)
#define _WD_EVENT_DISABLE		(1 << 1)
#endif
