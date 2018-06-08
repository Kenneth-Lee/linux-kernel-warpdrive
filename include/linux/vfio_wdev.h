/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __VFIO_WDEV_H
#define __VFIO_WDEV_H

#include <linux/device.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <linux/iommu.h>
#include <uapi/linux/vfio_wdev.h>

struct vfio_wdev_queue;
struct vfio_wdev;

/**
 * struct vfio_wdev_ops - WD device operations
 * @get_queue:  get a queue from the device according to algorithm
 * @put_queue:  free a queue to the device
 * @is_q_updated:  check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap:  mmap addresses of queue to user space
 * @open:  open queue to start it
 * @close:  close queue to stop it
 * @reset:  reset the WD device
 * @reset_queue:  reset the queue
 * @ioctl:   ioctl for user space users of the queue
 */
struct vfio_wdev_ops {
	int (*get_queue)(struct vfio_wdev *wdev, char *alg,
		struct vfio_wdev_queue **q);
	int (*put_queue)(struct vfio_wdev_queue *q);
	int (*is_q_updated)(struct vfio_wdev_queue *q);
	void (*mask_notify)(struct vfio_wdev_queue *q, int event_mask);
	int (*mmap)(struct vfio_wdev_queue *q, struct vm_area_struct *vma);
	int (*open)(struct vfio_wdev *wdev);
	int (*close)(struct vfio_wdev *wdev);
	int (*reset)(struct vfio_wdev *wdev);
	int (*reset_queue)(struct vfio_wdev_queue *q);
	struct vfio_wdev_queue *(*index_queue)(struct vfio_wdev *wdev, u16 index);
	int (*set_pasid)(struct vfio_wdev_queue *q, int pasid);
	int (*unset_pasid)(struct vfio_wdev_queue *q);
	long (*ioctl)(struct vfio_wdev *wdev, unsigned int cmd, unsigned long arg);
};

/**
 * struct vfio_wdev_queue - WD queue on WD device
 * @mutex:  mutex while multiple threads
 * @wdev:  WD device it belongs to
 * @pid:   Process ID that it belongs to
 * @flags:  queue attributions indication
 * @mdev:  mediated devices it based on
 * @priv:   driver data
 * @next: for list of queues
 * @wait: wait tasks on this queue
 * @status:  status of WD management
 * @qid: queue ID, which is inside the wdev
 */
struct vfio_wdev_queue {
	struct mutex mutex;
	struct vfio_wdev *wdev;
	int pid;
	__u32 flags;
	struct mdev_device *mdev;
	void *priv;
	struct list_head next;
	wait_queue_head_t wait;
	int status;
	int qid;
};

/**
 * struct vfio_wdev - Wrapdrive device description
 * @name:  device name
 * @status:  device status
 * @ref:  referrence count
 * @owner: module owner
 * @ops:  wd device operations
 * @dev:  its kernel device
 * @cls_dev:  its class device
 * @is_vf:  denotes whether it is virtual function
 * @iommu_type:  iommu type of hardware
 * @dev_id:   device ID
 * @priv: driver private data
 * @node_id: socket ID
 * @priority: priority while being selected, also can be set by users
 * @latency_level: latency while doing acceleration
 * @throughput_level: throughput while doing acceleration
 * @flags: device attributions
 * @api_ver: API version of WD
 * @mdev_fops: mediated device's parent operations
 */
struct vfio_wdev {
	char *name;
	int status;
	atomic_t ref;
	struct module *owner;
	const struct vfio_wdev_ops *ops;
	struct device *dev;
	struct device cls_dev;
	bool is_vf;
	u32 iommu_type;
	u32 dma_flag;
	u32 dev_id;
	void *priv;
	int node_id;
	int priority;
	int latency_level;
	int throughput_level;
	int flags;
	const char *api_ver;
	struct mdev_parent_ops mdev_fops;
};

int vfio_wdev_register(struct vfio_wdev *wdev);
void vfio_wdev_unregister(struct vfio_wdev *wdev);
void vfio_wdev_wake_up(struct vfio_wdev_queue *q);
int is_vfio_wdev_mdev(struct device *dev);
struct vfio_wdev *vfio_wdev_pdev_wdev(struct device *dev);
int vfio_wdev_pasid_pri_check(int pasid);
int vfio_wdev_get(struct device *dev);
int vfio_wdev_put(struct device *dev);
struct vfio_wdev *mdev_wdev(struct mdev_device *mdev);
extern struct device_attribute dev_attr_pid;
#define VFIO_WDEV_DEFAULT_MDEV_DEV_ATTRS \
	&dev_attr_pid.attr,

extern struct mdev_type_attribute mdev_type_attr_latency;
extern struct mdev_type_attribute mdev_type_attr_throughput;
extern struct mdev_type_attribute mdev_type_attr_flags;
#define VFIO_WDEV_DEFAULT_MDEV_TYPE_ATTRS \
	&mdev_type_attr_latency.attr, \
	&mdev_type_attr_throughput.attr, \
	&mdev_type_attr_flags.attr,

#define _VFIO_WDEV_EVENT_NOTIFY         (1 << 0)
#define _VFIO_WDEV_EVENT_DISABLE        (1 << 1)
#define _VFIO_WDEV_REGION(vm_pgoff)	(vm_pgoff & 0xf)

#endif
