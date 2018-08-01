/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __VFIO_SDMDEV_H
#define __VFIO_SDMDEV_H

#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <uapi/linux/vfio_sdmdev.h>

struct vfio_sdmdev_queue;
struct vfio_sdmdev;

/* event bit used to mask the hardware irq */
#define VFIO_SDMDEV_EVENT_Q_UPDATE BIT(0) /* irq if queue is updated */

/**
 * struct vfio_sdmdev_ops - WD device operations
 * @get_queue: get a queue from the device according to algorithm
 * @put_queue: free a queue to the device
 * @start_queue: put queue into action with current process's pasid.
 * @stop_queue: stop queue from running state
 * @is_q_updated: check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap: mmap addresses of queue to user space
 * @reset: reset the WD device
 * @reset_queue: reset the queue
 * @ioctl:   ioctl for user space users of the queue
 * @get_available_instances: get numbers of the queue remained
 */
struct vfio_sdmdev_ops {
	int (*get_queue)(struct vfio_sdmdev *sdmdev,
			 struct vfio_sdmdev_queue **q);
	void (*put_queue)(struct vfio_sdmdev_queue *q);
	int (*start_queue)(struct vfio_sdmdev_queue *q);
	void (*stop_queue)(struct vfio_sdmdev_queue *q);
	int (*is_q_updated)(struct vfio_sdmdev_queue *q);
	void (*mask_notify)(struct vfio_sdmdev_queue *q, int event_mask);
	int (*mmap)(struct vfio_sdmdev_queue *q, struct vm_area_struct *vma);
	int (*reset)(struct vfio_sdmdev *sdmdev);
	int (*reset_queue)(struct vfio_sdmdev_queue *q);
	long (*ioctl)(struct vfio_sdmdev_queue *q, unsigned int cmd,
			unsigned long arg);
	int (*get_available_instances)(struct vfio_sdmdev *sdmdev);
};

struct vfio_sdmdev_queue {
	struct mutex mutex;
	struct vfio_sdmdev *sdmdev;
	__u32 flags;
	void *priv;
	wait_queue_head_t wait;
	struct mdev_device *mdev;
	int fd;
	int container;
#ifdef CONFIG_IOMMU_SVA
	int pasid;
#endif
};

struct vfio_sdmdev {
	const char *name;
	int status;
	atomic_t ref;
	const struct vfio_sdmdev_ops *ops;
	struct device *dev;
	struct device cls_dev;
	bool is_vf;
	u32 iommu_type;
	u32 dma_flag;
	void *priv;
	int flags;
	const char *api_ver;
	struct mdev_parent_ops mdev_fops;
};

int vfio_sdmdev_register(struct vfio_sdmdev *sdmdev);
void vfio_sdmdev_unregister(struct vfio_sdmdev *sdmdev);
void vfio_sdmdev_wake_up(struct vfio_sdmdev_queue *q);
int vfio_sdmdev_is_sdmdev(struct device *dev);
struct vfio_sdmdev *vfio_sdmdev_pdev_sdmdev(struct device *dev);
struct vfio_sdmdev *mdev_sdmdev(struct mdev_device *mdev);

extern struct mdev_type_attribute mdev_type_attr_flags;
extern struct mdev_type_attribute mdev_type_attr_name;
extern struct mdev_type_attribute mdev_type_attr_device_api;
extern struct mdev_type_attribute mdev_type_attr_available_instances;
#define VFIO_SDMDEV_DEFAULT_MDEV_TYPE_ATTRS \
	&mdev_type_attr_name.attr, \
	&mdev_type_attr_device_api.attr, \
	&mdev_type_attr_available_instances.attr, \
	&mdev_type_attr_flags.attr

#define _VFIO_SDMDEV_REGION(vm_pgoff)	(vm_pgoff & 0xf)

#endif
