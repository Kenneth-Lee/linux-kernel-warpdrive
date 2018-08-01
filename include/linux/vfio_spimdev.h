/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __VFIO_SPIMDEV_H
#define __VFIO_SPIMDEV_H

#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <uapi/linux/vfio_spimdev.h>

struct vfio_spimdev_queue;
struct vfio_spimdev;

/**
 * struct vfio_spimdev_ops - WD device operations
 * @get_queue: get a queue from the device according to algorithm
 * @put_queue: free a queue to the device
 * @is_q_updated: check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap: mmap addresses of queue to user space
 * @reset: reset the WD device
 * @reset_queue: reset the queue
 * @ioctl:   ioctl for user space users of the queue
 * @get_available_instances: get numbers of the queue remained
 */
struct vfio_spimdev_ops {
	int (*get_queue)(struct vfio_spimdev *spimdev, unsigned long arg,
		struct vfio_spimdev_queue **q);
	int (*put_queue)(struct vfio_spimdev_queue *q);
	int (*is_q_updated)(struct vfio_spimdev_queue *q);
	void (*mask_notify)(struct vfio_spimdev_queue *q, int event_mask);
	int (*mmap)(struct vfio_spimdev_queue *q, struct vm_area_struct *vma);
	int (*reset)(struct vfio_spimdev *spimdev);
	int (*reset_queue)(struct vfio_spimdev_queue *q);
	long (*ioctl)(struct vfio_spimdev_queue *q, unsigned int cmd,
			unsigned long arg);
	int (*get_available_instances)(struct vfio_spimdev *spimdev);
};

struct vfio_spimdev_queue {
	struct mutex mutex;
	struct vfio_spimdev *spimdev;
	int qid;
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

struct vfio_spimdev {
	const char *name;
	int status;
	atomic_t ref;
	struct module *owner;
	const struct vfio_spimdev_ops *ops;
	struct device *dev;
	struct device cls_dev;
	bool is_vf;
	u32 iommu_type;
	u32 dma_flag;
	u32 dev_id;
	void *priv;
	int flags;
	const char *api_ver;
	struct mdev_parent_ops mdev_fops;
};

int vfio_spimdev_register(struct vfio_spimdev *spimdev);
void vfio_spimdev_unregister(struct vfio_spimdev *spimdev);
void vfio_spimdev_wake_up(struct vfio_spimdev_queue *q);
int vfio_spimdev_is_spimdev(struct device *dev);
struct vfio_spimdev *vfio_spimdev_pdev_spimdev(struct device *dev);
int vfio_spimdev_pasid_pri_check(int pasid);
int vfio_spimdev_get(struct device *dev);
int vfio_spimdev_put(struct device *dev);
struct vfio_spimdev *mdev_spimdev(struct mdev_device *mdev);

extern struct mdev_type_attribute mdev_type_attr_flags;
extern struct mdev_type_attribute mdev_type_attr_name;
extern struct mdev_type_attribute mdev_type_attr_device_api;
extern struct mdev_type_attribute mdev_type_attr_available_instances;
#define VFIO_SPIMDEV_DEFAULT_MDEV_TYPE_ATTRS \
	&mdev_type_attr_name.attr, \
	&mdev_type_attr_device_api.attr, \
	&mdev_type_attr_available_instances.attr, \
	&mdev_type_attr_flags.attr

#define _VFIO_SPIMDEV_REGION(vm_pgoff)	(vm_pgoff & 0xf)

#endif
