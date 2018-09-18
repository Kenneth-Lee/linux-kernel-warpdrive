/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __UACCE_H
#define __UACCE_H

#include <linux/device.h>
#include <linux/list.h>
#include <linux/iommu.h>
#include <uapi/linux/uacce.h>

struct uacce_queue;
struct uacce;

/**
 * struct uacce_ops - WD device operations
 * @get_queue: get a queue from the device according to algorithm
 * @put_queue: free a queue to the device
 * @is_q_updated: check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap: mmap addresses of queue to user space
 * @reset: reset the WD device
 * @reset_queue: reset the queue
 * @ioctl:   ioctl for user space users of the queue
 * @get_available_instances: get numbers of the queue remained
 * @stop_queue: make the queue stop work before put_queue
 */
struct uacce_ops {
	int (*get_queue)(struct uacce *uacce, unsigned long arg,
		struct uacce_queue **q);
	int (*put_queue)(struct uacce_queue *q);
	int (*stop_queue)(struct uacce_queue *q);
	int (*is_q_updated)(struct uacce_queue *q);
	void (*mask_notify)(struct uacce_queue *q, int event_mask);
	int (*mmap)(struct uacce_queue *q, struct vm_area_struct *vma);
	int (*reset)(struct uacce *uacce);
	int (*reset_queue)(struct uacce_queue *q);
	long (*ioctl)(struct uacce_queue *q, unsigned int cmd,
			unsigned long arg);
	int (*get_available_instances)(struct uacce *uacce);
};

struct uacce_queue {
	struct mutex mutex;
	struct uacce *uacce;
	int qid;
	__u32 flags;
	void *priv;
	wait_queue_head_t wait;
#ifdef CONFIG_IOMMU_SVA
	int pasid;
#endif
	struct list_head share_mem_list;
};

struct uacce {
	const char *name;
	int status;
	atomic_t ref;
	struct module *owner;
	const struct uacce_ops *ops;
	struct device *dev;
	struct device cls_dev;
	bool is_vf;
	u32 iommu_type;
	u32 dma_flag;
	u32 dev_id;
	void *priv;
	int flags;
	const char *api_ver;
};

int uacce_register(struct uacce *uacce);
void uacce_unregister(struct uacce *uacce);
void uacce_wake_up(struct uacce_queue *q);

#ifdef KENNY_TO_REMOVE
int uacce_is_uacce(struct device *dev);
struct uacce *uacce_pdev_uacce(struct device *dev);
int uacce_pasid_pri_check(int pasid);
int uacce_get(struct device *dev);
int uacce_put(struct device *dev);
#endif

#endif
