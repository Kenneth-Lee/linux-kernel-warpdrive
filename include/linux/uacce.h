/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __UACCE_H
#define __UACCE_H

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/iommu.h>
#include <uapi/linux/uacce.h>

struct uacce_queue;
struct uacce;

/* Static Share Virtual Memory Space */
struct uacce_svas {
	/* todo: support multiple section in the future */
	struct page **pages;
	unsigned long va;
	int nr_pages;
	int prot;
	struct mm_struct *mm;

	struct list_head list;
	struct list_head qs;
};

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
	void (*put_queue)(struct uacce_queue *q);
	int (*start_queue)(struct uacce_queue *q);
	int (*stop_queue)(struct uacce_queue *q);
	int (*is_q_updated)(struct uacce_queue *q);
	void (*mask_notify)(struct uacce_queue *q, int event_mask);
	int (*mmap)(struct uacce_queue *q, struct vm_area_struct *vma);
	int (*map)(struct uacce_queue *q);
	void (*unmap)(struct uacce_queue *q);
	int (*reset)(struct uacce *uacce);
	int (*reset_queue)(struct uacce_queue *q);
	long (*ioctl)(struct uacce_queue *q, unsigned int cmd,
			unsigned long arg);
};

struct uacce_queue {
	struct uacce *uacce;
	__u32 flags;
	void *priv;
	wait_queue_head_t wait;
	bool mapped_shm; /* this field is protected by the uacce_as lock */
#ifdef CONFIG_IOMMU_SVA
	int pasid;
#endif
	struct uacce_svas *svas;
	struct list_head list; /* as list for as->qs */
};

struct uacce {
	const char *name;
	int status;
	struct module *owner;
	const struct uacce_ops *ops;
	struct device *dev;
	struct device cls_dev;
	bool is_vf;
	u32 iommu_type;
	u32 dma_flag;
	u32 dev_id;
	struct cdev *cdev;
	void *priv;
	int flags;
	const char *api_ver;
	size_t io_nr_pages;
	atomic_t openned;
};

int uacce_register(struct uacce *uacce);
void uacce_unregister(struct uacce *uacce);
void uacce_wake_up(struct uacce_queue *q);

/* following are uacce stub API, for those drivers who can still work when uacce
 * is disabled
 */

/* va continue mem shared between device and the cpu (kenrel or user space) */
struct uacce_share_mem {
	struct device *dev;
	void *va;
	int order;
};

int uacce_set_iommu_domain(struct device *dev);
void uacce_unset_iommu_domain(struct device *dev);
struct uacce_share_mem *uacce_alloc_shared_mem(struct device *dev,
					       size_t size, int prot);
void uacce_free_shared_mem(struct uacce_share_mem *sm);
int uacce_mmap_shared_mem(struct uacce_share_mem *sm,
			  struct vm_area_struct *vma);

#endif
