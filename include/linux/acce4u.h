/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __ACCE4U_H
#define __ACCE4U_H

#include <linux/device.h>
#include <linux/list.h>
#include <linux/iommu.h>
#include <uapi/linux/acce4u.h>

struct acce4u_queue;
struct acce4u;

/**
 * struct acce4u_ops - WD device operations
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
struct acce4u_ops {
	int (*get_queue)(struct acce4u *acce4u, unsigned long arg,
		struct acce4u_queue **q);
	int (*put_queue)(struct acce4u_queue *q);
	int (*stop_queue)(struct acce4u_queue *q);
	int (*is_q_updated)(struct acce4u_queue *q);
	void (*mask_notify)(struct acce4u_queue *q, int event_mask);
	int (*mmap)(struct acce4u_queue *q, struct vm_area_struct *vma);
	int (*reset)(struct acce4u *acce4u);
	int (*reset_queue)(struct acce4u_queue *q);
	long (*ioctl)(struct acce4u_queue *q, unsigned int cmd,
			unsigned long arg);
	int (*get_available_instances)(struct acce4u *acce4u);
};

struct acce4u_queue {
	struct mutex mutex;
	struct acce4u *acce4u;
	int qid;
	__u32 flags;
	void *priv;
	wait_queue_head_t wait;
#ifdef CONFIG_IOMMU_SVA
	int pasid;
#endif
	struct list_head share_mem_list;
};

struct acce4u {
	const char *name;
	int status;
	atomic_t ref;
	struct module *owner;
	const struct acce4u_ops *ops;
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

int acce4u_register(struct acce4u *acce4u);
void acce4u_unregister(struct acce4u *acce4u);
void acce4u_wake_up(struct acce4u_queue *q);

#ifdef KENNY_TO_REMOVE
int acce4u_is_acce4u(struct device *dev);
struct acce4u *acce4u_pdev_acce4u(struct device *dev);
int acce4u_pasid_pri_check(int pasid);
int acce4u_get(struct device *dev);
int acce4u_put(struct device *dev);
#endif

#endif
