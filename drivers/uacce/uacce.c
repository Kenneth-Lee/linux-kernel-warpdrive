/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uacce.h>
#include <linux/wait.h>

static struct class *uacce_class;
static DEFINE_IDR(uacce_idr);
static dev_t uacce_devt;
static DEFINE_MUTEX(uacce_mutex); /* mutex to protect uacce */
static DEFINE_RWLOCK(uacce_lock); /* lock to protect all queues management */

static const struct file_operations uacce_fops;

/**
 * uacce_wake_up - Wake up the process who is waiting this queue
 * @q the accelerator queue to wake up
 */
void uacce_wake_up(struct uacce_queue *q)
{
	dev_info(q->uacce->dev, "wake up\n");
	wake_up_interruptible(&q->wait);
}
EXPORT_SYMBOL_GPL(uacce_wake_up);

static void uacce_cls_release(struct device *dev) { }

static struct uacce_svas *uacce_alloc_svas(void)
{
	struct uacce_svas *svas;

	svas = kzalloc(sizeof(*svas), GFP_KERNEL | GFP_ATOMIC);
	if (!svas)
		return ERR_PTR(-ENOMEM);

	svas->mm = current->mm;
	INIT_LIST_HEAD(&svas->qs);

	return svas;
}

static void uacce_free_svas(struct uacce_svas *svas)
{
	int i;

	if (svas->pages) {
		for (i = 0; i < svas->nr_pages; i++)
			put_page(svas->pages[i]);

		down_write(&svas->mm->mmap_sem);
		svas->mm->data_vm -= svas->nr_pages;
		up_write(&svas->mm->mmap_sem);
		kfree(svas->pages);
	}
	kfree(svas);
}

static inline int uacce_iommu_map_shm_pages(struct uacce_queue *q)
{
	struct device *dev = q->uacce->dev;
	struct uacce_svas *svas = q->svas;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i, j, ret;

	if (!domain)
		return -ENODEV;

	if (!svas)
		return 0;

	for (i = 0; i < svas->nr_pages; i++) {
		get_page(svas->pages[i]);
		ret = iommu_map(domain, svas->va + i * PAGE_SIZE,
				PFN_PHYS(page_to_pfn(svas->pages[i])),
				PAGE_SIZE, svas->prot | IOMMU_CACHE);
		if (ret)
			goto err_with_map_pages;
	}

	return 0;

err_with_map_pages:
	for (j = i-1; j >= 0; j--) {
		iommu_unmap(domain, svas->va + j * PAGE_SIZE, PAGE_SIZE);
		put_page(svas->pages[j]);
	}
	return ret;
}

static inline void uacce_iommu_unmap_shm_pages(struct uacce_queue *q)
{
	struct device *dev = q->uacce->dev;
	struct uacce_svas *svas = q->svas;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i;

	if (!domain || !svas)
		return;

	for (i = svas->nr_pages-1; i >= 0; i--) {
		iommu_unmap(domain, svas->va + i * PAGE_SIZE, PAGE_SIZE);
		put_page(svas->pages[i]);
	}
}

static void uacce_unmap_shm_on_queue(struct uacce_queue *q)
{
	if (q->mapped_shm)
		return;

	if (q->uacce->ops->map) {
		if (q->uacce->ops->unmap)
			q->uacce->ops->unmap(q);
	} else
		uacce_iommu_unmap_shm_pages(q);
}

static int uacce_map_shm_on_queue(struct uacce_queue *q)
{
	struct uacce_svas *svas = q->svas;
	int ret;

	if (!svas->va)
		return 0;

	if (q->uacce->flags & UACCE_DEV_NOIOMMU)
		ret = q->uacce->ops->map ? q->uacce->ops->map(q) : -ENODEV;
	else
		ret = uacce_iommu_map_shm_pages(q);

	if (!ret)
		q->mapped_shm = true;

	return ret;
}

static long uacce_cmd_share_svas(struct uacce_queue *tgt, int fd)
{
	struct file *filep = fget(fd);
	struct uacce_queue *src;
	int ret;

	if (!filep || filep->f_op != &uacce_fops)
		return -EINVAL;

	src = (struct uacce_queue *)filep->private_data;
	if (!src)
		return -EINVAL;

	/* no ssva is needed if the dev can do fault-from-dev */
	if (tgt->uacce->flags | UACCE_DEV_FAULT_FROM_DEV)
		return -EINVAL;

	write_lock(&uacce_lock);
	if (!src->svas || tgt->svas) {
		dev_warn(tgt->uacce->dev,
		       "tgt should have svas and src should not\n");
		ret = -EINVAL;
		goto err;
	}

	tgt->svas = src->svas;
	list_add(&tgt->list, &src->svas->qs);
	uacce_map_shm_on_queue(tgt);

	write_unlock(&uacce_lock);
	return 0;

err:
	write_unlock(&uacce_lock);
	return ret;
}

static long uacce_fops_unl_ioctl(struct file *filep,
				unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;

	switch (cmd) {
	case UACCE_CMD_SHARE_SVAS:
		return uacce_cmd_share_svas(q, arg);
	default:
		if (uacce->ops->ioctl)
			return uacce->ops->ioctl(q, cmd, arg);

		dev_err(uacce->dev, "ioctl cmd (%d) is not supported!\n", cmd);
		return -EINVAL;
	}
}

#ifdef CONFIG_COMPAT
static long uacce_fops_compat_ioctl(struct file *filep,
				   unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return uacce_fops_unl_ioctl(filep, cmd, arg);
}
#endif

static int uacce_dev_check(struct uacce *uacce)
{
	/* if dev support fault-from-dev, it should support pasid */
	if ((uacce->flags | UACCE_DEV_FAULT_FROM_DEV) ||
	    !(uacce->flags | UACCE_DEV_PASID))
		return -EINVAL;

	if (uacce->flags & UACCE_DEV_NOIOMMU)
		return 0;

	/* The device can be opened once if it dose not support multiple page
	 * table. The better way to check this is count it per iommu_domain,
	 * this is just a temporary solution
	 */
	if (!(uacce->flags & UACCE_DEV_PASID)) {
		if (atomic_add_unless(&uacce->openned, 1, 1))
			return -EBUSY;
	} else {
#ifndef CONFIG_IOMMU_SVA
		if (atomic_add_unless(&uacce->openned, 1, 1))
			return -EBUSY;
#endif
	}

	return 0;
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	int ret;
	int pasid = 0;

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce)
		return -ENODEV;

	if (!uacce->ops->get_queue)
		return -EINVAL;

	ret = uacce_dev_check(uacce);

	if (uacce->flags & UACCE_DEV_PASID) {
#ifdef CONFIG_IOMMU_SVA
		ret = __iommu_sva_bind_device(uacce->dev, current->mm, &pasid,
					      IOMMU_SVA_FEAT_IOPF, NULL);
#else
		ret = -EINVAL;
#endif
	}

	if (ret)
		return ret;

	ret = uacce->ops->get_queue(uacce, pasid, &q);
	if (ret < 0)
		return ret;

	q->uacce = uacce;
	init_waitqueue_head(&q->wait);
	filep->private_data = q;

	if (uacce->ops->start_queue) {
		ret = uacce->ops->start_queue(q);
		if (ret)
			goto err_with_queue;
	}

	__module_get(uacce->owner);

	return 0;

err_with_queue:
	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);
	return ret;
}

static vm_fault_t uacce_shm_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct uacce_svas *svas = vma->vm_private_data;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

	pr_info("fault on page %ld\n", page_offset);

	if (page_offset >= svas->nr_pages)
		return VM_FAULT_SIGBUS;

	read_lock(&uacce_lock);
	get_page(svas->pages[page_offset]);
	vmf->page = svas->pages[page_offset];
	read_unlock(&uacce_lock);

	return 0;
}

static const struct vm_operations_struct uacce_shm_vm_ops = {
	.fault = uacce_shm_vm_fault,
};

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce;

	uacce = q->uacce;

	if (uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	write_lock(&uacce_lock);
	uacce_unmap_shm_on_queue(q);
	if (q->svas) {
		if (q->list.next)
			list_del(&q->list);
		if (list_empty(&q->svas->qs))
			uacce_free_svas(q->svas);
		q->svas = NULL;
	}
	write_unlock(&uacce_lock);

#ifdef CONFIG_IOMMU_SVA
	if (uacce->flags & UACCE_DEV_SVA)
		iommu_sva_unbind_device(uacce->dev, q->pasid);

#endif

	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	module_put(uacce->owner);
	atomic_dec(&uacce->openned);

	return 0;
}

static int uacce_create_shm_pages(struct uacce_queue *q,
				  struct vm_area_struct *vma)
{
	int i, j, ret = 0;

	/* dev with SVA need no ssva */
	if (q->uacce->flags | UACCE_DEV_FAULT_FROM_DEV)
		return -EINVAL;

	write_lock(&uacce_lock);
	if (!q->svas)
		q->svas = uacce_alloc_svas();

	if (!q->svas) {
		ret = -ENOMEM;
		goto err_with_lock;
	}

	if (q->svas->va) {
		ret = -EBUSY;
		goto err_with_svas;
	}

	q->svas->va = vma->vm_start;
	q->svas->nr_pages = vma_pages(vma);

	if (q->svas->mm->data_vm + q->svas->nr_pages >
	    rlimit(RLIMIT_DATA) >> PAGE_SHIFT) {
		ret = -ENOMEM;
		goto err_with_svas;
	}
	q->svas->mm->data_vm += q->svas->nr_pages;

	if (vma->vm_flags & VM_READ)
		q->svas->prot |= IOMMU_READ;

	if (vma->vm_flags & VM_WRITE)
		q->svas->prot |= IOMMU_WRITE;

	q->svas->pages = kcalloc(q->svas->nr_pages, sizeof(*q->svas->pages),
			       GFP_KERNEL | GFP_ATOMIC);
	if (!q->svas->pages) {
		ret = -ENOMEM;
		goto err_with_init;
	}

	for (i = 0; i < q->svas->nr_pages; i++) {
		q->svas->pages[i] = alloc_page(GFP_KERNEL | GFP_ATOMIC);
		if (!q->svas->pages[i])
			goto err_with_pages;
	}

	ret = uacce_map_shm_on_queue(q);
	if (ret)
		goto err_with_pages;

	vma->vm_ops = &uacce_shm_vm_ops;
	vma->vm_private_data = q->svas;
	list_add(&q->list, &q->svas->qs);

	write_unlock(&uacce_lock);
	return 0;

err_with_pages:
	for (j = i-1; j >= 0; j--) {
		put_page(q->svas->pages[j]);
		q->svas->pages[j] = NULL;
	}
err_with_init:
	q->svas->va = 0;
	q->svas->nr_pages = 0;
	q->svas->mm->data_vm -= q->svas->nr_pages;
err_with_svas:
	uacce_free_svas(q->svas);
err_with_lock:
	write_unlock(&uacce_lock);
	return ret;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;
	int ret;

	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND;

	if (uacce->io_nr_pages != 0 && vma->vm_pgoff >= uacce->io_nr_pages) {
		dev_info(uacce->dev,
			 "map share memory (off=%lx, start=%lx, end=%lx)\n",
			 vma->vm_pgoff, vma->vm_start, vma->vm_end);
		ret = uacce_create_shm_pages(q, vma);
	} else if (uacce->ops->mmap) {
		dev_info(uacce->dev,
			 "map acce io space (off=%lx, start=%lx, end=%lx)\n",
			 vma->vm_pgoff, vma->vm_start, vma->vm_end);
		ret = uacce->ops->mmap(q, vma);
	} else {
		dev_err(uacce->dev, "no driver mmap!\n");
		ret = -ENODEV;
	}

	return ret;
}

static __poll_t uacce_fops_poll(struct file *file, poll_table *wait)
{
	struct uacce_queue *q = (struct uacce_queue *)file->private_data;
	struct uacce *uacce = q->uacce;

	poll_wait(file, &q->wait, wait);
	if (uacce->ops->is_q_updated && uacce->ops->is_q_updated(q))
		return EPOLLIN | EPOLLRDNORM;
	else
		return 0;
}

static const struct file_operations uacce_fops = {
	.owner		= THIS_MODULE,
	.open		= uacce_fops_open,
	.release	= uacce_fops_release,
	.unlocked_ioctl	= uacce_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= uacce_fops_compat_ioctl,
#endif
	.mmap		= uacce_fops_mmap,
	.poll		= uacce_fops_poll,
};

static int uacce_create_chrdev(struct uacce *uacce)
{
	int ret;

	ret = idr_alloc(&uacce_idr, uacce, 0, 0, GFP_KERNEL);
	if (ret < 0)
		return ret;

	uacce->dev_id = ret;
	uacce->cdev = cdev_alloc();
	if (!uacce->cdev) {
		ret = -ENOMEM;
		goto err_with_idr;
	}

	uacce->cdev->ops = &uacce_fops;
	uacce->cdev->owner = uacce->owner;
	ret = cdev_add(uacce->cdev, MKDEV(MAJOR(uacce_devt), uacce->dev_id), 1);
	if (ret)
		goto err_with_cdev;

	pr_info("create uacce minior=%d\n", uacce->dev_id);
	return 0;

err_with_cdev:
	cdev_del(uacce->cdev);
err_with_idr:
	idr_remove(&uacce_idr, uacce->dev_id);
	return ret;
}

static void uacce_destroy_chrdev(struct uacce *uacce)
{
	cdev_del(uacce->cdev);
	idr_remove(&uacce_idr, uacce->dev_id);
}

/**
 *	uacce_register - register an accelerator
 *	@uacce: the accelerator structure
 */
int uacce_register(struct uacce *uacce)
{
	int ret;

	if (!uacce->dev)
		return -ENODEV;

	mutex_lock(&uacce_mutex);

	ret = uacce_create_chrdev(uacce);
	if (ret)
		goto err_with_lock;

	uacce->cls_dev.parent = uacce->dev;
	uacce->cls_dev.class = uacce_class;
	uacce->cls_dev.release = uacce_cls_release;
	dev_set_name(&uacce->cls_dev, "%s", dev_name(uacce->dev));
	ret = device_register(&uacce->cls_dev);
	if (ret)
		goto err_with_chrdev;

#ifdef CONFIG_IOMMU_SVA
	ret = iommu_sva_init_device(uacce->dev, IOMMU_SVA_FEAT_IOPF, 0, 0,
				    NULL);
	if (ret) {
		device_unregister(&uacce->cls_dev);
		goto err_with_chrdev;
	}
#endif

	mutex_unlock(&uacce_mutex);
	return 0;

err_with_chrdev:
	uacce_destroy_chrdev(uacce);
err_with_lock:
	mutex_unlock(&uacce_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(uacce_register);

/**
 * uacce_unregister - unregisters a uacce
 * @uacce: the accelerator to unregister
 *
 * Unregister an accelerator that wat previously successully registered with
 * uacce_register().
 */
void uacce_unregister(struct uacce *uacce)
{
	mutex_lock(&uacce_mutex);

#ifdef CONFIG_IOMMU_SVA
	iommu_sva_shutdown_device(uacce->dev);
#endif
	device_unregister(&uacce->cls_dev);
	uacce_destroy_chrdev(uacce);

	mutex_unlock(&uacce_mutex);
}
EXPORT_SYMBOL_GPL(uacce_unregister);

static int __init uacce_init(void)
{
	int ret;

	uacce_class = class_create(THIS_MODULE, UACCE_CLASS_NAME);
	if (IS_ERR(uacce_class)) {
		ret = PTR_ERR(uacce_class);
		goto err;
	}

	ret = alloc_chrdev_region(&uacce_devt, 0, MINORMASK, "uacce");
	if (ret)
		goto err_with_class;

	pr_info("uacce init with major number:%d\n", MAJOR(uacce_devt));

	return 0;

err_with_class:
	class_destroy(uacce_class);
err:
	return ret;
}

static __exit void uacce_exit(void)
{
	unregister_chrdev_region(uacce_devt, MINORMASK);
	class_destroy(uacce_class);
	idr_destroy(&uacce_idr);
}

subsys_initcall(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
