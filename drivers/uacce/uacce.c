/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/uacce.h>
#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/wait.h>

struct uacce_mdev_state {
	struct uacce *uacce;
};

static struct class *uacce_class;
static DEFINE_IDR(uacce_idr);
static dev_t uacce_devt;
//static struct cdev uacce_cdev;

static DEFINE_MUTEX(uacce_mutex);

struct uacce_share_info {
	struct list_head list;
	size_t size;
	unsigned long vaddr;
	unsigned long old_vm_flags;
	struct page *pages[];
};

static struct uacce_share_info * uacce_search_share_info(
	struct uacce_queue *q, unsigned long vaddr, size_t size)
{
	struct uacce_share_info *si;

	list_for_each_entry(si, &q->share_mem_list, list) {
		/* in this version, we assume the map and umap operation should
		 * remain exact the same
		 */
		if (si->vaddr == vaddr && si->size == size)
			return si;
		else if ((vaddr > si->vaddr &&
			  vaddr < si->vaddr + si->size) ||
			 (si->vaddr > vaddr &&
			  si->vaddr < vaddr + size))
			return ERR_PTR(-EINVAL);
	}

	return NULL;
}

/**
 * cce4u_wake_up - Wake up the process who is waiting this queue
 * @q the accelerator queue to wake up
 */
void uacce_wake_up(struct uacce_queue *q)
{
	wake_up(&q->wait);
}
EXPORT_SYMBOL_GPL(uacce_wake_up);

static void uacce_cls_release(struct device *dev) { }

static int uacce_share_vma_range(struct uacce_share_info *si)
{
	struct vm_area_struct *vma;
	unsigned long end = si->vaddr + si->size;
	int ret;

	vma = find_vma(current->mm, si->vaddr);
	if (!vma || vma->vm_start > si->vaddr || vma->vm_end < end)
		return -EINVAL;

	if (vma->vm_flags & VM_SHARED)
		return 0;

	si->old_vm_flags = vma->vm_flags;
	if (si->vaddr != vma->vm_start) {
		ret = split_vma(current->mm, vma, si->vaddr, 1);
		if (ret)
			goto out;
	}

	if (end != vma->vm_end) {
		ret = split_vma(current->mm, vma, end, 0);
		if (ret)
			goto out;
	}

	vma->vm_flags |= VM_SHARED;

out:
	return ret;
}

static void uacce_unshare_vma_range(struct uacce_share_info *si)
{
	struct vm_area_struct *vma;
	//unsigned long end = si->vaddr + si->size;

	vma = find_vma(current->mm, si->vaddr);
	if (!vma || vma->vm_start > si->vaddr || 
	    vma->vm_end < si->vaddr + si->size ||
	    vma->vm_flags & VM_SHARED) {
		pr_err("uacce: unshare invalid si(%lx, %lx). "
		       "old_vm_flags=%lx, vma->flags=%lx)\n",
		       si->vaddr, si->size, si->old_vm_flags, vma->vm_flags);
		return;
	}

	vma->vm_flags = si->old_vm_flags;

	//todo: share I merge them?
}

static int uacce_pin_and_share_range(struct uacce_share_info *si)
{
	size_t i, nr_pages = si->size >> PAGE_SHIFT;
	int ret;

	/* pin the page
	 * todo: accounting (RLIMIT_MEMLOCK) for page pin
	 */
	down_read(&current->mm->mmap_sem);

	ret = get_user_pages_longterm(si->vaddr, nr_pages, FOLL_WRITE,
			si->pages, NULL);
	if (ret)
		goto err_with_mm_lock;
	
	ret = uacce_share_vma_range(si);
	if (ret)
		goto err_with_gup;

	up_read(&current->mm->mmap_sem);
	return 0;

err_with_gup:
	for (i = nr_pages; i >= 0; i--) {
		put_page(si->pages[i]);
	}
err_with_mm_lock:
	up_read(&current->mm->mmap_sem);
	return ret;
}

static void uacce_unpin_and_unshare_range(struct uacce_share_info *si)
{
	size_t i, nr_pages = si->size >> PAGE_SHIFT;

	down_read(&current->mm->mmap_sem);

	uacce_unshare_vma_range(si);

	for (i = nr_pages; i >= 0; i--) {
		put_page(si->pages[i]);
	}

	up_read(&current->mm->mmap_sem);
}

/* todo: set the shared vma to VM_SHARE */
static int uacce_share_mem(struct uacce_queue *q, unsigned long arg)
{
	struct uacce_mem_share_arg share;
	struct device *dev = q->uacce->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	int ret;
	int prot = IOMMU_READ | IOMMU_WRITE; /* use bi-dir for now */
	struct uacce_share_info *si, *esi;
	size_t nr_pages, i, j;

	if (q->flags & UACCE_FLAG_SHARE_ALL)
		return -EINVAL;

	if (copy_from_user(&share, (void __user *)arg, sizeof(share)))
		return -EFAULT;

	si = (struct uacce_share_info *)__get_free_page(GFP_KERNEL);
	if (!si)
		return -ENOMEM;

	si->size = share.size;
	si->vaddr = share.vaddr;

	if ((share.size != si->size || share.vaddr != si->vaddr) ||
	    (si->vaddr + si->size -1 < si->vaddr) ||	/* no wrap */
	    !(si->vaddr & ~PAGE_MASK) ||		/* page align */
	    !(si->size & ~PAGE_MASK) ||			/* page align */
	    !domain) {
		ret = -EINVAL;
		goto err_with_si;
	}

	esi = uacce_search_share_info(q, si->vaddr, si->size);
	if (IS_ERR(esi)) {
		ret = PTR_ERR(esi);
		goto err_with_si;
	} else if (esi) {
		ret = -EBUSY;
		goto err_with_si;
	}

	nr_pages = si->size >> PAGE_SHIFT;

	/* todo: give enough space for si */
	BUG_ON(nr_pages*sizeof(*si->pages)+sizeof(si) > PAGE_SIZE);

	ret = uacce_pin_and_share_range(si);
	if (ret)
		goto err_with_si;

	/* map the page one by one */
	for (i = 0; i < nr_pages; i++) {
		ret = iommu_map(domain, si->vaddr + (i << PAGE_SHIFT),
				page_to_pfn(si->pages[i]), PAGE_SIZE, prot);
		if (ret)
			goto err_with_map;
	}

	list_add(&si->list, &q->share_mem_list);

	return 0;

err_with_map:
	for (j = i; j >= 0; j--) {
		iommu_unmap(domain, page_to_pfn(si->pages[j]), PAGE_SIZE);
		SetPageDirty(si->pages[j]); //todo: is this necessary?
		put_page(si->pages[j]);
	}
	uacce_unpin_and_unshare_range(si);
err_with_si:
	free_page((unsigned long)si);
	return ret;
}

static int uacce_unshare_mem(struct uacce_queue *q, unsigned long arg)
{
	struct uacce_mem_share_arg share;
	struct device *dev = q->uacce->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	struct uacce_share_info *si;
	size_t nr_pages, i;

	if (q->flags & UACCE_FLAG_SHARE_ALL)
		return -EINVAL;

	if (copy_from_user(&share, (void __user *)arg, sizeof(share)))
		return -EFAULT;

	if (!domain)
		return -ENODEV;

	si = uacce_search_share_info(q, share.vaddr, share.size);
	if (IS_ERR_OR_NULL(si))
		return PTR_ERR_OR_ZERO(si);

	nr_pages = si->size >> PAGE_SHIFT;

	for (i = 0; i < nr_pages; i++) {
		iommu_unmap(domain, page_to_pfn(si->pages[i]), PAGE_SIZE);
		SetPageDirty(si->pages[i]);
		put_page(si->pages[i]); /* todo: accounting */
	}

	list_del(&si->list);
	free_page((unsigned long)si);

	return 0;
}

static long uacce_fops_unl_ioctl(struct file *filep,
				unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q =
		(struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;

	if (q->pid != current->pid)
		return -EBUSY;

	switch (cmd) {
	case UACCE_CMD_SHARE_MEM:
		return uacce_share_mem(q, arg);
	case UACCE_CMD_UNSHARE_MEM:
		return uacce_unshare_mem(q, arg);
	default:
		if (uacce->ops->ioctl)
			return uacce->ops->ioctl(q, cmd, arg);
		else {
			dev_err(uacce->dev,
				"ioctl cmd (%d) is not supported!\n", cmd);
			return -EINVAL;
		}
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

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce * uacce;
	int ret;
	int pasid = 0;

#ifdef CONFIG_IOMMU_SVA
	/* todo: allocate pasid for this process */
#endif

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce)
		return -ENODEV;

	if (!uacce->ops->get_queue)
		return -EINVAL;

	ret = uacce->ops->get_queue(uacce, pasid, &q);
	if (ret < 0) {
		dev_err(uacce->dev, "get_queue failed\n");
		return -ENODEV;
	}

	q->uacce = uacce;
	q->pid = current->pid;
	init_waitqueue_head(&q->wait);
	INIT_LIST_HEAD(&q->share_mem_list);
	filep->private_data = q;

	if (uacce->ops->start_queue) {
		ret = uacce->ops->start_queue(q);
		if (ret)
			goto err_with_queue;
	}

	return 0;

err_with_queue:
	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);
	return ret;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;
	struct uacce_share_info *si, *si_tmp;
	struct device *dev = uacce->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	size_t nr_pages, i;

	if (!domain)
		dev_warn(dev, "dev is running in no iommu mode\n");
	
	if (uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	list_for_each_entry_safe(si, si_tmp, &q->share_mem_list, list) {
		pr_err("there are data?\n");
		nr_pages = si->size >> PAGE_SHIFT;
		for (i = 0; i < nr_pages; i++) {
			if (domain)
				iommu_unmap(domain, page_to_pfn(si->pages[i]),
					    PAGE_SIZE);
			SetPageDirty(si->pages[i]);
			put_page(si->pages[i]); /* todo: accounting */
		}

		list_del(&si->list);
		free_page((unsigned long)si);
	}

	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);
	
	/* todo: should I get/put the module or device? */
	return 0;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;

	if (q->pid != current->pid)
		return -EBUSY;

	if (uacce->ops->mmap) {
		vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND;
		return uacce->ops->mmap(q, vma);
	}

	dev_err(uacce->dev, "no driver mmap!\n");
	return -EINVAL;
}

static __poll_t uacce_fops_poll(struct file *file, poll_table *wait)
{
	struct uacce_queue *q =
		(struct uacce_queue *)file->private_data;
	struct uacce *uacce = q->uacce;

	poll_wait(file, &q->wait, wait);
	if (uacce->ops->is_q_updated(q))
		return EPOLLIN | EPOLLRDNORM;

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

/**
 *	uacce_register - register an accelerator
 *	@uacce: the accelerator structure
 */
int uacce_register(struct uacce *uacce)
{
	int ret;
	struct cdev *cdev;

	if (!uacce->dev)
		return -ENODEV;

	mutex_lock(&uacce_mutex);

	uacce->dev_id = idr_alloc(&uacce_idr, uacce, 0, 0, GFP_KERNEL);
	if (uacce->dev_id < 0) {
		ret = uacce->dev_id;
		goto err_with_lock;
	}

	uacce->cls_dev.parent = uacce->dev;
	uacce->cls_dev.class = uacce_class;
	uacce->cls_dev.release = uacce_cls_release;
	dev_set_name(&uacce->cls_dev, "%s", dev_name(uacce->dev));
	ret = device_register(&uacce->cls_dev);
	if (ret)
		goto err_with_idr;

	cdev = cdev_alloc();
	if (!cdev) {
		ret = -ENOMEM;
		goto err_with_idr;
	}

	cdev->ops = &uacce_fops;
	cdev->owner = uacce->owner;
	ret = cdev_add(cdev, uacce_devt, 1);
	if (ret)
		goto err_with_cdev;

	mutex_unlock(&uacce_mutex);
	return 0;

err_with_cdev:
	cdev_del(cdev);
err_with_idr:
	idr_remove(&uacce_idr, uacce->dev_id);
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

	idr_remove(&uacce_idr, uacce->dev_id);
	device_unregister(&uacce->cls_dev);

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

module_init(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
