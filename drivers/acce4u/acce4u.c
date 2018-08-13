/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/acce4u.h>
#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/wait.h>

struct acce4u_mdev_state {
	struct acce4u *acce4u;
};

static struct class *acce4u_class;
static DEFINE_IDR(acce4u_idr);
static dev_t acce4u_devt;
static struct cdev acce4u_cdev;

/**
 * cce4u_wake_up - Wake up the process who is waiting this queue
 * @q the accelerator queue to wake up
 */
void acce4u_wake_up(struct acce4u_queue *q)
{
	wake_up(&q->wait);
}
EXPORT_SYMBOL_GPL(acce4u_wake_up);

static void acce4u_cls_release(struct device *dev) { }

/**
 *	acce4u_register - register an accelerator
 *	@acce4u: the accelerator structure
 */
int acce4u_register(struct acce4u *acce4u)
{
	int ret;
	const char *drv_name;
	struct device *dev;

	if (!acce4u->dev)
		return -ENODEV;

	drv_name = dev_driver_string(acce4u->dev);
	if (strstr(drv_name, "-")) {
		pr_err("acce4u: parent driver name cannot include '-'!\n");
		return -EINVAL;
	}

	acce4u->dev_id = idr_alloc(&acce4u_idr, acce4u, 0, 0, GFP_KERNEL);
	if (acce4u->dev_id < 0)
		return acce4u->dev_id;

	atomic_set(&acce4u->ref, 0); /* kenny: check if this is necessary */
	acce4u->cls_dev.parent = acce4u->dev;
	acce4u->cls_dev.class = acce4u_class;
	acce4u->cls_dev.release = acce4u_cls_release;
	dev_set_name(&acce4u->cls_dev, "%s", dev_name(acce4u->dev));
	ret = device_register(&acce4u->cls_dev);
	if (ret)
		goto err_with_idr;

	dev = device_create(acce4u_class, acce4u->dev,
			MKDEV(MAJOR(acce4u_devt), acce4u->dev_id),
			acce4u, "acce%d", acce4u->dev_id);
	if (IS_ERR(dev))
		goto err_with_cls_dev;

	return 0;

err_with_cls_dev:
	device_unregister(&acce4u->cls_dev);
err_with_idr:
	idr_remove(&acce4u_idr, acce4u->dev_id);
	return ret;
}
EXPORT_SYMBOL_GPL(acce4u_register);

/**
 * acce4u_unregister - unregisters a acce4u
 * @acce4u: the accelerator to unregister
 *
 * Unregister an accelerator that wat previously successully registered with
 * acce4u_register().
 */
void acce4u_unregister(struct acce4u *acce4u)
{
	idr_remove(&acce4u_idr, acce4u->dev_id);
	device_unregister(&acce4u->cls_dev);
	device_destroy(acce4u_class,
		       MKDEV(MAJOR(acce4u_devt), acce4u->dev_id));
}
EXPORT_SYMBOL_GPL(acce4u_unregister);

struct acce4u_share_info {
	struct list_head list;
	size_t size;
	unsigned long vaddr;
	struct page *pages[];
};

static struct acce4u_share_info * acce4u_search_share_info(
	struct acce4u_queue *q, unsigned long vaddr, size_t size)
{
	struct acce4u_share_info *si;

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

static int acce4u_share_mem(struct acce4u_queue *q, unsigned long arg)
{
	struct acce4u_mem_share_arg share;
	struct device *dev = q->acce4u->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	int ret;
	int prot = IOMMU_READ | IOMMU_WRITE; /* use bi-dir for now */
	struct acce4u_share_info *si, *esi;
	struct mm_struct *mm = current->mm;
	size_t nr_pages, i, j;

	if (copy_from_user(&share, (void __user *)arg, sizeof(share)))
		return -EFAULT;

	si = (struct acce4u_share_info *)__get_free_page(GFP_KERNEL);
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

	esi = acce4u_search_share_info(q, si->vaddr, si->size);
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

	/* pin the page
	 * todo: accounting (RLIMIT_MEMLOCK) for page pin,  this is
	 * not going to be a easy job
	 */
	down_read(&mm->mmap_sem);
	ret = get_user_pages_longterm(si->vaddr, nr_pages, FOLL_WRITE,
			si->pages, NULL);
	up_read(&mm->mmap_sem);
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
		SetPageDirty(si->pages[j]);
		put_page(si->pages[j]);
	}

err_with_si:
	free_page((unsigned long)si);
	return ret;
}

static int acce4u_unshare_mem(struct acce4u_queue *q, unsigned long arg)
{
	struct acce4u_mem_share_arg share;
	struct device *dev = q->acce4u->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	struct acce4u_share_info *si;
	size_t nr_pages, i;

	if (copy_from_user(&share, (void __user *)arg, sizeof(share)))
		return -EFAULT;

	if (!domain)
		return -ENODEV;

	si = acce4u_search_share_info(q, share.vaddr, share.size);
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

static long acce4u_fops_unl_ioctl(struct file *filep,
				unsigned int cmd, unsigned long arg)
{
	struct acce4u_queue *q =
		(struct acce4u_queue *)filep->private_data;
	struct acce4u *acce4u = q->acce4u;

	switch (cmd) {
	case ACCE4U_CMD_SHARE_MEM:
		return acce4u_share_mem(q, arg);
	case ACCE4U_CMD_UNSHARE_MEM:
		return acce4u_unshare_mem(q, arg);
	default:
		if (acce4u->ops->ioctl)
			return acce4u->ops->ioctl(q, cmd, arg);
		else {
			dev_err(acce4u->dev,
				"ioctl cmd (%d) is not supported!\n", cmd);
			return -EINVAL;
		}
	}
}

#ifdef CONFIG_COMPAT
static long acce4u_fops_compat_ioctl(struct file *filep,
				   unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return acce4u_fops_unl_ioctl(filep, cmd, arg);
}
#endif

static int acce4u_fops_open(struct inode *inode, struct file *filep)
{
	struct acce4u_queue *q;
	struct acce4u * acce4u;
	int ret;
	int pasid = 0;

#ifdef CONFIG_IOMMU_SVA
	/* todo: allocate pasid for this process */
#endif

	acce4u = idr_find(&acce4u_idr, iminor(inode));
	if (!acce4u)
		return -ENODEV;

	if (!acce4u->ops->get_queue)
		return -EINVAL;

	ret = acce4u->ops->get_queue(acce4u, pasid, &q);
	if (ret < 0) {
		dev_err(acce4u->dev, "get_queue failed\n");
		return -ENODEV;
	}

	q->acce4u = acce4u;
	init_waitqueue_head(&q->wait);
	INIT_LIST_HEAD(&q->share_mem_list);
	filep->private_data = q;

	return ret;
}

static int acce4u_fops_release(struct inode *inode, struct file *filep)
{
	struct acce4u_queue *q = (struct acce4u_queue *)filep->private_data;
	struct acce4u *acce4u = q->acce4u;
	struct acce4u_share_info *si, *si_tmp;
	struct device *dev = acce4u->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	size_t nr_pages, i;

	WARN_ON(!domain);
	
	acce4u->ops->stop_queue(q);

	list_for_each_entry_safe(si, si_tmp, &q->share_mem_list, list) {
		nr_pages = si->size >> PAGE_SHIFT;
		for (i = 0; i < nr_pages; i++) {
			iommu_unmap(domain, page_to_pfn(si->pages[i]),
				    PAGE_SIZE);
			SetPageDirty(si->pages[i]);
			put_page(si->pages[i]); /* todo: accounting */
		}

		list_del(&si->list);
		free_page((unsigned long)si);
	}

	acce4u->ops->put_queue(q);
	
	/* todo: should I get/put the module or device? */
	return 0;
}

static int acce4u_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct acce4u_queue *q = (struct acce4u_queue *)filep->private_data;
	struct acce4u *acce4u = q->acce4u;

	if (acce4u->ops->mmap)
		return acce4u->ops->mmap(q, vma);

	dev_err(acce4u->dev, "no driver mmap!\n");
	return -EINVAL;
}

static __poll_t acce4u_fops_poll(struct file *file, poll_table *wait)
{
	struct acce4u_queue *q =
		(struct acce4u_queue *)file->private_data;
	struct acce4u *acce4u = q->acce4u;

	poll_wait(file, &q->wait, wait);
	if (acce4u->ops->is_q_updated(q))
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}

static const struct file_operations acce4u_fops = {
	.owner		= THIS_MODULE,
	.open		= acce4u_fops_open,
	.release	= acce4u_fops_release,
	.unlocked_ioctl	= acce4u_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= acce4u_fops_compat_ioctl,
#endif
	.mmap		= acce4u_fops_mmap,
	.poll		= acce4u_fops_poll,
};

static int __init acce4u_init(void)
{
	int ret;

	acce4u_class = class_create(THIS_MODULE, ACCE4U_CLASS_NAME);
	if (IS_ERR(acce4u_class)) {
		ret = PTR_ERR(acce4u_class);
		goto err;
	}

	ret = alloc_chrdev_region(&acce4u_devt, 0, MINORMASK, "acce4u");
	if (ret)
		goto err_with_class;

	cdev_init(&acce4u_cdev, &acce4u_fops);
	ret = cdev_add(&acce4u_cdev, acce4u_devt, MINORMASK);
	if (ret)
		goto err_with_chrdev_region;

	return 0;

err_with_chrdev_region:
	unregister_chrdev_region(acce4u_devt, MINORMASK);
err_with_class:
	class_destroy(acce4u_class);
err:
	return ret;
}

static __exit void acce4u_exit(void)
{
	class_destroy(acce4u_class);
	idr_destroy(&acce4u_idr);
}

module_init(acce4u_init);
module_exit(acce4u_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
