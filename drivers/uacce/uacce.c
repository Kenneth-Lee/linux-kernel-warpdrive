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
static struct cdev uacce_cdev;

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

/**
 *	uacce_register - register an accelerator
 *	@uacce: the accelerator structure
 */
int uacce_register(struct uacce *uacce)
{
	int ret;
	const char *drv_name;
	struct device *dev;

	if (!uacce->dev)
		return -ENODEV;

	drv_name = dev_driver_string(uacce->dev);
	if (strstr(drv_name, "-")) {
		pr_err("uacce: parent driver name cannot include '-'!\n");
		return -EINVAL;
	}

	uacce->dev_id = idr_alloc(&uacce_idr, uacce, 0, 0, GFP_KERNEL);
	if (uacce->dev_id < 0)
		return uacce->dev_id;

	atomic_set(&uacce->ref, 0); /* kenny: check if this is necessary */
	uacce->cls_dev.parent = uacce->dev;
	uacce->cls_dev.class = uacce_class;
	uacce->cls_dev.release = uacce_cls_release;
	dev_set_name(&uacce->cls_dev, "%s", dev_name(uacce->dev));
	ret = device_register(&uacce->cls_dev);
	if (ret)
		goto err_with_idr;

	dev = device_create(uacce_class, uacce->dev,
			MKDEV(MAJOR(uacce_devt), uacce->dev_id),
			uacce, "acce%d", uacce->dev_id);
	if (IS_ERR(dev))
		goto err_with_cls_dev;

	return 0;

err_with_cls_dev:
	device_unregister(&uacce->cls_dev);
err_with_idr:
	idr_remove(&uacce_idr, uacce->dev_id);
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
	idr_remove(&uacce_idr, uacce->dev_id);
	device_unregister(&uacce->cls_dev);
	device_destroy(uacce_class,
		       MKDEV(MAJOR(uacce_devt), uacce->dev_id));
}
EXPORT_SYMBOL_GPL(uacce_unregister);

struct uacce_share_info {
	struct list_head list;
	size_t size;
	unsigned long vaddr;
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

static int uacce_share_mem(struct uacce_queue *q, unsigned long arg)
{
	struct uacce_mem_share_arg share;
	struct device *dev = q->uacce->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	int ret;
	int prot = IOMMU_READ | IOMMU_WRITE; /* use bi-dir for now */
	struct uacce_share_info *si, *esi;
	struct mm_struct *mm = current->mm;
	size_t nr_pages, i, j;

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

static int uacce_unshare_mem(struct uacce_queue *q, unsigned long arg)
{
	struct uacce_mem_share_arg share;
	struct device *dev = q->uacce->dev;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	struct uacce_share_info *si;
	size_t nr_pages, i;

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
	init_waitqueue_head(&q->wait);
	INIT_LIST_HEAD(&q->share_mem_list);
	filep->private_data = q;

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

	WARN_ON(!domain);
	
	uacce->ops->stop_queue(q);

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

	uacce->ops->put_queue(q);
	
	/* todo: should I get/put the module or device? */
	return 0;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;

	if (uacce->ops->mmap)
		return uacce->ops->mmap(q, vma);

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

	cdev_init(&uacce_cdev, &uacce_fops);
	ret = cdev_add(&uacce_cdev, uacce_devt, MINORMASK);
	if (ret)
		goto err_with_chrdev_region;

	return 0;

err_with_chrdev_region:
	unregister_chrdev_region(uacce_devt, MINORMASK);
err_with_class:
	class_destroy(uacce_class);
err:
	return ret;
}

static __exit void uacce_exit(void)
{
	class_destroy(uacce_class);
	idr_destroy(&uacce_idr);
}

module_init(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
