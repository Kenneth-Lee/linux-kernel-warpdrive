/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/uacce.h>
#include <linux/compat.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/slab.h>

static struct class *uacce_class;
static DEFINE_IDR(uacce_idr);
static dev_t uacce_devt;
static DEFINE_MUTEX(uacce_mutex);
static LIST_HEAD(as_list); /* todo: use rcu version in the future */

static void uacce_dump_pages(struct uacce_as *as, char *msg)
{
	int i;

	pr_info("%s", msg);
	pr_info(" dump pages(%d) state\n", as->nr_pages);
	for (i=0; i < as->nr_pages; i++)
		pr_info("page[%d] ref=%d", i, page_ref_count(as->pages[i]));
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

static long uacce_fops_unl_ioctl(struct file *filep,
				unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q =
		(struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;

	if (q->as->pid != current->pid)
		return -EBUSY;

	switch (cmd) {
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

static struct uacce_as *uacce_get_as(void)
{
	struct uacce_as *as;
	pid_t pid = current->pid;

	mutex_lock(&uacce_mutex);

	list_for_each_entry(as, &as_list, list) {
		if (as->pid == pid)
			goto out;
	}

	as = kzalloc(sizeof(*as), GFP_KERNEL);
	if (!as) {
		as = ERR_PTR(-ENOMEM);
		goto out;
	}
	as->pid = pid;
	mutex_init(&as->mutex);
	list_add(&as->list, &as_list);
	atomic_inc(&as->refcount);
	INIT_LIST_HEAD(&as->qs);

out:
	mutex_unlock(&uacce_mutex);
	return as;
}

static void uacce_put_as(struct uacce_as *as)
{
	int i;

	if (atomic_dec_and_test(&as->refcount)) {
		if (as->pages) {
			for (i = 0; i < as->nr_pages; i++)
				put_page(as->pages[i]);
			kfree(as->pages);
		}

		mutex_lock(&uacce_mutex);
		list_del(&as->list);
		kfree(as);
		mutex_unlock(&uacce_mutex);
	}
}

static int inline uacce_iommu_map_shm_pages(struct uacce_queue *q)
{
	struct device *dev = q->uacce->dev;
	struct uacce_as *as = q->as;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	int i, j, ret;

	if (!domain)
		return -ENODEV;

	for (i=0; i < as->nr_pages; i++) {
		get_page(as->pages[i]);
		ret = iommu_map(domain, as->va + i * PAGE_SIZE,
				page_to_pfn(as->pages[i]), PAGE_SIZE, as->prot);
		if (ret)
			goto err_with_map_pages;
	}

	return 0;

err_with_map_pages:
	for (j=i-1; j>=0; j--) {
		iommu_unmap(domain, as->va + j * PAGE_SIZE, PAGE_SIZE);
		put_page(as->pages[j]);
	}
	return ret;
}

static inline void uacce_iommu_unmap_shm_pages(struct uacce_queue *q)
{
	struct device *dev = q->uacce->dev;
	struct uacce_as *as = q->as;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	int i;

	if (domain)
		return;

	for (i=as->nr_pages-1; i>=0; i--) {
		iommu_unmap(domain, as->va + i * PAGE_SIZE, PAGE_SIZE);
		put_page(as->pages[i]);
	}
}

static int uacce_map_shm_on_queue(struct uacce_queue *q)
{
	struct uacce_as *as = q->as;
	int ret;

	if (!as->va) {
		return 0;
	}

	ret = q->uacce->ops->map ? q->uacce->ops->map(q) :
				   uacce_iommu_map_shm_pages(q);
	if (!ret)
		q->mapped_shm = true;

	return ret;
}

static void uacce_unmap_shm_on_queue(struct uacce_queue *q)
{
	struct uacce_as *as = q->as;

	if (!as->va || q->mapped_shm)
		return;

	if (q->uacce->ops->map) {
		if (q->uacce->ops->unmap)
			q->uacce->ops->unmap(q);
	} else
		uacce_iommu_map_shm_pages(q);
}

static void uacce_as_add_queue(struct uacce_queue *q) {
	mutex_lock(&q->as->mutex);
	list_add(&q->list, &q->as->qs);
	mutex_unlock(&q->as->mutex);
}

static void uacce_as_del_queue(struct uacce_queue *q) {
	mutex_lock(&q->as->mutex);
	list_add(&q->list, &q->as->qs);
	mutex_unlock(&q->as->mutex);
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce * uacce;
	int ret;
	int pasid = 0;
	struct uacce_as *as;

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce)
		return -ENODEV;

	if (!uacce->dev) {
		/* open manager */
		filep->private_data = NULL;
		return 0;
	}

	if (!uacce->ops->get_queue)
		return -EINVAL;

	as = uacce_get_as();
	if (IS_ERR(as))
		return PTR_ERR(as);

#ifdef CONFIG_IOMMU_SVA
	/* todo: allocate queue pasid and set for this process */
#endif

	ret = uacce->ops->get_queue(uacce, pasid, &q);
	if (ret < 0) {
		dev_err(uacce->dev, "get_queue failed\n");
		goto err_with_as;
	}

	q->uacce = uacce;
	q->as = as;
	init_waitqueue_head(&q->wait);
	mutex_init(&q->mutex);
	filep->private_data = q;

	if (uacce->ops->start_queue) {
		ret = uacce->ops->start_queue(q);
		if (ret)
			goto err_with_queue;
	}

	ret = uacce_map_shm_on_queue(q);
	if (ret)
		goto err_with_started_queue;

	uacce_as_add_queue(q);
	return 0;

err_with_started_queue:
	if (uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);
err_with_queue:
	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);
err_with_as:
	uacce_put_as(as);
	return ret;
}

static vm_fault_t uacce_shm_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct uacce_as *as = vma->vm_private_data;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

	pr_info("fault on page %ld\n", page_offset);

	if (page_offset >= as->nr_pages)
		return VM_FAULT_SIGBUS;

	mutex_lock(&as->mutex);
	get_page(as->pages[page_offset]);
	vmf->page = as->pages[page_offset];
	mutex_unlock(&as->mutex);

	uacce_dump_pages(as, "fault");

	return 0;
}

static const struct vm_operations_struct uacce_shm_vm_ops = {
	.fault = uacce_shm_vm_fault,
};

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce;

	if (!q) {
		/* close manager */
		return 0;
	}

	uacce = q->uacce;

	if (uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	uacce_unmap_shm_on_queue(q);
	uacce_as_del_queue(q);
	uacce_put_as(q->as);
	q->as = NULL;

	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);
	
	/* todo: should I get/put the module or device? */
	return 0;
}

static int uacce_create_shm_pages(struct uacce_as *as,
				  struct vm_area_struct *vma)
{
	struct uacce_queue *q;
	int i, j, ret = 0;
	LIST_HEAD(mapped);

	mutex_lock(&as->mutex);

	if (as->va) {
		ret = -EBUSY;
		goto err_with_lock;
	}

	as->va = vma->vm_start;
	as->nr_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

	if (vma->vm_flags & VM_READ)
		as->prot |= IOMMU_READ;

	if (vma->vm_flags & VM_WRITE)
		as->prot |= IOMMU_WRITE;

	as->pages = kzalloc(sizeof(*as->pages) * as->nr_pages,
			       GFP_KERNEL);
	if (!as->pages) {
		ret = -ENOMEM;
		goto err_with_init;
	}

	for (i=0; i < as->nr_pages; i++) {
		as->pages[i] = alloc_page(GFP_KERNEL);
		if (!as->pages[i])
			goto err_with_pages;
	}

	list_for_each_entry(q, &as->qs, list) {
		ret = uacce_map_shm_on_queue(q);
		if (ret)
			goto err_with_mapped_queue;
	}

	mutex_unlock(&as->mutex);
	return 0;

err_with_mapped_queue:
	list_for_each_entry(q, &as->qs, list) {
		uacce_unmap_shm_on_queue(q);
	}
err_with_pages:
	for (j=i-1; j>=0; j--) {
		put_page(as->pages[j]);
		as->pages[j] = NULL;
	}
err_with_init:
	as->va = 0;
	as->nr_pages = 0;
err_with_lock:
	mutex_unlock(&as->mutex);
	return ret;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce;
	struct uacce_as *as;

	as = uacce_get_as();
	if (IS_ERR(as))
		return PTR_ERR(as);

	vma->vm_ops = &uacce_shm_vm_ops;
	vma->vm_private_data = as;

	if (!q)
		return uacce_create_shm_pages(as, vma);

	uacce = q->uacce;

	if (uacce->io_nr_pages !=0 && vma->vm_pgoff >= uacce->io_nr_pages) {
		pr_info("map share memory (off=%lx)\n", vma->vm_pgoff);
		return uacce_create_shm_pages(as, vma);
	}else if (uacce->ops->mmap) {
		vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND;
		pr_info("map accelerator io space (off=%lx)\n", vma->vm_pgoff);
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

static int uacce_create_chrdev(struct uacce *uacce)
{
	int ret;

	uacce->dev_id = idr_alloc(&uacce_idr, uacce, 0, 0, GFP_KERNEL);
	if (uacce->dev_id < 0)
		return uacce->dev_id;

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

	idr_remove(&uacce_idr, uacce->dev_id);
	device_unregister(&uacce->cls_dev);

	mutex_unlock(&uacce_mutex);
}
EXPORT_SYMBOL_GPL(uacce_unregister);

static struct uacce uacce_manager = {
	.name = "Uacce Manager",
	.owner = THIS_MODULE,
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

	pr_info("uacce init with major number:%d\n", MAJOR(uacce_devt));

	/* create the manager device */
	ret = uacce_create_chrdev(&uacce_manager);
	if (ret < 0)
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
	mutex_lock(&uacce_mutex);
	uacce_destroy_chrdev(&uacce_manager);
	unregister_chrdev_region(uacce_devt, MINORMASK);
	class_destroy(uacce_class);
	idr_destroy(&uacce_idr);
	mutex_unlock(&uacce_mutex);
}

module_init(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
