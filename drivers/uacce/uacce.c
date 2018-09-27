/* SPDX-License-Identifier: GPL-2.0+ */
#include <linux/uacce.h>
#include <linux/compat.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/file.h>

static struct class *uacce_class;
static DEFINE_IDR(uacce_idr);
static dev_t uacce_devt;
static DEFINE_MUTEX(uacce_mutex);

static const struct file_operations uacce_fops;

/**
 * uacce_wake_up - Wake up the process who is waiting this queue
 * @q the accelerator queue to wake up
 */
void uacce_wake_up(struct uacce_queue *q)
{
	wake_up(&q->wait);
}
EXPORT_SYMBOL_GPL(uacce_wake_up);

static void uacce_cls_release(struct device *dev) { }

static inline void uacce_get_svas_no_q(struct uacce_svas *svas)
{
	atomic_inc(&svas->refcount);
}

static inline void uacce_put_svas_no_q(struct uacce_svas *svas)
{
	int i;

	if (atomic_dec_and_test(&svas->refcount)) {
		if (svas->pages) {
			for (i = 0; i < svas->nr_pages; i++)
				put_page(svas->pages[i]);
			kfree(svas->pages);
		}
		kfree(svas);
	}
}

/* hold the q mutex before call this function */
struct uacce_svas *uacce_get_svas(struct uacce_queue *q)
{
	if (q->svas) {
		uacce_get_svas_no_q(q->svas);
		return q->svas;
	}

	q->svas = kzalloc(sizeof(*q->svas), GFP_KERNEL);
	if (!q->svas)
		return ERR_PTR(-ENOMEM);

	mutex_init(&q->svas->mutex);
	INIT_LIST_HEAD(&q->svas->qs);
	atomic_inc(&q->svas->refcount);

	return q->svas;
}
EXPORT_SYMBOL_GPL(uacce_get_svas);

/* share the src's svas to the tgt
 * DO NOT hold the q mutex before call this function */
static int uacce_share_svas(struct uacce_queue *tgt, struct uacce_queue *src)
{
	struct uacce_svas *svas;

	mutex_lock(&src->mutex);
	svas = uacce_get_svas(src);
	mutex_unlock(&src->mutex);

	if (!svas)
		return -ENODEV;

	mutex_lock(&tgt->mutex);
	tgt->svas = svas;
	mutex_unlock(&tgt->mutex);

	mutex_lock(&svas->mutex);
	list_add(&tgt->list, &svas->qs);
	mutex_unlock(&svas->mutex);

	return 0;
}

/* DO NOT hold the q mutex before call this function */
void uacce_put_svas(struct uacce_queue *q)
{
	struct uacce_svas *svas;

	mutex_lock(&q->mutex);
	svas = q->svas;
	q->svas = NULL;
	mutex_unlock(&q->mutex);

	if (!svas)
		return;

	mutex_lock(&svas->mutex);
	list_del(&q->list);
	mutex_unlock(&svas->mutex);

	uacce_put_svas_no_q(svas);
}
EXPORT_SYMBOL_GPL(uacce_put_svas);

static long uacce_cmd_share_svas(struct uacce_queue *tgt, int fd)
{
	struct file *filep = fget(fd);
	struct uacce_queue *src;

	if (!filep || filep->f_op != &uacce_fops)
		return -EINVAL;

	src = (struct uacce_queue *)filep->private_data;
	if (!src)
		return -EINVAL;

	return uacce_share_svas(tgt, src);
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

static int inline uacce_iommu_map_shm_pages(struct uacce_queue *q)
{
	struct device *dev = q->uacce->dev;
	struct uacce_svas *svas = q->svas;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	int i, j, ret;

	if (!domain)
		return -ENODEV;

	mutex_lock(&svas->mutex);
	for (i=0; i < svas->nr_pages; i++) {
		get_page(svas->pages[i]);
		ret = iommu_map(domain, svas->va + i * PAGE_SIZE,
				page_to_pfn(svas->pages[i]), PAGE_SIZE,
				svas->prot);
		if (ret)
			goto err_with_map_pages;
	}
	mutex_unlock(&svas->mutex);

	return 0;

err_with_map_pages:
	for (j=i-1; j>=0; j--) {
		iommu_unmap(domain, svas->va + j * PAGE_SIZE, PAGE_SIZE);
		put_page(svas->pages[j]);
	}
	mutex_unlock(&svas->mutex);
	return ret;
}

static inline void uacce_iommu_unmap_shm_pages(struct uacce_queue *q)
{
	struct device *dev = q->uacce->dev;
	struct uacce_svas *svas = q->svas;
	struct iommu_domain * domain = iommu_get_domain_for_dev(dev);
	int i;

	if (domain)
		return;

	mutex_lock(&svas->mutex);
	for (i=svas->nr_pages-1; i>=0; i--) {
		iommu_unmap(domain, svas->va + i * PAGE_SIZE, PAGE_SIZE);
		put_page(svas->pages[i]);
	}
	mutex_lock(&svas->mutex);
}

static int uacce_map_shm_on_queue(struct uacce_queue *q)
{
	struct uacce_svas *svas = q->svas;
	int ret;

	if (!svas->va) {
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
	struct uacce_svas *svas = q->svas;

	if (!svas->va || q->mapped_shm)
		return;

	if (q->uacce->ops->map) {
		if (q->uacce->ops->unmap)
			q->uacce->ops->unmap(q);
	} else
		uacce_iommu_map_shm_pages(q);
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce * uacce;
	int ret;
	int pasid = 0;

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce)
		return -ENODEV;

	if (!uacce->ops->get_queue)
		return -EINVAL;

#ifdef CONFIG_IOMMU_SVA
	/* todo: allocate queue pasid and set for this process */
#endif

	ret = uacce->ops->get_queue(uacce, pasid, &q);
	if (ret < 0)
		return ret;

	q->uacce = uacce;
	init_waitqueue_head(&q->wait);
	mutex_init(&q->mutex);
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

static vm_fault_t uacce_shm_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct uacce_svas *svas = vma->vm_private_data;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

	pr_info("fault on page %ld\n", page_offset);

	if (page_offset >= svas->nr_pages)
		return VM_FAULT_SIGBUS;

	mutex_lock(&svas->mutex);
	get_page(svas->pages[page_offset]);
	vmf->page = svas->pages[page_offset];
	mutex_unlock(&svas->mutex);

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

	uacce_unmap_shm_on_queue(q);
	uacce_put_svas(q);

	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);
	
	return 0;
}

static int uacce_create_shm_pages(struct uacce_svas *svas,
				  struct vm_area_struct *vma)
{
	struct uacce_queue *q;
	int i, j, ret = 0;
	LIST_HEAD(mapped);

	mutex_lock(&svas->mutex);

	if (svas->va) {
		ret = -EBUSY;
		goto err_with_lock;
	}

	svas->va = vma->vm_start;
	svas->nr_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

	if (vma->vm_flags & VM_READ)
		svas->prot |= IOMMU_READ;

	if (vma->vm_flags & VM_WRITE)
		svas->prot |= IOMMU_WRITE;

	svas->pages = kzalloc(sizeof(*svas->pages) * svas->nr_pages,
			       GFP_KERNEL);
	if (!svas->pages) {
		ret = -ENOMEM;
		goto err_with_init;
	}

	for (i=0; i < svas->nr_pages; i++) {
		svas->pages[i] = alloc_page(GFP_KERNEL);
		if (!svas->pages[i])
			goto err_with_pages;
	}

	list_for_each_entry(q, &svas->qs, list) {
		ret = uacce_map_shm_on_queue(q);
		if (ret)
			goto err_with_mapped_queue;
	}

	mutex_unlock(&svas->mutex);
	return 0;

err_with_mapped_queue:
	list_for_each_entry(q, &svas->qs, list) {
		uacce_unmap_shm_on_queue(q);
	}
err_with_pages:
	for (j=i-1; j>=0; j--) {
		put_page(svas->pages[j]);
		svas->pages[j] = NULL;
	}
err_with_init:
	svas->va = 0;
	svas->nr_pages = 0;
err_with_lock:
	mutex_unlock(&svas->mutex);
	return ret;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = (struct uacce_queue *)filep->private_data;
	struct uacce *uacce = q->uacce;
	struct uacce_svas *svas;
	int ret;

	mutex_lock(&q->mutex);

	if (uacce->io_nr_pages !=0 && vma->vm_pgoff >= uacce->io_nr_pages) {
		svas = uacce_get_svas(q);
		if (IS_ERR(svas))
			return PTR_ERR(svas);

		vma->vm_ops = &uacce_shm_vm_ops;
		vma->vm_private_data = svas;

		dev_info(uacce->dev, "map share memory (off=%lx)\n",
			 vma->vm_pgoff);
		ret = uacce_create_shm_pages(svas, vma);
	}else if (uacce->ops->mmap) {
		vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND;
		dev_info(uacce->dev, "map accelerator io space (off=%lx)\n",
			 vma->vm_pgoff);
		ret = uacce->ops->mmap(q, vma);
	}else {
		dev_err(uacce->dev, "no driver mmap!\n");
		ret = -ENODEV;
	}

	mutex_unlock(&q->mutex);
	return ret;
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
