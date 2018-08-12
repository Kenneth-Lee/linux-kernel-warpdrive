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

static long acce4u_fops_unl_ioctl(struct file *filep,
				unsigned int cmd, unsigned long arg)
{
	struct acce4u_queue *q =
		(struct acce4u_queue *)filep->private_data;
	struct acce4u *acce4u = q->acce4u;

	switch (cmd) {
	case ACCE4U_CMD_SHARE_MEM:
		return -EINVAL; //todo
	case ACCE4U_CMD_UNSHARE_MEM:
		return -EINVAL; //todo
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
	filep->private_data = q;

	return ret;
}

static int acce4u_fops_release(struct inode *inode, struct file *filep)
{
	struct acce4u_queue *q = (struct acce4u_queue *)filep->private_data;
	struct acce4u *acce4u = q->acce4u;

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
