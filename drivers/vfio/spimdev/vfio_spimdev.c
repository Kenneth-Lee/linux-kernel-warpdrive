// SPDX-License-Identifier: GPL-2.0+
#include <linux/module.h>
#include <linux/of.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/vfio_spimdev.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>

struct spimdev_mdev_state {
	struct vfio_spimdev *spimdev;
};

static struct class *spimdev_class;

static int __dev_exist(struct device *dev, void *data)
{
	return !strcmp(dev_name(dev), dev_name((struct device *)data));
}

#ifdef CONFIG_IOMMU_SVA
static bool _is_valid_pasid(int pasid)
{
	struct mm_struct *mm;

	mm = iommu_sva_find(pasid);
	if (mm) {
		mmput(mm);
		return mm == current->mm;
	}

	return false;
}
#endif

/* Check if the device is a mediated device belongs to vfio_spimdev */
int is_vfio_spimdev_mdev(struct device *dev)
{
	struct mdev_device *mdev;
	struct device *pdev;

	mdev = mdev_from_dev(dev);
	if (!mdev)
		return 0;

	pdev = mdev_parent_dev(mdev);
	if (!pdev)
		return 0;

	return class_for_each_device(spimdev_class, NULL, pdev, __dev_exist);
}
EXPORT_SYMBOL(is_vfio_spimdev_mdev);

struct vfio_spimdev *vfio_spimdev_pdev_spimdev(struct device *dev)
{
	struct device *class_dev;

	if (!dev)
		return ERR_PTR(-EINVAL);

	class_dev = class_find_device(spimdev_class, NULL, dev,
		       (int(*)(struct device *, const void *))__dev_exist);
	if (!class_dev)
		return ERR_PTR(-ENODEV);

	return container_of(class_dev, struct vfio_spimdev, cls_dev);
}
EXPORT_SYMBOL(vfio_spimdev_pdev_spimdev);

struct vfio_spimdev *mdev_spimdev(struct mdev_device *mdev)
{
	struct device *pdev = mdev_parent_dev(mdev);

	return vfio_spimdev_pdev_spimdev(pdev);
}
EXPORT_SYMBOL(mdev_spimdev);

static ssize_t iommu_type_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	if (!spimdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", spimdev->iommu_type);
}

static DEVICE_ATTR_RO(iommu_type);

static ssize_t dma_flag_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	if (!spimdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", spimdev->dma_flag);
}

static DEVICE_ATTR_RO(dma_flag);

/* mdev->dev_attr_groups */
static struct attribute *vfio_spimdev_attrs[] = {
	&dev_attr_iommu_type.attr,
	&dev_attr_dma_flag.attr,
	NULL,
};
static const struct attribute_group vfio_spimdev_group = {
	.name  = VFIO_SPIMDEV_PDEV_ATTRS_GRP_NAME,
	.attrs = vfio_spimdev_attrs,
};
const struct attribute_group *vfio_spimdev_groups[] = {
	&vfio_spimdev_group,
	NULL,
};

/* default attributes for mdev->supported_type_groups, used by registerer*/
#define DEVICE_ATTR_RO_EXPORT(name)	\
		DEVICE_ATTR_RO(name);	\
		EXPORT_SYMBOL(dev_attr_##name);

#define MDEV_TYPE_ATTR_RO_EXPORT(name)	\
		MDEV_TYPE_ATTR_RO(name);	\
		EXPORT_SYMBOL(mdev_type_attr_##name);

#define DEF_SIMPLE_SPIMDEV_ATTR(_name, spimdev_member, format) \
static ssize_t _name##_show(struct kobject *kobj, struct device *dev, \
			    char *buf) \
{ \
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev); \
	if (!spimdev) \
		return -ENODEV; \
	return sprintf(buf, format, spimdev->spimdev_member); \
} \
MDEV_TYPE_ATTR_RO_EXPORT(_name)

DEF_SIMPLE_SPIMDEV_ATTR(flags, flags, "%d");
DEF_SIMPLE_SPIMDEV_ATTR(name, name, "%s"); /* this should be algorithm name, */
		/* but you would not care if you have only one algorithm */
DEF_SIMPLE_SPIMDEV_ATTR(device_api, api_ver, "%s");

/* this return total queue left, not mdev left */
static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	return sprintf(buf, "%d",
			spimdev->ops->get_available_instances(spimdev));
}
MDEV_TYPE_ATTR_RO_EXPORT(available_instances);


static int vfio_spimdev_mdev_create(struct kobject *kobj,
	struct mdev_device *mdev)
{
	struct device *dev = mdev_dev(mdev);
	struct spimdev_mdev_state *mdev_state;
	struct vfio_spimdev *spimdev = mdev_spimdev(mdev);

	if (!spimdev->ops->get_queue)
		return -ENODEV;

	mdev_state = devm_kzalloc(dev, sizeof(struct spimdev_mdev_state),
				  GFP_KERNEL);
	if (!mdev_state)
		return -ENOMEM;
	mdev_set_drvdata(mdev, mdev_state);
	mdev_state->spimdev = spimdev;
	dev->iommu_fwspec = mdev_parent_dev(mdev)->iommu_fwspec;
	pr_info("Create Mdev: %s\n", dev_name(dev));

	__module_get(spimdev->owner);

	return 0;
}

static int vfio_spimdev_mdev_remove(struct mdev_device *mdev)
{
	struct vfio_spimdev *spimdev = mdev_spimdev(mdev);
	struct device *dev = mdev_dev(mdev);

	dev->iommu_fwspec = NULL;
	mdev_set_drvdata(mdev, NULL);
	module_put(spimdev->owner);

	return 0;
}

/* Wake up the process who is waiting this queue */
void vfio_spimdev_wake_up(struct vfio_spimdev_queue *q)
{
	wake_up(&q->wait);
}
EXPORT_SYMBOL(vfio_spimdev_wake_up);

static int vfio_spimdev_q_file_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int vfio_spimdev_q_file_release(struct inode *inode, struct file *file)
{
	struct vfio_spimdev_queue *q =
		(struct vfio_spimdev_queue *)file->private_data;
	struct vfio_spimdev *spimdev = q->spimdev;
	int ret;

	ret = spimdev->ops->put_queue(q);
	if (ret) {
		dev_err(spimdev->dev, "drv put queue fail (%d)!\n", ret);
		return ret;
	}

	put_device(mdev_dev(q->mdev));

	return 0;
}

static long vfio_spimdev_q_file_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	struct vfio_spimdev_queue *q =
		(struct vfio_spimdev_queue *)file->private_data;
	struct vfio_spimdev *spimdev = q->spimdev;
	int ret;

	if (cmd == VFIO_SPIMDEV_CMD_WAIT) {

		u16 timeout = msecs_to_jiffies(arg & 0xffff);

		if (spimdev->ops->mask_notify)
			spimdev->ops->mask_notify(q,
						  _VFIO_SPIMDEV_EVENT_NOTIFY);

		ret = timeout ?
			wait_event_interruptible_timeout(q->wait,
				spimdev->ops->is_q_updated(q), timeout) :
			wait_event_interruptible(q->wait,
				spimdev->ops->is_q_updated(q));

		if (spimdev->ops->mask_notify)
			spimdev->ops->mask_notify(q,
						  _VFIO_SPIMDEV_EVENT_DISABLE);

		return ret;
	}

	if (spimdev->ops->ioctl)
		return spimdev->ops->ioctl(q, cmd, arg);

	dev_err(spimdev->dev,
		"%s, ioctl cmd (%d) is not supported!\n", __func__, cmd);

	return -EINVAL;
}

static int vfio_spimdev_q_file_mmap(struct file *file,
		struct vm_area_struct *vma)
{
	struct vfio_spimdev_queue *q =
		(struct vfio_spimdev_queue *)file->private_data;
	struct vfio_spimdev *spimdev = q->spimdev;

	if (spimdev->ops->mmap)
		return spimdev->ops->mmap(q, vma);

	dev_err(spimdev->dev, "\nno driver mmap!");

	return -EINVAL;
}


static const struct file_operations spimdev_q_file_ops = {
	.owner = THIS_MODULE,
	.open = vfio_spimdev_q_file_open,
	.unlocked_ioctl = vfio_spimdev_q_file_ioctl,
	.release = vfio_spimdev_q_file_release,
	.mmap = vfio_spimdev_q_file_mmap,
};

static long vfio_spimdev_mdev_get_queue(struct mdev_device *mdev,
		struct vfio_spimdev *spimdev, unsigned long arg)
{
	struct vfio_spimdev_queue *q;
	int ret;
	int fd;
	int pasid = arg;

	if (!spimdev->ops->get_queue)
		return -EINVAL;

#ifdef CONFIG_IOMMU_SVA
	if (_is_valid_pasid(pasid))
		return -EINVAL;
#endif

	ret = spimdev->ops->get_queue(spimdev, arg, &q);
	if (ret < 0) {
		dev_err(spimdev->dev, "get_queue failed\n");
		return -ENODEV;
	}

	fd = anon_inode_getfd("spimdev_q", &spimdev_q_file_ops,
			q, O_CLOEXEC | O_RDWR);
	if (fd < 0) {
		dev_err(spimdev->dev, "getfd fail %d\n", fd);
		ret = fd;
		goto err_with_queue;
	}

	q->fd = fd;
	q->spimdev = spimdev;
	q->mdev = mdev;
	q->container = arg;
	init_waitqueue_head(&q->wait);
	get_device(mdev_dev(mdev));


	return fd;

err_with_queue:
	spimdev->ops->put_queue(q);
	return ret;
}

static long vfio_spimdev_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			       unsigned long arg)
{
	struct spimdev_mdev_state *mdev_state;
	struct vfio_spimdev *spimdev;

	if (!mdev)
		return -ENODEV;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -ENODEV;

	spimdev = mdev_state->spimdev;
	if (!spimdev)
		return -ENODEV;

	if (cmd == VFIO_SPIMDEV_CMD_GET_Q)
		return vfio_spimdev_mdev_get_queue(mdev, spimdev, arg);

	dev_err(spimdev->dev,
		"%s, ioctl cmd (0x%x) is not supported!\n", __func__, cmd);
	return -EINVAL;
}

static void vfio_spimdev_release(struct device *dev) { }
static void vfio_spimdev_mdev_release(struct mdev_device *mdev) { }
static int vfio_spimdev_mdev_open(struct mdev_device *mdev) { return 0; }

/**
 *	vfio_spimdev_register - register a spimdev
 *	@spimdev: device structure
 */
int vfio_spimdev_register(struct vfio_spimdev *spimdev)
{
	static atomic_t id = ATOMIC_INIT(-1);
	int ret;
	const char *drv_name;

	if (!spimdev->dev)
		return -ENODEV;

	drv_name = dev_driver_string(spimdev->dev);
	if (strstr(drv_name, "-")) {
		pr_err("spimdev: parent driver name cannot include '-'!\n");
		return -EINVAL;
	}

	spimdev->dev_id = (int)atomic_inc_return(&id);
	spimdev->cls_dev.parent = spimdev->dev;
	spimdev->cls_dev.class = spimdev_class;
	spimdev->cls_dev.release = vfio_spimdev_release;
	dev_set_name(&spimdev->cls_dev, "%s", dev_name(spimdev->dev));
	ret = device_register(&spimdev->cls_dev);
	if (ret)
		return ret;

	spimdev->mdev_fops.owner		= spimdev->owner;
	spimdev->mdev_fops.dev_attr_groups	= vfio_spimdev_groups;
	assert(spimdev->mdev_fops.mdev_attr_groups);
	assert(spimdev->mdev_fops.supported_type_groups);
	spimdev->mdev_fops.create		= vfio_spimdev_mdev_create;
	spimdev->mdev_fops.remove		= vfio_spimdev_mdev_remove;
	spimdev->mdev_fops.ioctl		= vfio_spimdev_mdev_ioctl;
	spimdev->mdev_fops.open			= vfio_spimdev_mdev_open;
	spimdev->mdev_fops.release		= vfio_spimdev_mdev_release;

	ret = mdev_register_device(spimdev->dev, &spimdev->mdev_fops);
	if (ret)
		device_unregister(&spimdev->cls_dev);

	return ret;
}
EXPORT_SYMBOL(vfio_spimdev_register);

/**
 * vfio_spimdev_unregister - unregisters a spimdev
 * @spimdev: device to unregister
 *
 * Unregister a miscellaneous device that wat previously successully registered
 * with vfio_spimdev_register().
 */
void vfio_spimdev_unregister(struct vfio_spimdev *spimdev)
{
	mdev_unregister_device(spimdev->dev);
	device_unregister(&spimdev->cls_dev);
}
EXPORT_SYMBOL(vfio_spimdev_unregister);

static int __init vfio_spimdev_init(void)
{
	spimdev_class = class_create(THIS_MODULE, VFIO_SPIMDEV_CLASS_NAME);
	return PTR_ERR_OR_ZERO(spimdev_class);
}

static __exit void vfio_spimdev_exit(void)
{
	class_destroy(spimdev_class);
}

module_init(vfio_spimdev_init);
module_exit(vfio_spimdev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("VFIO Share Parent's IOMMU Mediated Device");
