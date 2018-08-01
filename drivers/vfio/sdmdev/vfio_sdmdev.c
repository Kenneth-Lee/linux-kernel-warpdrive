// SPDX-License-Identifier: GPL-2.0+
#include <linux/module.h>
#include <linux/vfio_sdmdev.h>

static struct class *sdmdev_class;

static int vfio_sdmdev_dev_exist(struct device *dev, void *data)
{
	return !strcmp(dev_name(dev), dev_name((struct device *)data));
}

#ifdef CONFIG_IOMMU_SVA
static bool vfio_sdmdev_is_valid_pasid(int pasid)
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

/* Check if the device is a mediated device belongs to vfio_sdmdev */
int vfio_sdmdev_is_sdmdev(struct device *dev)
{
	struct mdev_device *mdev;
	struct device *pdev;

	mdev = mdev_from_dev(dev);
	if (!mdev)
		return 0;

	pdev = mdev_parent_dev(mdev);
	if (!pdev)
		return 0;

	return class_for_each_device(sdmdev_class, NULL, pdev,
			vfio_sdmdev_dev_exist);
}
EXPORT_SYMBOL_GPL(vfio_sdmdev_is_sdmdev);

struct vfio_sdmdev *vfio_sdmdev_pdev_sdmdev(struct device *dev)
{
	struct device *class_dev;

	if (!dev)
		return ERR_PTR(-EINVAL);

	class_dev = class_find_device(sdmdev_class, NULL, dev,
		(int(*)(struct device *, const void *))vfio_sdmdev_dev_exist);
	if (!class_dev)
		return ERR_PTR(-ENODEV);

	return container_of(class_dev, struct vfio_sdmdev, cls_dev);
}
EXPORT_SYMBOL_GPL(vfio_sdmdev_pdev_sdmdev);

struct vfio_sdmdev *mdev_sdmdev(struct mdev_device *mdev)
{
	struct device *pdev = mdev_parent_dev(mdev);

	return vfio_sdmdev_pdev_sdmdev(pdev);
}
EXPORT_SYMBOL_GPL(mdev_sdmdev);

static ssize_t iommu_type_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct vfio_sdmdev *sdmdev = vfio_sdmdev_pdev_sdmdev(dev);

	if (!sdmdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", sdmdev->iommu_type);
}

static DEVICE_ATTR_RO(iommu_type);

static ssize_t dma_flag_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct vfio_sdmdev *sdmdev = vfio_sdmdev_pdev_sdmdev(dev);

	if (!sdmdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", sdmdev->dma_flag);
}

static DEVICE_ATTR_RO(dma_flag);

/* mdev->dev_attr_groups */
static struct attribute *vfio_sdmdev_attrs[] = {
	&dev_attr_iommu_type.attr,
	&dev_attr_dma_flag.attr,
	NULL,
};
static const struct attribute_group vfio_sdmdev_group = {
	.name  = VFIO_SDMDEV_PDEV_ATTRS_GRP_NAME,
	.attrs = vfio_sdmdev_attrs,
};
const struct attribute_group *vfio_sdmdev_groups[] = {
	&vfio_sdmdev_group,
	NULL,
};

/* default attributes for mdev->supported_type_groups, used by registerer*/
#define MDEV_TYPE_ATTR_RO_EXPORT(name) \
		MDEV_TYPE_ATTR_RO(name); \
		EXPORT_SYMBOL_GPL(mdev_type_attr_##name);

#define DEF_SIMPLE_SDMDEV_ATTR(_name, sdmdev_member, format) \
static ssize_t _name##_show(struct kobject *kobj, struct device *dev, \
			    char *buf) \
{ \
	struct vfio_sdmdev *sdmdev = vfio_sdmdev_pdev_sdmdev(dev); \
	if (!sdmdev) \
		return -ENODEV; \
	return sprintf(buf, format, sdmdev->sdmdev_member); \
} \
MDEV_TYPE_ATTR_RO_EXPORT(_name)

DEF_SIMPLE_SDMDEV_ATTR(flags, flags, "%d");
DEF_SIMPLE_SDMDEV_ATTR(name, name, "%s"); /* this should be algorithm name, */
		/* but you would not care if you have only one algorithm */
DEF_SIMPLE_SDMDEV_ATTR(device_api, api_ver, "%s");

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct vfio_sdmdev *sdmdev = vfio_sdmdev_pdev_sdmdev(dev);
	int nr_inst = 0;

	nr_inst = sdmdev->ops->get_available_instances ?
		sdmdev->ops->get_available_instances(sdmdev) : 0;
	return sprintf(buf, "%d", nr_inst);
}
MDEV_TYPE_ATTR_RO_EXPORT(available_instances);

static int vfio_sdmdev_mdev_create(struct kobject *kobj,
	struct mdev_device *mdev)
{
	struct device *pdev = mdev_parent_dev(mdev);
	struct vfio_sdmdev_queue *q;
	struct vfio_sdmdev *sdmdev = mdev_sdmdev(mdev);
	int ret;

	if (!sdmdev->ops->get_queue)
		return -ENODEV;

	ret = sdmdev->ops->get_queue(sdmdev, &q);
	if (ret)
		return ret;

	q->sdmdev = sdmdev;
	q->mdev = mdev;
	init_waitqueue_head(&q->wait);

	mdev_set_drvdata(mdev, q);
	get_device(pdev);

	return 0;
}

static int vfio_sdmdev_mdev_remove(struct mdev_device *mdev)
{
	struct vfio_sdmdev_queue *q =
		(struct vfio_sdmdev_queue *)mdev_get_drvdata(mdev);
	struct vfio_sdmdev *sdmdev = q->sdmdev;
	struct device *pdev = mdev_parent_dev(mdev);

	put_device(pdev);
	BUG_ON(!sdmdev->ops->put_queue);
	sdmdev->ops->put_queue(q);

	return 0;
}

/* Wake up the process who is waiting this queue */
void vfio_sdmdev_wake_up(struct vfio_sdmdev_queue *q)
{
	wake_up_all(&q->wait);
}
EXPORT_SYMBOL_GPL(vfio_sdmdev_wake_up);

static int vfio_sdmdev_mdev_mmap(struct mdev_device *mdev,
				 struct vm_area_struct *vma)
{
	struct vfio_sdmdev_queue *q =
		(struct vfio_sdmdev_queue *)mdev_get_drvdata(mdev);
	struct vfio_sdmdev *sdmdev = q->sdmdev;

	if (sdmdev->ops->mmap)
		return sdmdev->ops->mmap(q, vma);

	dev_err(sdmdev->dev, "no driver mmap!\n");
	return -EINVAL;
}

static inline int vfio_sdmdev_wait(struct vfio_sdmdev_queue *q,
		    		   unsigned long timeout)
{
	int ret;
	struct vfio_sdmdev *sdmdev = q->sdmdev;

	if (!sdmdev->ops->mask_notify)
		return -ENODEV;

	sdmdev->ops->mask_notify(q, VFIO_SDMDEV_EVENT_Q_UPDATE);

	ret = timeout ?  wait_event_interruptible_timeout(q->wait,
			sdmdev->ops->is_q_updated(q), timeout) :
		     wait_event_interruptible(q->wait,
			sdmdev->ops->is_q_updated(q));

	sdmdev->ops->mask_notify(q, 0);

	return ret;
}

static long vfio_sdmdev_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			       unsigned long arg)
{
	struct vfio_sdmdev_queue *q =
		(struct vfio_sdmdev_queue *)mdev_get_drvdata(mdev);
	struct vfio_sdmdev *sdmdev = q->sdmdev;

	switch (cmd) {
	case VFIO_SDMDEV_CMD_WAIT:
		return vfio_sdmdev_wait(q, arg);

#ifdef CONFIG_IOMMU_SVA
	case VFIO_SDMDEV_CMD_BIND_PASID:
		int ret;

		if (!vfio_sdmdev_is_valid_pasid(arg))
			return -EINVAL;

		mutex_lock(&q->mutex);
		q->pasid = arg;

		if (sdmdev->ops->start_queue)
			ret = sdmdev->ops->start_queue(q);

		mutex_unlock(&q->mutex);

		return ret;
#endif

	default:
		if (sdmdev->ops->ioctl)
			return sdmdev->ops->ioctl(q, cmd, arg);

		dev_err(sdmdev->dev, "ioctl cmd (%d) is not supported!\n", cmd);
		return -EINVAL;
	}
}

static void vfio_sdmdev_release(struct device *dev) { }

static void vfio_sdmdev_mdev_release(struct mdev_device *mdev)
{
	struct vfio_sdmdev_queue *q =
		(struct vfio_sdmdev_queue *)mdev_get_drvdata(mdev);
	struct vfio_sdmdev *sdmdev = q->sdmdev;

	if (sdmdev->ops->stop_queue)
		sdmdev->ops->stop_queue(q);
}

static int vfio_sdmdev_mdev_open(struct mdev_device *mdev)
{
#ifndef CONFIG_IOMMU_SVA
	struct vfio_sdmdev_queue *q =
		(struct vfio_sdmdev_queue *)mdev_get_drvdata(mdev);
	struct vfio_sdmdev *sdmdev = q->sdmdev;

	if (sdmdev->ops->start_queue)
		sdmdev->ops->start_queue(q);
#endif

	return 0;
}

/**
 *	vfio_sdmdev_register - register a sdmdev
 *	@sdmdev: device structure
 */
int vfio_sdmdev_register(struct vfio_sdmdev *sdmdev)
{
	int ret;

	if (!sdmdev->dev)
		return -ENODEV;

	atomic_set(&sdmdev->ref, 0);
	sdmdev->cls_dev.parent = sdmdev->dev;
	sdmdev->cls_dev.class = sdmdev_class;
	sdmdev->cls_dev.release = vfio_sdmdev_release;
	dev_set_name(&sdmdev->cls_dev, "%s", dev_name(sdmdev->dev));
	ret = device_register(&sdmdev->cls_dev);
	if (ret)
		goto err;

	sdmdev->mdev_fops.owner			= THIS_MODULE;
	sdmdev->mdev_fops.dev_attr_groups	= vfio_sdmdev_groups;
	WARN_ON(!sdmdev->mdev_fops.supported_type_groups);
	sdmdev->mdev_fops.create		= vfio_sdmdev_mdev_create;
	sdmdev->mdev_fops.remove		= vfio_sdmdev_mdev_remove;
	sdmdev->mdev_fops.ioctl			= vfio_sdmdev_mdev_ioctl;
	sdmdev->mdev_fops.open			= vfio_sdmdev_mdev_open;
	sdmdev->mdev_fops.release		= vfio_sdmdev_mdev_release;
	sdmdev->mdev_fops.mmap			= vfio_sdmdev_mdev_mmap,

	ret = mdev_register_device(sdmdev->dev, &sdmdev->mdev_fops);
	if (ret)
		goto err_with_cls_dev;

	return 0;

err_with_cls_dev:
	device_unregister(&sdmdev->cls_dev);
err:
	return ret;
}
EXPORT_SYMBOL_GPL(vfio_sdmdev_register);

/**
 * vfio_sdmdev_unregister - unregisters a sdmdev
 * @sdmdev: device to unregister
 *
 * Unregister a sdmdev that wat previously successully registered with
 * vfio_sdmdev_register().
 */
void vfio_sdmdev_unregister(struct vfio_sdmdev *sdmdev)
{
	mdev_unregister_device(sdmdev->dev);
	device_unregister(&sdmdev->cls_dev);
}
EXPORT_SYMBOL_GPL(vfio_sdmdev_unregister);

static int __init vfio_sdmdev_init(void)
{
	sdmdev_class = class_create(THIS_MODULE, VFIO_SDMDEV_CLASS_NAME);
	return PTR_ERR_OR_ZERO(sdmdev_class);
}

static __exit void vfio_sdmdev_exit(void)
{
	class_destroy(sdmdev_class);
}

module_init(vfio_sdmdev_init);
module_exit(vfio_sdmdev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("VFIO Share Domain Mediated Device");
