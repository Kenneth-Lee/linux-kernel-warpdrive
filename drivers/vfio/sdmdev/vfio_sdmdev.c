// SPDX-License-Identifier: GPL-2.0+
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vfio_sdmdev.h>
#include <linux/pagemap.h>

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

#ifdef CONFIG_DMA_SHARED_BUFFER
static struct sg_table *vfio_sdmdev_dmabuf_op_map_dma_buf(
			struct dma_buf_attachment *attach,
			enum dma_data_direction dir)
{
	/* todo: map to device by calling back the queue provider */
	return NULL;
}

static void vfio_sdmdev_dmabuf_op_unmap_dma_buf(
			struct dma_buf_attachment *attach,
			struct sg_table *table,
			enum dma_data_direction dir)
{
	/* todo */
}

static inline struct vfio_sdmdev_dma_buf_ctx *vfio_sdmdev_create_dma_buf_ctx(
		size_t size)
{
	struct vfio_sdmdev_dma_buf_ctx *ctx;
	int pagenum = DIV_ROUND_UP(size, PAGE_SIZE);

	ctx = kzalloc(sizeof(*ctx)+sizeof(struct page *)*pagenum, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->pagenum = pagenum;
	mutex_init(&ctx->lock);

	return ctx;
}

static inline void vfio_sdmdev_release_dma_buf_ctx(
		struct vfio_sdmdev_dma_buf_ctx *ctx)
{
	kfree(ctx);
}

static void vfio_sdmdev_dmabuf_op_release(struct dma_buf *dmabuf)
{
	struct vfio_sdmdev_dma_buf_ctx *ctx = dmabuf->priv;
	int i;

	mutex_lock(&ctx->lock);

	for (i=0; i < ctx->pagenum; i++) {
		if (ctx->pages[i]) {
			put_page(ctx->pages[i]);
		}
	}

	mutex_unlock(&ctx->lock);

	vfio_sdmdev_release_dma_buf_ctx(ctx);
}

static void *vfio_sdmdev_dmabuf_op_map(struct dma_buf *dmabuf,
				       unsigned long pgnum)
{
	struct vfio_sdmdev_dma_buf_ctx *ctx = dmabuf->priv;
	int i, j;
	void * vaddr;

	mutex_lock(&ctx->lock);

	for (i=0; i < pgnum; i++) {
		if (!ctx->pages[i]) {
			ctx->pages[i] = alloc_page(GFP_USER);
			if (!ctx->pages[i]) {
				for (j=i-1; j>=0; j--)
					put_page(ctx->pages[j]);
				mutex_unlock(&ctx->lock);
				return ERR_PTR(-ENOMEM);
			}
		}
		get_page(ctx->pages[i]);
	}

	vaddr = vmap(ctx->pages, pgnum, VM_MAP, PAGE_KERNEL);

	mutex_unlock(&ctx->lock);

	return vaddr;
}

static void vfio_sdmdev_dmabuf_op_unmap(struct dma_buf *dmabuf,
					unsigned long page_num, void *vaddr)
{
	struct vfio_sdmdev_dma_buf_ctx *ctx = dmabuf->priv;
	int i;

	vunmap(vaddr);

	mutex_lock(&ctx->lock);
	for (i=0; i < page_num; i++) {
		if (ctx->pages[i]) {
			put_page(ctx->pages[i]);
		}else
			WARN(1, "kerne umap un-allocated page\n");
	}

	mutex_unlock(&ctx->lock);
}

static vm_fault_t vfio_sdmdev_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct dma_buf *dmabuf = vma->vm_private_data;
	struct vfio_sdmdev_dma_buf_ctx *ctx = dmabuf->priv;

	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

	if (page_offset >= ctx->pagenum)
		return VM_FAULT_SIGBUS;

	mutex_lock(&ctx->lock);
	if (!ctx->pages[page_offset]) {
		ctx->pages[page_offset] = alloc_page(GFP_USER);
	}

	vmf->page = ctx->pages[page_offset];


	if (!vmf->page) {
		mutex_unlock(&ctx->lock);
		return VM_FAULT_SIGBUS;
	}

	get_page(vmf->page);

	mutex_unlock(&ctx->lock);
	return 0;
}

static const struct vm_operations_struct vfio_sdmdev_vm_ops = {
	.fault = vfio_sdmdev_vm_fault,
};

/* map this buffer to user space */
static int vfio_sdmdev_dmabuf_op_mmap(struct dma_buf *dmabuf,
				      struct vm_area_struct *vma)
{
	if (vma->vm_pgoff >= dmabuf->size >> PAGE_SHIFT)
		return -EINVAL;
	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if (vma->vm_end - vma->vm_start > dmabuf->size)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;

	vma->vm_ops = &vfio_sdmdev_vm_ops;
	vma->vm_private_data = dmabuf;
	return 0;
}

static const struct dma_buf_ops vfio_sdmdev_dma_buf_ops = {
	.map_dma_buf = vfio_sdmdev_dmabuf_op_map_dma_buf,
	.unmap_dma_buf = vfio_sdmdev_dmabuf_op_unmap_dma_buf,
	.release = vfio_sdmdev_dmabuf_op_release,
	.map = vfio_sdmdev_dmabuf_op_map,
	.unmap = vfio_sdmdev_dmabuf_op_unmap,
	.mmap = vfio_sdmdev_dmabuf_op_mmap,
};

static inline int vfio_sdmdev_get_dma_buf(struct vfio_sdmdev_queue *q,
					  void __user *arg)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct vfio_sdmdev_get_dma_buf_arg db_arg;
	struct vfio_sdmdev_dma_buf_ctx *ctx;
	int ret;

	mutex_lock(&q->mutex);
	if (q->dma_buf) {
		ret = -EBUSY;
		goto err_with_lock;
	}

	if (copy_from_user(&db_arg, arg, sizeof(db_arg))) {
		ret = -EFAULT;
		goto err_with_lock;
	}


	ctx = vfio_sdmdev_create_dma_buf_ctx(db_arg.size);
	if (!ctx) {
		ret = PTR_ERR(ctx);
		goto err_with_lock;
	}

	exp_info.ops = &vfio_sdmdev_dma_buf_ops;
	exp_info.size = db_arg.size;
	exp_info.flags = O_RDWR;
	exp_info.priv = ctx;

	q->dma_buf = dma_buf_export(&exp_info);
	if (!q->dma_buf) {
		ret = PTR_ERR(q->dma_buf);
		goto err_with_ctx;
	}

	ret = dma_buf_fd(q->dma_buf, 0);
	if (ret < 0)
		goto err_with_dma_buf;

	mutex_unlock(&q->mutex);
	return ret;

err_with_dma_buf:
	dma_buf_put(q->dma_buf);
	q->dma_buf = NULL;
err_with_ctx:
	vfio_sdmdev_release_dma_buf_ctx(ctx);
err_with_lock:
	mutex_unlock(&q->mutex);
	return ret;
}
#endif

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

#ifdef CONFIG_DMA_SHARED_BUFFER
	case VFIO_SDMDEV_CMD_GET_BUF:
		return vfio_sdmdev_get_dma_buf(q, (void __user *)arg);
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

	if (q->dma_buf) {
		dev_info(mdev_dev(q->mdev), "clear old dma_buf %lx\n",
			 (unsigned long)q->dma_buf);
		q->dma_buf = NULL;

	}

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
	/* clear the shm for a new process */
	if (q->dma_buf) {
		dev_info(mdev_dev(q->mdev), "clear old dma_buf %lx\n",
			 (unsigned long)q->dma_buf);
		q->dma_buf = NULL;

	}

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
