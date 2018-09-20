// SPDX-License-Identifier: GPL-2.0
/*
 * Manage PASIDs and bind process address spaces to devices.
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/**
 * DOC: io_mm model
 *
 * The io_mm keeps track of process address spaces shared between CPU and IOMMU.
 * The following example illustrates the relation between structures
 * iommu_domain, io_mm and iommu_bond. An iommu_bond is a link between io_mm and
 * device. A device can have multiple io_mm and an io_mm may be bound to
 * multiple devices.
 *              ___________________________
 *             |  IOMMU domain A           |
 *             |  ________________         |
 *             | |  IOMMU group   |        +------- io_pgtables
 *             | |                |        |
 *             | |   dev 00:00.0 ----+------- bond --- io_mm X
 *             | |________________|   \    |
 *             |                       '----- bond ---.
 *             |___________________________|           \
 *              ___________________________             \
 *             |  IOMMU domain B           |           io_mm Y
 *             |  ________________         |           / /
 *             | |  IOMMU group   |        |          / /
 *             | |                |        |         / /
 *             | |   dev 00:01.0 ------------ bond -' /
 *             | |   dev 00:01.1 ------------ bond --'
 *             | |________________|        |
 *             |                           +------- io_pgtables
 *             |___________________________|
 *
 * In this example, device 00:00.0 is in domain A, devices 00:01.* are in domain
 * B. All devices within the same domain access the same address spaces. Device
 * 00:00.0 accesses address spaces X and Y, each corresponding to an mm_struct.
 * Devices 00:01.* only access address space Y. In addition each
 * IOMMU_DOMAIN_DMA domain has a private address space, io_pgtable, that is
 * managed with iommu_map()/iommu_unmap(), and isn't shared with the CPU MMU.
 *
 * To obtain the above configuration, users would for instance issue the
 * following calls:
 *
 *     iommu_sva_bind_device(dev 00:00.0, mm X, ...) -> PASID 1
 *     iommu_sva_bind_device(dev 00:00.0, mm Y, ...) -> PASID 2
 *     iommu_sva_bind_device(dev 00:01.0, mm Y, ...) -> PASID 2
 *     iommu_sva_bind_device(dev 00:01.1, mm Y, ...) -> PASID 2
 *
 * A single Process Address Space ID (PASID) is allocated for each mm. In the
 * example, devices use PASID 1 to read/write into address space X and PASID 2
 * to read/write into address space Y.
 *
 * Hardware tables describing this configuration in the IOMMU would typically
 * look like this:
 *
 *                                PASID tables
 *                                 of domain A
 *                              .->+--------+
 *                             / 0 |        |-------> io_pgtable
 *                            /    +--------+
 *            Device tables  /   1 |        |-------> pgd X
 *              +--------+  /      +--------+
 *      00:00.0 |      A |-'     2 |        |--.
 *              +--------+         +--------+   \
 *              :        :       3 |        |    \
 *              +--------+         +--------+     --> pgd Y
 *      00:01.0 |      B |--.                    /
 *              +--------+   \                  |
 *      00:01.1 |      B |----+   PASID tables  |
 *              +--------+     \   of domain B  |
 *                              '->+--------+   |
 *                               0 |        |-- | --> io_pgtable
 *                                 +--------+   |
 *                               1 |        |   |
 *                                 +--------+   |
 *                               2 |        |---'
 *                                 +--------+
 *                               3 |        |
 *                                 +--------+
 *
 * With this model, a single call binds all devices in a given domain to an
 * address space. Other devices in the domain will get the same bond implicitly.
 * However, users must issue one bind() for each device, because IOMMUs may
 * implement SVA differently. Furthermore, mandating one bind() per device
 * allows the driver to perform sanity-checks on device capabilities.
 *
 * In some IOMMUs, one entry of the PASID table (typically the first one) can
 * hold non-PASID translations. In this case PASID 0 is reserved and the first
 * entry points to the io_pgtable pointer. In other IOMMUs the io_pgtable
 * pointer is held in the device table and PASID 0 is available to the
 * allocator.
 */

struct iommu_bond {
	struct io_mm		*io_mm;
	struct device		*dev;
	struct iommu_domain	*domain;

	struct list_head	mm_head;
	struct list_head	dev_head;
	struct list_head	domain_head;

	void			*drvdata;
};

/*
 * Because we're using an IDR, PASIDs are limited to 31 bits (the sign bit is
 * used for returning errors). In practice implementations will use at most 20
 * bits, which is the PCI limit.
 */
static DEFINE_IDR(iommu_pasid_idr);

/*
 * For the moment this is an all-purpose lock. It serializes
 * access/modifications to bonds, access/modifications to the PASID IDR, and
 * changes to io_mm refcount as well.
 */
static DEFINE_SPINLOCK(iommu_sva_lock);

static struct io_mm *
io_mm_alloc(struct iommu_domain *domain, struct device *dev,
	    struct mm_struct *mm, unsigned long flags)
{
	int ret;
	int pasid;
	struct io_mm *io_mm;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	if (!domain->ops->mm_alloc || !domain->ops->mm_free)
		return ERR_PTR(-ENODEV);

	io_mm = domain->ops->mm_alloc(domain, mm, flags);
	if (IS_ERR(io_mm))
		return io_mm;
	if (!io_mm)
		return ERR_PTR(-ENOMEM);

	/*
	 * The mm must not be freed until after the driver frees the io_mm
	 * (which may involve unpinning the CPU ASID for instance, requiring a
	 * valid mm struct.)
	 */
	mmgrab(mm);

	io_mm->flags		= flags;
	io_mm->mm		= mm;
	io_mm->release		= domain->ops->mm_free;
	INIT_LIST_HEAD(&io_mm->devices);
	/* Leave kref as zero until the io_mm is fully initialized */

	idr_preload(GFP_KERNEL);
	spin_lock(&iommu_sva_lock);
	pasid = idr_alloc(&iommu_pasid_idr, io_mm, param->min_pasid,
			  param->max_pasid + 1, GFP_ATOMIC);
	io_mm->pasid = pasid;
	spin_unlock(&iommu_sva_lock);
	idr_preload_end();

	if (pasid < 0) {
		ret = pasid;
		goto err_free_mm;
	}

	/* TODO: keep track of mm. For the moment, abort. */
	ret = -ENOSYS;
	spin_lock(&iommu_sva_lock);
	idr_remove(&iommu_pasid_idr, io_mm->pasid);
	spin_unlock(&iommu_sva_lock);

err_free_mm:
	io_mm->release(io_mm);
	mmdrop(mm);

	return ERR_PTR(ret);
}

static void io_mm_free(struct io_mm *io_mm)
{
	struct mm_struct *mm = io_mm->mm;

	io_mm->release(io_mm);
	mmdrop(mm);
}

static void io_mm_release(struct kref *kref)
{
	struct io_mm *io_mm;

	io_mm = container_of(kref, struct io_mm, kref);
	WARN_ON(!list_empty(&io_mm->devices));

	/* The PASID can now be reallocated for another mm... */
	idr_remove(&iommu_pasid_idr, io_mm->pasid);
	/* ... but this mm is freed after a grace period (TODO) */
	io_mm_free(io_mm);
}

/*
 * Returns non-zero if a reference to the io_mm was successfully taken.
 * Returns zero if the io_mm is being freed and should not be used.
 */
static int io_mm_get_locked(struct io_mm *io_mm)
{
	if (io_mm)
		return kref_get_unless_zero(&io_mm->kref);

	return 0;
}

static void io_mm_put_locked(struct io_mm *io_mm)
{
	kref_put(&io_mm->kref, io_mm_release);
}

static void io_mm_put(struct io_mm *io_mm)
{
	spin_lock(&iommu_sva_lock);
	io_mm_put_locked(io_mm);
	spin_unlock(&iommu_sva_lock);
}

static int io_mm_attach(struct iommu_domain *domain, struct device *dev,
			struct io_mm *io_mm, void *drvdata)
{
	int ret;
	bool attach_domain = true;
	int pasid = io_mm->pasid;
	struct iommu_bond *bond, *tmp;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	if (!domain->ops->mm_attach || !domain->ops->mm_detach)
		return -ENODEV;

	if (pasid > param->max_pasid || pasid < param->min_pasid)
		return -ERANGE;

	bond = kzalloc(sizeof(*bond), GFP_KERNEL);
	if (!bond)
		return -ENOMEM;

	bond->domain		= domain;
	bond->io_mm		= io_mm;
	bond->dev		= dev;
	bond->drvdata		= drvdata;

	spin_lock(&iommu_sva_lock);
	/*
	 * Check if this io_mm is already bound to the domain. In which case the
	 * IOMMU driver doesn't have to install the PASID table entry.
	 */
	list_for_each_entry(tmp, &domain->mm_list, domain_head) {
		if (tmp->io_mm == io_mm) {
			attach_domain = false;
			break;
		}
	}

	ret = domain->ops->mm_attach(domain, dev, io_mm, attach_domain);
	if (ret) {
		kfree(bond);
		goto out_unlock;
	}

	list_add(&bond->mm_head, &io_mm->devices);
	list_add(&bond->domain_head, &domain->mm_list);
	list_add(&bond->dev_head, &param->mm_list);

out_unlock:
	spin_unlock(&iommu_sva_lock);
	return ret;
}

static void io_mm_detach_locked(struct iommu_bond *bond)
{
	struct iommu_bond *tmp;
	bool detach_domain = true;
	struct iommu_domain *domain = bond->domain;

	list_for_each_entry(tmp, &domain->mm_list, domain_head) {
		if (tmp->io_mm == bond->io_mm && tmp->dev != bond->dev) {
			detach_domain = false;
			break;
		}
	}

	list_del(&bond->mm_head);
	list_del(&bond->domain_head);
	list_del(&bond->dev_head);

	domain->ops->mm_detach(domain, bond->dev, bond->io_mm, detach_domain);

	io_mm_put_locked(bond->io_mm);
	kfree(bond);
}

int __iommu_sva_bind_device(struct device *dev, struct mm_struct *mm, int *pasid,
			    unsigned long flags, void *drvdata)
{
	int i;
	int ret = 0;
	struct iommu_bond *bond;
	struct io_mm *io_mm = NULL;
	struct iommu_domain *domain;
	struct iommu_sva_param *param;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return -EINVAL;

	mutex_lock(&dev->iommu_param->sva_lock);
	param = dev->iommu_param->sva_param;
	if (!param || (flags & ~param->features)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* If an io_mm already exists, use it */
	spin_lock(&iommu_sva_lock);
	idr_for_each_entry(&iommu_pasid_idr, io_mm, i) {
		if (io_mm->mm == mm && io_mm_get_locked(io_mm)) {
			/* ... Unless it's already bound to this device */
			list_for_each_entry(bond, &io_mm->devices, mm_head) {
				if (bond->dev == dev) {
					ret = -EEXIST;
					io_mm_put_locked(io_mm);
					break;
				}
			}
			break;
		}
	}
	spin_unlock(&iommu_sva_lock);
	if (ret)
		goto out_unlock;

	/* Require identical features within an io_mm for now */
	if (io_mm && (flags != io_mm->flags)) {
		io_mm_put(io_mm);
		ret = -EDOM;
		goto out_unlock;
	}

	if (!io_mm) {
		io_mm = io_mm_alloc(domain, dev, mm, flags);
		if (IS_ERR(io_mm)) {
			ret = PTR_ERR(io_mm);
			goto out_unlock;
		}
	}

	ret = io_mm_attach(domain, dev, io_mm, drvdata);
	if (ret)
		io_mm_put(io_mm);
	else
		*pasid = io_mm->pasid;

out_unlock:
	mutex_unlock(&dev->iommu_param->sva_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(__iommu_sva_bind_device);

int __iommu_sva_unbind_device(struct device *dev, int pasid)
{
	int ret = -ESRCH;
	struct iommu_domain *domain;
	struct iommu_bond *bond = NULL;
	struct iommu_sva_param *param;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return -EINVAL;

	mutex_lock(&dev->iommu_param->sva_lock);
	param = dev->iommu_param->sva_param;
	if (!param) {
		ret = -EINVAL;
		goto out_unlock;
	}

	spin_lock(&iommu_sva_lock);
	list_for_each_entry(bond, &param->mm_list, dev_head) {
		if (bond->io_mm->pasid == pasid) {
			io_mm_detach_locked(bond);
			ret = 0;
			break;
		}
	}
	spin_unlock(&iommu_sva_lock);

out_unlock:
	mutex_unlock(&dev->iommu_param->sva_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(__iommu_sva_unbind_device);

static void __iommu_sva_unbind_device_all(struct device *dev)
{
	struct iommu_sva_param *param = dev->iommu_param->sva_param;
	struct iommu_bond *bond, *next;

	if (!param)
		return;

	spin_lock(&iommu_sva_lock);
	list_for_each_entry_safe(bond, next, &param->mm_list, dev_head)
		io_mm_detach_locked(bond);
	spin_unlock(&iommu_sva_lock);
}

/**
 * iommu_sva_unbind_device_all() - Detach all address spaces from this device
 * @dev: the device
 *
 * When detaching @dev from a domain, IOMMU drivers should use this helper.
 */
void iommu_sva_unbind_device_all(struct device *dev)
{
	mutex_lock(&dev->iommu_param->sva_lock);
	__iommu_sva_unbind_device_all(dev);
	mutex_unlock(&dev->iommu_param->sva_lock);
}
EXPORT_SYMBOL_GPL(iommu_sva_unbind_device_all);

/**
 * iommu_sva_init_device() - Initialize Shared Virtual Addressing for a device
 * @dev: the device
 * @features: bitmask of features that need to be initialized
 * @min_pasid: min PASID value supported by the device
 * @max_pasid: max PASID value supported by the device
 *
 * Users of the bind()/unbind() API must call this function to initialize all
 * features required for SVA.
 *
 * The device must support multiple address spaces (e.g. PCI PASID). By default
 * the PASID allocated during bind() is limited by the IOMMU capacity, and by
 * the device PASID width defined in the PCI capability or in the firmware
 * description. Setting @max_pasid to a non-zero value smaller than this limit
 * overrides it. Similarly, @min_pasid overrides the lower PASID limit supported
 * by the IOMMU.
 *
 * The device should not be performing any DMA while this function is running,
 * otherwise the behavior is undefined.
 *
 * Return 0 if initialization succeeded, or an error.
 */
int iommu_sva_init_device(struct device *dev, unsigned long features,
		       unsigned int min_pasid, unsigned int max_pasid)
{
	int ret;
	struct iommu_sva_param *param;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (!domain || !domain->ops->sva_init_device)
		return -ENODEV;

	if (features)
		return -EINVAL;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	param->features		= features;
	param->min_pasid	= min_pasid;
	param->max_pasid	= max_pasid;
	INIT_LIST_HEAD(&param->mm_list);

	mutex_lock(&dev->iommu_param->sva_lock);
	if (dev->iommu_param->sva_param) {
		ret = -EEXIST;
		goto err_unlock;
	}

	/*
	 * IOMMU driver updates the limits depending on the IOMMU and device
	 * capabilities.
	 */
	ret = domain->ops->sva_init_device(dev, param);
	if (ret)
		goto err_unlock;

	dev->iommu_param->sva_param = param;
	mutex_unlock(&dev->iommu_param->sva_lock);
	return 0;

err_unlock:
	mutex_unlock(&dev->iommu_param->sva_lock);
	kfree(param);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_init_device);

/**
 * iommu_sva_shutdown_device() - Shutdown Shared Virtual Addressing for a device
 * @dev: the device
 *
 * Disable SVA. Device driver should ensure that the device isn't performing any
 * DMA while this function is running.
 */
void iommu_sva_shutdown_device(struct device *dev)
{
	struct iommu_sva_param *param;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (!domain)
		return;

	mutex_lock(&dev->iommu_param->sva_lock);
	param = dev->iommu_param->sva_param;
	if (!param)
		goto out_unlock;

	__iommu_sva_unbind_device_all(dev);

	if (domain->ops->sva_shutdown_device)
		domain->ops->sva_shutdown_device(dev);

	kfree(param);
	dev->iommu_param->sva_param = NULL;
out_unlock:
	mutex_unlock(&dev->iommu_param->sva_lock);
}
EXPORT_SYMBOL_GPL(iommu_sva_shutdown_device);
