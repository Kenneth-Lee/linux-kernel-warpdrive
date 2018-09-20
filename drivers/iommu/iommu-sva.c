// SPDX-License-Identifier: GPL-2.0
/*
 * Manage PASIDs and bind process address spaces to devices.
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/iommu.h>
#include <linux/slab.h>

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

	if (domain->ops->sva_shutdown_device)
		domain->ops->sva_shutdown_device(dev);

	kfree(param);
	dev->iommu_param->sva_param = NULL;
out_unlock:
	mutex_unlock(&dev->iommu_param->sva_lock);
}
EXPORT_SYMBOL_GPL(iommu_sva_shutdown_device);
