/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


/* This file is shared bewteen WD user and kernel space, which is
 * including attibutions of user and drivers caring for
 */

#ifndef _UAPIVFIO_SPIMDEV_H
#define _UAPIVFIO_SPIMDEV_H

#include <linux/types.h>


#define VFIO_SPIMDEV_VER			1
#define VFIO_SPIMDEV_CLASS_NAME		"spimdev"

/* Attributions in mdev SYSFS DIR of mdev in vfio_spimdev */
#define VFIO_SPIMDEV_MDEV_ATTRS_GRP_NAME	"mdev_spimdev_attrs"

/* Device ATTRs in parent dev SYSFS DIR */
#define VFIO_SPIMDEV_PDEV_ATTRS_GRP_NAME	"params"

/* Parent device attributes */
#define SPIMDEV_IOMMU_TYPE	"iommu_type"
#define SPIMDEV_DMA_FLAG	"dma_flag"

/* Maximum length of algorithm name string */
#define VFIO_SPIMDEV_ALG_NAME_SIZE		64

enum vfio_spimdev_dma_flags {
	VFIO_SPIMDEV_DMA_INVALID = 0,

	/* While IOMMU or device cannot support PASID */
	VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP = 1,

	/* While IOMMU support PASID and device support PASID */
	VFIO_SPIMDEV_DMA_MULTI_PROC_MAP = 2,

	/* While IOMMU support SVM and device support page fault */
	VFIO_SPIMDEV_DMA_SVM = 4,

	/* While IOMMU support SVM but device cannot support page fault */
	VFIO_SPIMDEV_DMA_SVM_NO_FAULT = 8,

	/* Physical address DMA mode */
	VFIO_SPIMDEV_DMA_PHY = 16,
};

/* Input data buffer can be a scatter-gather list */
#define VFIO_SPIMDEV_CAPA_SGL		1

/* Share whole process space with WD device */
#define VFIO_SPIMDEV_CAPA_SHARE_ALL		2


#define VFIO_SPIMDEV_CMD_WAIT	_IOW('W', 1, unsigned long)
#define VFIO_SPIMDEV_CMD_GET_Q	_IOW('W', 2, unsigned long)
#define VFIO_SPIMDEV_CMD_SET_PASID	_IOW('W', 3, unsigned long)
#define VFIO_SPIMDEV_CMD_CLR_PASID	_IOW('W', 4, unsigned long)
#endif
