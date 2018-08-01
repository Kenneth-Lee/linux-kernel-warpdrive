/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _UAPIVFIO_SDMDEV_H
#define _UAPIVFIO_SDMDEV_H

#include <linux/ioctl.h>

#define VFIO_SDMDEV_CLASS_NAME		"sdmdev"

/* Device ATTRs in parent dev SYSFS DIR */
#define VFIO_SDMDEV_PDEV_ATTRS_GRP_NAME	"params"

/* Parent device attributes */
#define SDMDEV_IOMMU_TYPE	"iommu_type"
#define SDMDEV_DMA_FLAG		"dma_flag"

/* Maximum length of algorithm name string */
#define VFIO_SDMDEV_ALG_NAME_SIZE		64

/* the bits used in SDMDEV_DMA_FLAG attributes */
#define VFIO_SDMDEV_DMA_INVALID			0
#define	VFIO_SDMDEV_DMA_SINGLE_PROC_MAP		1
#define	VFIO_SDMDEV_DMA_MULTI_PROC_MAP		2
#define	VFIO_SDMDEV_DMA_SVM			4
#define	VFIO_SDMDEV_DMA_SVM_NO_FAULT		8
#define	VFIO_SDMDEV_DMA_PHY			16

#define VFIO_SDMDEV_CMD_WAIT		_IO('W', 1)
#define VFIO_SDMDEV_CMD_BIND_PASID	_IO('W', 2)
#endif
