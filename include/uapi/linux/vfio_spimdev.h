/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _UAPIVFIO_SPIMDEV_H
#define _UAPIVFIO_SPIMDEV_H

#include <linux/ioctl.h>

#define VFIO_SPIMDEV_CLASS_NAME		"spimdev"

/* Device ATTRs in parent dev SYSFS DIR */
#define VFIO_SPIMDEV_PDEV_ATTRS_GRP_NAME	"params"

/* Parent device attributes */
#define SPIMDEV_IOMMU_TYPE	"iommu_type"
#define SPIMDEV_DMA_FLAG	"dma_flag"

/* Maximum length of algorithm name string */
#define VFIO_SPIMDEV_ALG_NAME_SIZE		64

/* the bits used in SPIMDEV_DMA_FLAG attributes */
#define VFIO_SPIMDEV_DMA_INVALID		0
#define	VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP	1
#define	VFIO_SPIMDEV_DMA_MULTI_PROC_MAP		2
#define	VFIO_SPIMDEV_DMA_SVM			4
#define	VFIO_SPIMDEV_DMA_SVM_NO_FAULT		8
#define	VFIO_SPIMDEV_DMA_PHY			16

#define VFIO_SPIMDEV_CMD_GET_Q	_IO('W', 1)
#endif
