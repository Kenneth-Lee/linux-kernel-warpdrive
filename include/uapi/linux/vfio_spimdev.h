// SPDX-License-Identifier: GPL-2.0+
/* This file is shared bewteen WD user and kernel space, which is
 * including attibutions of user and drivers caring for
 */

#ifndef _UAPIVFIO_SPIMDEV_H
#define _UAPIVFIO_SPIMDEV_H

#include <linux/types.h>

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

/* Input data buffer can be a scatter-gather list */
#define VFIO_SPIMDEV_CAPA_SGL		1

/* Share whole process space with WD device */
#define VFIO_SPIMDEV_CAPA_SHARE_ALL		2


#define VFIO_SPIMDEV_CMD_WAIT	_IOW('W', 1, unsigned long)
#define VFIO_SPIMDEV_CMD_GET_Q	_IOW('W', 2, unsigned long)
#endif
