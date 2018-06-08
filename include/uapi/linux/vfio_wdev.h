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

#ifndef _UAPIVFIO_WDEV_H
#define _UAPIVFIO_WDEV_H

#include <linux/types.h>


#define VFIO_WDEV_VER			1
#define VFIO_WDEV_CLASS_NAME		"warpdrive"

/* Attributions in mdev SYSFS DIR of mdev in vfio_wdev */
#define VFIO_WDEV_MDEV_ATTRS_GRP_NAME	"mdev_wdev_attrs"

/* Device ATTRs in parent dev SYSFS DIR */
#define VFIO_WDEV_PDEV_ATTRS_GRP_NAME	"wdev"

/* Parent device attributes */
#define WDPAN_PRIORITY		"priority"
#define WDPAN_NODE_ID		"node_id"
#define WDPAN_IOMMU_TYPE	"iommu_type"
#define WDPAN_DMA_FLAG		"dma_flag"

/* Maximum length of algorithm name string */
#define VFIO_WDEV_ALG_NAME_SIZE		64

enum vfio_wdev_dma_flags {
	VFIO_WDEV_DMA_INVALID = 0,

	/* While IOMMU or device cannot support PASID */
	VFIO_WDEV_DMA_SINGLE_PROC_MAP = 1,

	/* While IOMMU support PASID and device support PASID */
	VFIO_WDEV_DMA_MULTI_PROC_MAP = 2,

	/* While IOMMU support SVM and device support page fault */
	VFIO_WDEV_DMA_SVM = 4,

	/* While IOMMU support SVM but device cannot support page fault */
	VFIO_WDEV_DMA_SVM_NO_FAULT = 8,

	/* Physical address DMA mode */
	VFIO_WDEV_DMA_PHY = 16,
};

/* Notes: The throughput and delay of queue as it doing the corresponding
 * algorithm.The standard value is based on mainstream X86 CPU throughput,
 * which is '10'.The driver guys should know the value of his engine while
 * compared with mainstream X86 CPU core. Of cource, this real value will
 * change as X86 CPU is developing. So, the mainstream X86 CPU version is
 * based on the WD version releasing time.
 * (fixme: this text should be removed finally)
 */

/* The throughput requirement is a value from 1 to 100, default to 10
 * bigger is higher
 */
typedef __u8 vfio_wdev_throughput_t;

/* The latency requirement is a value from 1 to 100, default to 10
 * and the smaller value is, the delay is shorter.
 */
typedef __u8 vfio_wdev_latency_t;

/* Input data buffer can be a scatter-gather list */
#define VFIO_WDEV_CAPA_SGL		1

/* Share whole process space with WD device */
#define VFIO_WDEV_CAPA_SHARE_ALL		2


#define VFIO_WDEV_CMD_WAIT	_IOW('W', 1, unsigned long)
#define VFIO_WDEV_CMD_GET_Q	_IOW('W', 2, unsigned long)
#define VFIO_WDEV_CMD_PUT_Q	_IOW('W', 3, unsigned long)
#define VFIO_WDEV_CMD_SET_PASID	_IOW('W', 4, unsigned long)
#define VFIO_WDEV_CMD_CLR_PASID	_IOW('W', 5, unsigned long)
#endif
