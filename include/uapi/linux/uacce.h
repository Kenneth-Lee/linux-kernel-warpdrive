/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _UAPIUUACCE_H
#define _UAPIUUACCE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define UACCE_CLASS_NAME		"uacce"

#define UACCE_CMD_SHARE_SVAS	_IO('W', 0)

/**
 * UACCE Device Attributes:
 *
 * NOIOMMU: the device has no IOMMU support
 * 	can do ssva, but no map to the dev
 * PASID: the device has IOMMU which support PASID setting
 * 	can do ssva, mapped to dev per process
 * FAULT_FROM_DEV: the device has IOMMU which can do page fault request
 * 	no need for ssva, should be used with PASID
 * SVA: full function device
 * SHARE_DOMAIN: no PASID, can do ssva only for one process and the kernel
 */
#define UACCE_DEV_NOIOMMU		(1<<0)
#define UACCE_DEV_PASID			(1<<1)
#define UACCE_DEV_FAULT_FROM_DEV	(1<<2)

#define UACCE_DEV_SVA		(UACCE_DEV_PASID | UACCE_DEV_FAULT_FROM_DEV)
#define UACCE_DEV_SHARE_DOMAIN	(0)

#endif
