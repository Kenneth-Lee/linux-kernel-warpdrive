/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * IOMMU user API definitions
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _UAPI_IOMMU_H
#define _UAPI_IOMMU_H

#include <linux/types.h>

/**
 * PASID table data used to bind guest PASID table to the host IOMMU. This will
 * enable guest managed first level page tables.
 * @version: for future extensions and identification of the data format
 * @bytes: size of this structure
 * @base_ptr:	PASID table pointer
 * @pasid_bits:	number of bits supported in the guest PASID table, must be less
 *		or equal than the host supported PASID size.
 */
struct pasid_table_config {
	__u32 version;
#define PASID_TABLE_CFG_VERSION_1 1
	__u32 bytes;
	__u64 base_ptr;
	__u8 pasid_bits;
};

/**
 * enum iommu_inv_granularity - Generic invalidation granularity
 * @IOMMU_INV_GRANU_DOMAIN_ALL_PASID:	TLB entries or PASID caches of all
 *					PASIDs associated with a domain ID
 * @IOMMU_INV_GRANU_PASID_SEL:		TLB entries or PASID cache associated
 *					with a PASID and a domain
 * @IOMMU_INV_GRANU_PAGE_PASID:		TLB entries of selected page range
 *					within a PASID
 *
 * When an invalidation request is passed down to IOMMU to flush translation
 * caches, it may carry different granularity levels, which can be specific
 * to certain types of translation caches.
 * This enum is a collection of granularities for all types of translation
 * caches. The idea is to make it easy for IOMMU model specific driver to
 * convert from generic to model specific value. Each IOMMU driver
 * can enforce check based on its own conversion table. The conversion is
 * based on 2D look-up with inputs as follows:
 * - translation cache types
 * - granularity
 *
 *             type |   DTLB    |    TLB    |   PASID   |
 *  granule         |           |           |   cache   |
 * -----------------+-----------+-----------+-----------+
 *  DN_ALL_PASID    |   Y       |   Y       |   Y       |
 *  PASID_SEL       |   Y       |   Y       |   Y       |
 *  PAGE_PASID      |   Y       |   Y       |   N/A     |
 *
 */
enum iommu_inv_granularity {
	IOMMU_INV_GRANU_DOMAIN_ALL_PASID,
	IOMMU_INV_GRANU_PASID_SEL,
	IOMMU_INV_GRANU_PAGE_PASID,
	IOMMU_INV_NR_GRANU,
};

/**
 * enum iommu_inv_type - Generic translation cache types for invalidation
 *
 * @IOMMU_INV_TYPE_DTLB:	device IOTLB
 * @IOMMU_INV_TYPE_TLB:		IOMMU paging structure cache
 * @IOMMU_INV_TYPE_PASID:	PASID cache
 * Invalidation requests sent to IOMMU for a given device need to indicate
 * which type of translation cache to be operated on. Combined with enum
 * iommu_inv_granularity, model specific driver can do a simple lookup to
 * convert from generic to model specific value.
 */
enum iommu_inv_type {
	IOMMU_INV_TYPE_DTLB,
	IOMMU_INV_TYPE_TLB,
	IOMMU_INV_TYPE_PASID,
	IOMMU_INV_NR_TYPE
};

/**
 * Translation cache invalidation header that contains mandatory meta data.
 * @version:	info format version, expecting future extesions
 * @type:	type of translation cache to be invalidated
 */
struct tlb_invalidate_hdr {
	__u32 version;
#define TLB_INV_HDR_VERSION_1 1
	enum iommu_inv_type type;
};

/**
 * Translation cache invalidation information, contains generic IOMMU
 * data which can be parsed based on model ID by model specific drivers.
 * Since the invalidation of second level page tables are included in the
 * unmap operation, this info is only applicable to the first level
 * translation caches, i.e. DMA request with PASID.
 *
 * @granularity:	requested invalidation granularity, type dependent
 * @size:		2^size of 4K pages, 0 for 4k, 9 for 2MB, etc.
 * @nr_pages:		number of pages to invalidate
 * @pasid:		processor address space ID value per PCI spec.
 * @addr:		page address to be invalidated
 * @flags		IOMMU_INVALIDATE_ADDR_LEAF: leaf paging entries
 *			IOMMU_INVALIDATE_GLOBAL_PAGE: global pages
 *
 */
struct tlb_invalidate_info {
	struct tlb_invalidate_hdr	hdr;
	enum iommu_inv_granularity	granularity;
	__u32		flags;
#define IOMMU_INVALIDATE_ADDR_LEAF	(1 << 0)
#define IOMMU_INVALIDATE_GLOBAL_PAGE	(1 << 1)
	__u8		size;
	__u64		nr_pages;
	__u32		pasid;
	__u64		addr;
};
#endif /* _UAPI_IOMMU_H */
