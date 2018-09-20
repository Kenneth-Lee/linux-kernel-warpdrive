/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PASID table management for the IOMMU
 *
 * Copyright (C) 2018 ARM Ltd.
 */
#ifndef __IOMMU_PASID_TABLE_H
#define __IOMMU_PASID_TABLE_H

#include <linux/bug.h>
#include <linux/types.h>
#include "io-pgtable.h"

struct mm_struct;

enum iommu_pasid_table_fmt {
	PASID_TABLE_NUM_FMTS,
};

/**
 * iommu_pasid_entry - Entry of a PASID table
 *
 * @arch_id: architecture-specific data that uniquely identifies the entry. Used
 * by some IOMMUs for TLB invalidation
 * @release: function that frees the entry and its content. PASID entries may be
 * freed well after the PASID table ops are released, and may be shared between
 * different PASID tables, so the release method has to be standalone.
 */
struct iommu_pasid_entry {
	u64 arch_id;
	void (*release)(struct iommu_pasid_entry *);
};

/**
 * iommu_pasid_table_ops - Operations on a PASID table
 *
 * @alloc_shared_entry: allocate an entry for sharing an mm (SVA). Returns the
 * pointer to a new entry or an error.
 * @alloc_priv_entry: allocate an entry for map/unmap operations. Returns the
 * pointer to a new entry or an error.
 * @set_entry: write PASID table entry
 * @clear_entry: clear PASID table entry
 */
struct iommu_pasid_table_ops {
	struct iommu_pasid_entry *
	(*alloc_shared_entry)(struct iommu_pasid_table_ops *ops,
			      struct mm_struct *mm);
	struct iommu_pasid_entry *
	(*alloc_priv_entry)(struct iommu_pasid_table_ops *ops,
			    enum io_pgtable_fmt fmt,
			    struct io_pgtable_cfg *cfg);
	int (*set_entry)(struct iommu_pasid_table_ops *ops, int pasid,
			 struct iommu_pasid_entry *entry);
	void (*clear_entry)(struct iommu_pasid_table_ops *ops, int pasid,
			    struct iommu_pasid_entry *entry);
};

/**
 * iommu_pasid_sync_ops - Callbacks into the IOMMU driver
 *
 * @cfg_flush: flush cached configuration for one entry. For a multi-level PASID
 * table, 'leaf' tells whether to only flush cached leaf entries or intermediate
 * levels as well.
 * @cfg_flush_all: flush cached configuration for all entries of the PASID table
 * @tlb_flush: flush TLB entries for one entry
 */
struct iommu_pasid_sync_ops {
	void (*cfg_flush)(void *cookie, int pasid, bool leaf);
	void (*cfg_flush_all)(void *cookie);
	void (*tlb_flush)(void *cookie, int pasid,
			  struct iommu_pasid_entry *entry);
};

/**
 * struct iommu_pasid_table_cfg - Configuration data for a set of PASID tables.
 *
 * @iommu_dev device performing the DMA table walks
 * @order: number of PASID bits, set by IOMMU driver
 * @flush: TLB management callbacks for this set of tables.
 *
 * @base: DMA address of the allocated table, set by the allocator.
 */
struct iommu_pasid_table_cfg {
	struct device				*iommu_dev;
	size_t					order;
	const struct iommu_pasid_sync_ops	*sync;
	dma_addr_t				base;
};

struct iommu_pasid_table_ops *
iommu_alloc_pasid_ops(enum iommu_pasid_table_fmt fmt,
		      struct iommu_pasid_table_cfg *cfg,
		      void *cookie);
void iommu_free_pasid_ops(struct iommu_pasid_table_ops *ops);

static inline void iommu_free_pasid_entry(struct iommu_pasid_entry *entry)
{
	if (WARN_ON(!entry->release))
		return;
	entry->release(entry);
}

/**
 * struct iommu_pasid_table - describes a set of PASID tables
 *
 * @fmt: The PASID table format.
 * @cookie: An opaque token provided by the IOMMU driver and passed back to any
 * callback routine.
 * @cfg: A copy of the PASID table configuration.
 * @ops: The PASID table operations in use for this set of page tables.
 */
struct iommu_pasid_table {
	enum iommu_pasid_table_fmt	fmt;
	void				*cookie;
	struct iommu_pasid_table_cfg	cfg;
	struct iommu_pasid_table_ops	ops;
};

#define iommu_pasid_table_ops_to_table(ops) \
	container_of((ops), struct iommu_pasid_table, ops)

struct iommu_pasid_init_fns {
	struct iommu_pasid_table *(*alloc)(struct iommu_pasid_table_cfg *cfg,
					   void *cookie);
	void (*free)(struct iommu_pasid_table *table);
};

static inline void iommu_pasid_flush_all(struct iommu_pasid_table *table)
{
	table->cfg.sync->cfg_flush_all(table->cookie);
}

static inline void iommu_pasid_flush(struct iommu_pasid_table *table,
					 int pasid, bool leaf)
{
	table->cfg.sync->cfg_flush(table->cookie, pasid, leaf);
}

static inline void iommu_pasid_flush_tlbs(struct iommu_pasid_table *table,
					  int pasid,
					  struct iommu_pasid_entry *entry)
{
	table->cfg.sync->tlb_flush(table->cookie, pasid, entry);
}

#endif /* __IOMMU_PASID_TABLE_H */
