/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __WD_H
#define __WD_H
#include <stdlib.h>
#include <errno.h>

#define SYS_VAL_SIZE		16
#define PATH_STR_SIZE 		256
#define WD_NAME_SIZE 		64
#define WD_MAX_MEMLIST_SZ 	128


#ifndef dma_addr_t
#define dma_addr_t __u64
#endif
#include "../../include/uapi/linux/vfio.h"
#include "../../include/uapi/linux/vfio_wdev.h"

typedef int bool;

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

/* the flags used by wd_capa->flags, the high 16bits are for algorithm
 * and the low 16bits are for Framework
 */
#define WD_FLAGS_FW_PREFER_LOCAL_ZONE 1

#define WD_FLAGS_FW_MASK 0x0000FFFF

/* Memory in accelerating message can be different */
enum wd_addr_flags {
	WD_AATTR_INVALID = 0,

	 /* Common user virtual memory */
	_WD_AATTR_COM_VIRT = 1,

	 /* Physical address*/
	_WD_AATTR_PHYS = 2,

	/* I/O virtual address*/
	_WD_AATTR_IOVA = 4,

	/* SGL, user cares for */
	WD_AATTR_SGL = 8,
};

#define WD_CAPA_PRIV_DATA_SIZE	64

/* Queue Capabilities header */
struct wd_capa {
	__u32 ver;
	char *alg;
	int throughput;
	int latency;
	__u32 flags;
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE];
};

#define alloc_obj(objp) (objp = malloc(sizeof(*objp)))
#define free_obj(objp) if (objp)free(objp)
#define WD_ERR(format, args...) printf(format, ##args)

struct wd_queue {
	char mdev_name[WD_NAME_SIZE];
	char *hw_type;
	int hw_type_id;
	int dma_flag;
	struct wd_capa capa;
	void *priv; /* private data used by the drv layer */
	int container;
	int group;
	int mdev;
	int pasid;
	void *alg_info;
	void *ctx;
	char mdev_path[PATH_STR_SIZE];
	char iommu_lpath[PATH_STR_SIZE];
	char iommu_fpath[PATH_STR_SIZE];
	char iommu_name[PATH_STR_SIZE];
	char vfio_group_path[PATH_STR_SIZE];
	int iommu_type;
	__u16 index;
	__u16 is_new_group;
	__u32 is_ext_container;
};

int wd_request_queue(int container, struct wd_queue *q, struct wd_capa *capa);
extern void wd_release_queue(struct wd_queue *q);
extern int wd_send(struct wd_queue *q, void *req);
extern int wd_recv(struct wd_queue *q, void **resp);
extern void wd_flush(struct wd_queue *q);
extern int wd_send_sync(struct wd_queue *q, void *req, __u16 ms);
extern int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms);
extern int wd_mem_share(struct wd_queue *q, const void *addr,
			size_t size, int flags);
extern void wd_mem_unshare(struct wd_queue *q, const void *addr, size_t size);

/* for debug only */
extern int wd_dump_all_algos(void);

/* this is only for drv used */
extern int wd_set_queue_attr(struct wd_queue *q, const char *name,
				char *value);
extern int __iommu_type(struct wd_queue *q);


#endif
