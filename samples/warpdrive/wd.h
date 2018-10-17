// SPDX-License-Identifier: GPL-2.0
#ifndef __WD_H
#define __WD_H
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include "../../include/uapi/linux/uacce.h"

#define SYS_VAL_SIZE		16
#define PATH_STR_SIZE		256
#define WD_NAME_SIZE		64

typedef int bool;

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef WD_ERR
#define WD_ERR(format, args...) fprintf(stderr, format, ##args)
#endif

#if defined(__AARCH64_CMODEL_SMALL__) && __AARCH64_CMODEL_SMALL__

#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")
#define rmb()		dsb(ld)
#define wmb()		dsb(st)

#else

#define rmb()
#define wmb()
#error "no platform mb, define one before compiling"

#endif

static inline void wd_reg_write(void *reg_addr, uint32_t value)
{
	*((volatile uint32_t *)reg_addr) = value;
	wmb();
}

static inline uint32_t wd_reg_read(void *reg_addr)
{
	uint32_t temp;

	temp = *((volatile uint32_t *)reg_addr);
	rmb();

	return temp;
}

#define WD_CAPA_PRIV_DATA_SIZE	64

#define alloc_obj(objp) do { \
	objp = malloc(sizeof(*objp)); \
	memset(objp, 0, sizeof(*objp)); \
}while(0)
#define free_obj(objp) if (objp)free(objp)

struct wd_queue {
	char hw_type[PATH_STR_SIZE];
	int hw_type_id;
	int dma_flag;
	void *priv; /* private data used by the drv layer */
	int fd;
	int pasid;
	int iommu_type;
	char *dev_path;
};

extern int wd_request_queue(struct wd_queue *q);
extern void wd_release_queue(struct wd_queue *q);
extern int wd_send(struct wd_queue *q, void *req);
extern int wd_recv(struct wd_queue *q, void **resp);
extern void wd_flush(struct wd_queue *q);
extern int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms);
extern void *wd_preserve_share_memory(struct wd_queue *q, size_t size);
extern int wd_share_preserved_memory(struct wd_queue *q,
				     struct wd_queue *target_q);

#endif
