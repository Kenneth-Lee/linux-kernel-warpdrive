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
#define PATH_STR_SIZE 		256
#define WD_NAME_SIZE 		64
#define WD_MAX_MEMLIST_SZ 	128


#ifndef dma_addr_t
#define dma_addr_t __u64
#endif

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
#ifndef WD_ERR
#define WD_ERR(format, args...) fprintf(stderr, format, ##args)
#endif

/* Default page size should be 4k size */
#define WDQ_MAP_REGION(region_index)	((region_index << 12) & 0xf000)
#define WDQ_MAP_Q(q_index)		((q_index << 16) & 0xffff0000)

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

static inline int _get_attr_str(const char *path, char value[PATH_STR_SIZE])
{
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		WD_ERR("open %s fail\n", path);
		return fd;
	}
	memset(value, 0, PATH_STR_SIZE);
	ret = read(fd, value, PATH_STR_SIZE);
	if (ret > 0) {
		close(fd);
		return 0;
	}
	close(fd);

	WD_ERR("read nothing from %s\n", path);
	return -EINVAL;
}

static inline int _get_attr_int(const char *path)
{
	char value[PATH_STR_SIZE];
	_get_attr_str(path, value);
	return atoi(value);
}

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

/* for debug only */
extern int wd_dump_all_algos(void);

/* this is only for drv used */
extern int wd_set_queue_attr(struct wd_queue *q, const char *name,
				char *value);
extern int __iommu_type(struct wd_queue *q);
#endif
