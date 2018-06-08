/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* the common drv header define the unified interface for wd */
#ifndef __WD_ADAPTER_H__
#define __WD_ADAPTER_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>


#include "wd.h"

struct wd_drv_dio_if {
	char *hw_type;
	int (*open)(struct wd_queue *q);
	int (*close)(struct wd_queue *q);
	int (*set_pasid)(struct wd_queue *q);
	int (*unset_pasid)(struct wd_queue *q);
	int (*send)(struct wd_queue *q, void *req);
	int (*recv)(struct wd_queue *q, void **req);
	void (*flush)(struct wd_queue *q);
	int (*share)(struct wd_queue *q, const void *addr,
		size_t size, int flags);
	int (*unshare)(struct wd_queue *q, const void *addr, size_t size);
};

extern int drv_open(struct wd_queue *q);
extern int drv_close(struct wd_queue *q);
extern int drv_send(struct wd_queue *q, void *req);
extern int drv_recv(struct wd_queue *q, void **req);
extern void drv_flush(struct wd_queue *q);
extern int drv_share(struct wd_queue *q, const void *addr,
	size_t size, int flags);
extern void drv_unshare(struct wd_queue *q, const void *addr, size_t size);
extern bool drv_can_do_mem_share(struct wd_queue *q);

#endif
