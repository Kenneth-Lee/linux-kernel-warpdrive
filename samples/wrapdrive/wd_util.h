/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* the common drv header define the unified interface for wd */
#ifndef __WD_UTIL_H__
#define __WD_UTIL_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "../../include/uapi/linux/vfio.h"
#include "wd.h"


#ifndef  WD_ERR
#define WD_ERR(format, args...) printf(format, ##args)
#endif

int wd_write_sysfs_file(const char *path, char *buf, int size);

static inline void wd_reg_write(void *reg_addr, uint32_t value)
{
	*((volatile uint32_t *)reg_addr) = value;
}

static inline uint32_t wd_reg_read(void *reg_addr)
{
	uint32_t temp;
	
	temp = *((volatile uint32_t *)reg_addr);

	return temp;
}

inline static void wd_kill_mdev(char *dev_path) {
	char buf[SYSFS_PATH_MAX];
	FILE *f;

	strncpy(buf, dev_path, PATH_STR_SIZE);
	strcat(buf, "/remove");
	f = fopen(buf, "w");
	if(!f) {
		WD_ERR("wrapdrive kill mdev failt: open %s fail\n", buf);
		return;
	}
	fwrite("1", 1, 1, f);
	fclose(f);
}

#endif
