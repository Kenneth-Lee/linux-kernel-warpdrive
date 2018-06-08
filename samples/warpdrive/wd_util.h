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


#ifndef WD_ERR
#define WD_ERR(format, args...) printf(format, ##args)
#endif

/* Default page size should be 4k size */
#define WDQ_MAP_REGION(region_index)	((region_index << 12) & 0xf000)
#define WDQ_MAP_Q(q_index)		((q_index << 16) & 0xffff0000)

void *wd_map_queue_region(struct wd_queue *q, __u32 region_size,
				  __u16 region_index);

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

static inline int _get_attr_value(const char *path, const char *attr_name)
{
	char attr_path[PATH_STR_SIZE];
	int fd, ret;
	char value[PATH_STR_SIZE];

	(void)sprintf(attr_path, "%s/%s", path, attr_name);
	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		WD_ERR("open %s fail\n", attr_path);
		return fd;
	}
	memset(value, 0, PATH_STR_SIZE);
	ret = read(fd, value, PATH_STR_SIZE);
	if (ret > 0) {
		close(fd);
		return atoi(value);
	}
	close(fd);

	WD_ERR("read nothing from %s\n", attr_path);
	return ret;
}

static inline int _set_attr_value(const char *path, const char *attr_name, char *value)
{
	char attr_path[PATH_STR_SIZE];
	int fd, ret;

	(void)sprintf(attr_path, "%s/%s",  path, attr_name);
	fd = open(attr_path, O_WRONLY);
	if (fd < 0) {
		WD_ERR("open %s fail\n", attr_path);
		return fd;
	}

	ret = write(fd, value, PATH_STR_SIZE);
	if (ret >= 0) {
		close(fd);
		return 0;
	}
	close(fd);

	return -EFAULT;
}
#endif
