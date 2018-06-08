/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include "wd_util.h"

void *wd_map_queue_region(struct wd_queue *q, __u32 region_size,
				  __u16 region_index)
{
	void *vaddr;
	off_t off_set;


	if (!q || q->index > 0xffff || region_index > 0xf) {
		WD_ERR("%s: param error!\n", __func__);
		return NULL;
	}
	off_set = (off_t)(WDQ_MAP_REGION(region_index) | WDQ_MAP_Q(q->index));
	vaddr = mmap(NULL, region_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->mdev, off_set);
	if (vaddr == MAP_FAILED || vaddr == NULL) {
		WD_ERR("%s: mmap fail!\n", __func__);
		return NULL;
	}

	return vaddr;
}
