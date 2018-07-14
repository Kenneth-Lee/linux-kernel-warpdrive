/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


/* This file defines the dummy algo interface between the user and kernel space
 */

#ifndef __DUMMY_USR_IF_H
#define __DUMMY_USR_IF_H


/* Algorithm name */
#define AN_DUMMY_MEMCPY "memcopy"

#define AAN_AFLAGS		"aflags"
#define AAN_MAX_COPY_SIZE	"max_copy_size"

struct wd_dummy_cpy_param {
	int flags;
	int max_copy_size;
};

struct wd_dummy_cpy_msg {
	char *src_addr;
	char *tgt_addr;
	size_t size;
	void *ptr;
	__u32 ret;
};

#endif
