/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "../../include/uapi/linux/vfio.h"
#include "wd.h"
#include "wd_dummy.h"
#include "wd_util.h"


int wd_dummy_memcpy(struct wd_queue *q, void *dst, void *src, size_t size)
{
	struct wd_dummy_cpy_msg req, *resp;
	int ret;

	req.src_addr = src;
	req.tgt_addr = dst;
	req.size = size;

	ret = wd_send(q, (void *)&req);
	if (ret)
		return ret;

	return wd_recv_sync(q, (void **)&resp, 0);
}

int wd_dummy_request_memcpy_queue(struct wd_queue *q, int max_copy_size)
{
	struct wd_capa capa;
	struct wd_dummy_cpy_param *cparam =
		(struct wd_dummy_cpy_param *)&capa.priv;

	memset(&capa, 0, sizeof(capa));
	capa.ver = 1;
	capa.alg = AN_DUMMY_MEMCPY;
	capa.throughput= 10;
	capa.latency = 10;
	cparam->max_copy_size = max_copy_size;

	return wd_request_queue(q, &capa);
}
