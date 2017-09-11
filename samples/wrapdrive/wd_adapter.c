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


#include "wd_adapter.h"
#include "./drv/hisi_sec_udrv_v1.h"
#include "./drv/dummy_drv.h"

static struct wd_drv_dio_if hw_dio_tbl[] = { {
		.hw_type = HISI_SEC_DRV_NAME,
		.open = hisi_sec_v1_dio_enable,
		.close = hisi_sec_v1_dio_disable,
		.send = hisi_sec_v1_send,
		.recv = hisi_sec_v1_recv,
		.share = NULL,
		.unshare = NULL,
	}, {
		.hw_type = DUMMY_WD,
		.open = dummy_set_queue_dio,
		.close = dummy_unset_queue_dio,
		.send = dummy_add_to_dio_q,
		.recv = dummy_get_from_dio_q,
	},

	/* Add other drivers direct IO operations here */
};

/* todo: there should be some stable way to match the device and the driver */
#define MAX_HW_TYPE (sizeof(hw_dio_tbl) / sizeof(hw_dio_tbl[0]))

int drv_open(struct wd_queue *q)
{ 
	int i;

	//todo: try to find another dev if the user driver is not avaliable
	for(i = 0; i < MAX_HW_TYPE; i++) {
		if (!strncmp(q->hw_type,
			hw_dio_tbl[i].hw_type, WD_NAME_SIZE)) {
			q->hw_type_id = i;
			return hw_dio_tbl[q->hw_type_id].open(q);
		}
	}
	WD_ERR("No matching driver to use!\n");	
	return -ENODEV;
}

int drv_close(struct wd_queue *q) {
	return hw_dio_tbl[q->hw_type_id].close(q);
}

int drv_send(struct wd_queue *q, void *req) {
	return hw_dio_tbl[q->hw_type_id].send(q, req);
}

int drv_recv(struct wd_queue *q, void **req) {
	return hw_dio_tbl[q->hw_type_id].recv(q, req);
}

int drv_share(struct wd_queue *q, const void *addr, size_t size, int flags) {
	return hw_dio_tbl[q->hw_type_id].share(q, addr, size, flags);
}

void drv_unshare(struct wd_queue *q, const void *addr, size_t size) {
	hw_dio_tbl[q->hw_type_id].unshare(q, addr, size);
}

bool drv_can_do_mem_share(struct wd_queue *q) {
	return hw_dio_tbl[q->hw_type_id].share != NULL;
}

void drv_flush(struct wd_queue *q) {
	if (hw_dio_tbl[q->hw_type_id].flush)
		hw_dio_tbl[q->hw_type_id].flush(q);
}
