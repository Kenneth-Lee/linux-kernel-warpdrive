// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include <dirent.h>


#include "wd_adapter.h"
#include "./drv/hisi_qm_udrv.h"
#include "./drv/dummy_drv.h"

static struct wd_drv_dio_if hw_dio_tbl[] = { {
		.hw_type = "hisi_qm_v1",
		.open = hisi_qm_set_queue_dio,
		.close = hisi_qm_unset_queue_dio,
		.send = hisi_qm_add_to_dio_q,
		.recv = hisi_qm_get_from_dio_q,
	}, {
		.hw_type = "wd_dummy_v1",
		.open = dummy_set_queue_dio,
		.close = dummy_unset_queue_dio,
		.send = dummy_add_to_dio_q,
		.recv = dummy_get_from_dio_q,
		.flush = dummy_flush,
		.preserve_mem = dummy_preserve_mem,
	},
	/* Add other drivers direct IO operations here */
};

/* todo: there should be some stable way to match the device and the driver */
#define MAX_HW_TYPE (sizeof(hw_dio_tbl) / sizeof(hw_dio_tbl[0]))

int drv_open(struct wd_queue *q)
{
	int i;

	//todo: try to find another dev if the user driver is not avaliable
	for (i = 0; i < MAX_HW_TYPE; i++) {
		if (!strcmp(q->hw_type,
			hw_dio_tbl[i].hw_type)) {
			q->hw_type_id = i;
			return hw_dio_tbl[q->hw_type_id].open(q);
		}
	}
	WD_ERR("No matching driver to use!\n");
	errno = ENODEV;
	return -ENODEV;
}

void drv_close(struct wd_queue *q)
{
	hw_dio_tbl[q->hw_type_id].close(q);
}

int drv_send(struct wd_queue *q, void *req)
{
	return hw_dio_tbl[q->hw_type_id].send(q, req);
}

int drv_recv(struct wd_queue *q, void **req)
{
	return hw_dio_tbl[q->hw_type_id].recv(q, req);
}

void drv_flush(struct wd_queue *q)
{
	if (hw_dio_tbl[q->hw_type_id].flush)
		hw_dio_tbl[q->hw_type_id].flush(q);
}

void *drv_preserve_mem(struct wd_queue *q, size_t size)
{
	if (hw_dio_tbl[q->hw_type_id].preserve_mem)
		return hw_dio_tbl[q->hw_type_id].preserve_mem(q, size);
	else
		return 0;
}
