/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __HZIP_DRV_H__
#define __HZIP_DRV_H__

#include <linux/types.h>
#include "../wd.h"



struct hisi_zip_msg {
	__u32 consumed;
	__u32 produced;
	__u32 comp_date_length;
	__u32 dw3;
	__u32 input_date_length;
	__u32 lba_l;
	__u32 lba_h;
	__u32 dw7; /* ... */
	__u32 dw8; /* ... */
	__u32 dw9; /* ... */
	__u32 dw10; /* ... */
	__u32 priv_info;
	__u32 dw12; /* ... */
	__u32 tag;
	__u32 dest_avail_out;
	__u32 rsvd0;
	__u32 comp_head_addr_l;
	__u32 comp_head_addr_h;
	__u32 source_addr_l;
	__u32 source_addr_h;
	__u32 dest_addr_l;
	__u32 dest_addr_h;
	__u32 stream_ctx_addr_l;
	__u32 stream_ctx_addr_h;
	__u32 cipher_key1_addr_l;
	__u32 cipher_key1_addr_h;
	__u32 cipher_key2_addr_l;
	__u32 cipher_key2_addr_h;
	__u32 rsvd1[4];
};


struct hisi_acc_qm_sqc {
	__u16 sqn;
};

#define HACC_QM_MB_SQC		_IOR('d', 1, struct hisi_acc_qm_sqc *)

#define DOORBELL_CMD_SQ		0
#define DOORBELL_CMD_CQ		1

int hisi_zip_set_queue_dio(struct wd_queue *q);
int hisi_zip_unset_queue_dio(struct wd_queue *q);
int hisi_zip_add_to_dio_q(struct wd_queue *q, void *req);
int hisi_zip_get_from_dio_q(struct wd_queue *q, void **resp);

#endif
