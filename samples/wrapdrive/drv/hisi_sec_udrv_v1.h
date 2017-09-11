/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef HISI_SEC_UDRV_V1_H
#define HISI_SEC_UDRV_V1_H

#ifdef __cplusplus
extern "C"{
#endif

#include "../wd_cipher.h"
#include "../wd_util.h"
#include "../../../drivers/crypto/hisilicon/hacv1/hisi_sec_drv_if.h"

#ifndef  SEC_ERROR
#define SEC_ERROR(format, args...) printf(format, ##args)
#endif

struct sec_eng_ring {
	__u32 depth;
	__u32 type;
	__u32 write;
	__u32 read;
	__u32 used;
	__u32 msg_size;
	void *base;
};

struct sec_wd_msg {
	union {
		struct wd_cipher_msg cmsg;

		/* To be extended */

		/* First 4 bytes of the message must indicate algorithm */
		char *alg;
	};
};

struct sec_eng_info {
	struct sec_eng_ring ring[HISI_SEC_HW_RING_NUM];
	void *rbase[HISI_SEC_HW_RING_NUM];
	struct wd_queue *q;
	int efd;
	int irqfd;

	/* Since SEC message format is different from WD's, the following is
	* needed to store receiveing messages.
	*/
	struct sec_wd_msg out_q[HISI_SEC_QUEUE_LEN];
	struct sec_eng_ring out_ring;
};
int hisi_sec_v1_dio_enable(struct wd_queue *q);
int hisi_sec_v1_send(struct wd_queue *q, void *req);
int hisi_sec_v1_recv(struct wd_queue *q, void **req);
int hisi_sec_v1_dio_disable(struct wd_queue *q);

#ifdef __cplusplus
}
#endif


#endif /* HISI_SEC_UDRV_V1_H */
