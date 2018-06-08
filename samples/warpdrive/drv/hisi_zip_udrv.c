/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "hisi_zip_udrv.h"
#include "../wd_util.h"

#if __AARCH64EL__ == 1
#define mb() asm volatile("dsb sy" : : : "memory")
#else
#warning "this file need to be used on AARCH64EL mode"
#define mb()
#endif

#define HZIP_SQE_SIZE		128
#define QM_CQE_SIZE		16
#define QM_EQ_DEPTH		1024

/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

#define HZIP_BAR2_SIZE		(4 * 1024 * 1024)

#define HZIP_DOORBELL_OFFSET	0x340

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7; /* phase, status */
};

struct hzip_queue_info {
	void *sq_base;
	void *cq_base;
	void *doorbell_base;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	bool cqc_phase;
	void *recv;
	int is_sq_full;
};

char *hzip_request_type[] = {
	"none",
	"resv",			/* 0x01 */
	"zlib_comp",		/* 0x02 */
};

int hacc_db(struct hzip_queue_info *q, __u8 cmd, __u16 index, __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)cmd << 16);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;

	*((__u64 *)base) = doorbell;

	return 0;
}

static int hisi_zip_fill_sqe(void *msg, struct hzip_queue_info *info, __u16 i)
{
	struct hisi_zip_msg *sqe = (struct hisi_zip_msg *)info->sq_base + i;

	memcpy((void *)sqe, msg, sizeof(struct hisi_zip_msg));

	return 0;
}

int hisi_zip_recv_sqe(struct hisi_zip_msg *sqe, void *recv_msg)
{
	__u32 status = sqe->dw3 & 0xff;
	__u32 type = sqe->dw9 & 0xff;

	if (status != 0) {
		printf("hisi zip %s fail!\n", hzip_request_type[type]);
		return -1;
	}

	memcpy((void *)recv_msg, sqe, sizeof(struct hisi_zip_msg));

	return 1;
}

int hisi_zip_set_queue_dio(struct wd_queue *q)
{
	struct hzip_queue_info *info;
	void *vaddr;
	int ret;
	unsigned long id;

	info = malloc(sizeof(struct hzip_queue_info));
	if (!info)
		return -1;

	q->priv = info;

	vaddr = wd_map_queue_region(q, HZIP_SQE_SIZE * QM_EQ_DEPTH, 0);
	if (vaddr == NULL)
		return -EIO;
	info->sq_base = vaddr;
	vaddr = wd_map_queue_region(q, QM_CQE_SIZE * QM_EQ_DEPTH, 1);
	if (vaddr == NULL)
		return -EIO;
	info->cq_base = vaddr;
	vaddr = wd_map_queue_region(q, HZIP_BAR2_SIZE, 2);
	if (vaddr == NULL)
		return -EIO;
	info->doorbell_base = vaddr + HZIP_DOORBELL_OFFSET;
	info->sq_tail_index = 0;
	info->sq_head_index = 0;
	info->cq_head_index = 0;
	info->cqc_phase = 1;

	info->is_sq_full = 0;
	id = (unsigned long)q->index;
	ret = ioctl(q->mdev, HACC_QM_MB_SQC, id);
	if (ret < 0) {
		printf("HACC_QM_MB_SQC ioctl fail!\n");
		return -1;
	}

	info->sqn = ret;
	info->recv = malloc(sizeof(struct hisi_zip_msg) * QM_EQ_DEPTH);
	if (!info->recv)
		return -1;

	return 0;
}

int hisi_zip_unset_queue_dio(struct wd_queue *q)
{
	struct hzip_queue_info *info = (struct hzip_queue_info *)q->priv;

	munmap(info->sq_base, HZIP_SQE_SIZE * QM_EQ_DEPTH);
	munmap(info->cq_base, QM_CQE_SIZE * QM_EQ_DEPTH);
	munmap(info->doorbell_base - HZIP_DOORBELL_OFFSET, HZIP_BAR2_SIZE);

	free(info->recv);
	free(info);
	q->priv = NULL;

	return 0;
}

int hisi_zip_add_to_dio_q(struct wd_queue *q, void *req)
{
	struct hzip_queue_info *info = (struct hzip_queue_info *)q->priv;
	__u16 i;

	if (info->is_sq_full)
		return -EBUSY;

	i = info->sq_tail_index;

	hisi_zip_fill_sqe(req, q->priv, i);

	mb();

	if (i == (QM_EQ_DEPTH - 1))
		i = 0;
	else
		i++;

	hacc_db(info, DOORBELL_CMD_SQ, i, 0);

	info->sq_tail_index = i;

	if (i == info->sq_head_index)
		info->is_sq_full = 1;

	return 0;
}

int hisi_zip_get_from_dio_q(struct wd_queue *q, void **resp)
{
	struct hzip_queue_info *info = (struct hzip_queue_info *)q->priv;
	__u16 i = info->cq_head_index;
	struct cqe *cq_base = info->cq_base;
	struct hisi_zip_msg *sq_base = info->sq_base;
	struct cqe *cqe = cq_base + i;
	struct hisi_zip_msg *sqe;
	void *recv_msg = info->recv + i * sizeof(struct hisi_zip_msg);
	int ret;

	if (info->cqc_phase == CQE_PHASE(cqe)) {
		sqe = sq_base + CQE_SQ_HEAD_INDEX(cqe);
		ret = hisi_zip_recv_sqe(sqe, recv_msg);
		if (ret < 0)
			return -EIO;

		if (info->is_sq_full)
			info->is_sq_full = 0;
	} else {
		return 0;
	}

	if (i == (QM_EQ_DEPTH - 1)) {
		info->cqc_phase = !(info->cqc_phase);
		i = 0;
	} else {
		i++;
	}

	hacc_db(info, DOORBELL_CMD_CQ, i, 0);

	info->cq_head_index = i;
	info->sq_head_index = i;

	*resp = recv_msg;

	return ret;
}
