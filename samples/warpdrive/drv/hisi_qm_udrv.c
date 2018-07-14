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
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>

#include "hisi_qm_udrv.h"
#include "../wd_util.h"

#if __AARCH64EL__ == 1
#define mb() {asm volatile("dsb sy" : : : "memory"); }
#else
#warning "this file need to be used on AARCH64EL mode"
#define mb()
#endif

#define QM_SQE_SIZE		128
#define QM_CQE_SIZE		16
#define QM_EQ_DEPTH		1024

/* cqe shift */
#define CQE_PHASE(cq)	(((*((__u32 *)(cq) + 3)) >> 16) & 0x1)
#define CQE_SQ_NUM(cq)	((*((__u32 *)(cq) + 2)) >> 16)
#define CQE_SQ_HEAD_INDEX(cq)	((*((__u32 *)(cq) + 2)) & 0xffff)

#define QM_IOMEM_SIZE		4096

#define QM_DOORBELL_OFFSET	0x340

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7; /* phase, status */
};

struct hisi_qm_queue_info {
	void *sq_base;
	void *cq_base;
	void *doorbell_base;
	__u16 sq_tail_index;
	__u16 sq_head_index;
	__u16 cq_head_index;
	__u16 sqn;
	bool cqc_phase;
	void *req_cache[QM_EQ_DEPTH];
	int is_sq_full;
};

int hacc_db(struct hisi_qm_queue_info *q, __u8 cmd, __u16 index, __u8 priority)
{
	void *base = q->doorbell_base;
	__u16 sqn = q->sqn;
	__u64 doorbell = 0;

	doorbell = (__u64)sqn | ((__u64)cmd << 16);
	doorbell |= ((__u64)index | ((__u64)priority << 16)) << 32;

	*((__u64 *)base) = doorbell;

	return 0;
}

static int hisi_qm_fill_sqe(void *msg, struct hisi_qm_queue_info *info, __u16 i)
{
	struct hisi_qm_msg *sqe = (struct hisi_qm_msg *)info->sq_base + i;
	memcpy((void *)sqe, msg, sizeof(struct hisi_qm_msg));
	assert(!info->req_cache[i]);
	info->req_cache[i] = msg;

	return 0;
}

static int hisi_qm_recv_sqe(struct hisi_qm_msg *sqe, struct hisi_qm_queue_info *info, __u16 i)
{
	__u32 status = sqe->dw3 & 0xff;
	__u32 type = sqe->dw9 & 0xff;

	if (status != 0 && status != 0x0d) {
		fprintf(stderr, "bad status (s=%d, t=%d)\n", status, type);
		return -EIO;
	}

	assert(info->req_cache[i]);
	memcpy((void *)info->req_cache[i], sqe, sizeof(struct hisi_qm_msg));
	return 0;
}

int hisi_qm_set_queue_dio(struct wd_queue *q)
{
	struct hisi_qm_queue_info *info;
	void *vaddr;
	int ret;

	alloc_obj(info);
	if (!info)
		return -1;

	q->priv = info;

	vaddr = mmap(NULL,
		QM_SQE_SIZE * QM_EQ_DEPTH + QM_CQE_SIZE * QM_EQ_DEPTH,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 4096);
	if (vaddr <= 0) {
		ret = (intptr_t)vaddr;
		goto err_with_info;
	}
	info->sq_base = vaddr;
	info->cq_base = vaddr + QM_SQE_SIZE * QM_EQ_DEPTH;

	vaddr = mmap(NULL, QM_IOMEM_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (vaddr <= 0) {
		ret = (intptr_t)vaddr;
		goto err_with_scq;
	}
	info->doorbell_base = vaddr + QM_DOORBELL_OFFSET;
	info->sq_tail_index = 0;
	info->sq_head_index = 0;
	info->cq_head_index = 0;
	info->cqc_phase = 1;

	info->is_sq_full = 0;

	return 0;

err_with_scq:
	munmap(info->sq_base,
		QM_SQE_SIZE * QM_EQ_DEPTH + QM_CQE_SIZE * QM_EQ_DEPTH);
err_with_info:
	free(info);
	return ret;
}

void hisi_qm_unset_queue_dio(struct wd_queue *q)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;

	munmap(info->doorbell_base - QM_DOORBELL_OFFSET, QM_IOMEM_SIZE);
	munmap(info->cq_base, QM_CQE_SIZE * QM_EQ_DEPTH);
	munmap(info->sq_base, QM_SQE_SIZE * QM_EQ_DEPTH);
	free(info);
	q->priv = NULL;
}

int hisi_qm_add_to_dio_q(struct wd_queue *q, void *req)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;
	__u16 i;

	if (info->is_sq_full)
		return -EBUSY;

	i = info->sq_tail_index;

	hisi_qm_fill_sqe(req, q->priv, i);

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

int hisi_qm_get_from_dio_q(struct wd_queue *q, void **resp)
{
	struct hisi_qm_queue_info *info = (struct hisi_qm_queue_info *)q->priv;
	__u16 i = info->cq_head_index;
	struct cqe *cq_base = info->cq_base;
	struct hisi_qm_msg *sq_base = info->sq_base;
	struct cqe *cqe = cq_base + i;
	struct hisi_qm_msg *sqe;
	int ret;

	if (info->cqc_phase == CQE_PHASE(cqe)) {
		sqe = sq_base + CQE_SQ_HEAD_INDEX(cqe);
		ret = hisi_qm_recv_sqe(sqe, info, i);
		if (ret < 0)
			return -EIO;

		if (info->is_sq_full)
			info->is_sq_full = 0;
	} else {
		return -EAGAIN;
	}

	*resp = info->req_cache[i];
	info->req_cache[i] = NULL;

	if (i == (QM_EQ_DEPTH - 1)) {
		info->cqc_phase = !(info->cqc_phase);
		i = 0;
	} else
		i++;

	hacc_db(info, DOORBELL_CMD_CQ, i, 0);

	info->cq_head_index = i;
	info->sq_head_index = i;


	return ret;
}
