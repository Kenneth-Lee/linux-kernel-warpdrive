/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __HISI_HPRE_H
#define __HISI_HPRE_H

#include <linux/list.h>
#include "../qm.h"

#define HPRE_SQE_SIZE			64
#define HPRE_SQ_SIZE			(HPRE_SQE_SIZE * QM_Q_DEPTH)
#define QM_CQ_SIZE			(QM_CQE_SIZE * QM_Q_DEPTH)
#define HPRE_PF_DEF_Q_NUM		64
#define HPRE_PF_DEF_Q_BASE		0

struct hisi_hpre_ctrl;

struct hisi_hpre {
	struct hisi_qm qm;
	struct list_head list;
	struct hisi_hpre_ctrl *ctrl;
#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	struct vfio_spimdev *spimdev;
#endif
};

enum hisi_hpre_alg_type {
	HPRE_ALG_NC_NCRT = 0x0,
	HPRE_ALG_NC_CRT = 0x1,
	HPRE_ALG_KG_STD = 0x2,
	HPRE_ALG_KG_CRT = 0x3,
	HPRE_ALG_DH_G2 = 0x4,
	HPRE_ALG_DH = 0x5,
	HPRE_ALG_PRIME = 0x6,
	HPRE_ALG_MOD = 0x7,
	HPRE_ALG_MOD_INV = 0x8,
	HPRE_ALG_MUL = 0x9,
	HPRE_ALG_COPRIME = 0xA
};

struct hisi_hpre_sqe {
	__u32 alg	: 5;

	/* error type */
	__u32 etype	:11;
	__u32 resv0	: 14;
	__u32 done	: 2;
	__u32 task_len1	: 8;
	__u32 task_len2	: 8;
	__u32 mrttest_num	: 8;
	__u32 resv1	: 8;
	__u32 low_key;
	__u32 hi_key;
	__u32 low_in;
	__u32 hi_in;
	__u32 low_out;
	__u32 hi_out;
	__u32 tag	:16;
	__u32 resv2	:16;
	__u32 rsvd1[7];
};

extern struct list_head hisi_hpre_list;

extern int hpre_algs_register(void);
extern void hpre_algs_unregister(void);

#endif
