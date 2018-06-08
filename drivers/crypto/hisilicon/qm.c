/*
 * Copyright (c) 2018 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/io.h>
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/irqreturn.h>
#include "qm.h"

#define QM_DEF_Q_NUM		    128

/* eq/aeq irq enable */
#define QM_VF_AEQ_INT_SOURCE		0x0
#define QM_VF_AEQ_INT_MASK		0x4
#define QM_VF_EQ_INT_SOURCE		0x8
#define QM_VF_EQ_INT_MASK		0xc

/* mailbox */
#define MAILBOX_CMD_SQC			0x0
#define MAILBOX_CMD_CQC			0x1
#define MAILBOX_CMD_EQC			0x2
#define MAILBOX_CMD_AEQC		0x3
#define MAILBOX_CMD_SQC_BT		0x4
#define MAILBOX_CMD_CQC_BT		0x5

#define MAILBOX_CMD_SEND_BASE		0x300
#define MAILBOX_EVENT_SHIFT		8
#define MAILBOX_STATUS_SHIFT		9
#define MAILBOX_BUSY_SHIFT		13
#define MAILBOX_OP_SHIFT		14
#define MAILBOX_QUEUE_SHIFT		16

/* sqc shift */
#define SQ_HEAD_SHIFT			0
#define SQ_TAIL_SHIFI			16
#define SQ_HOP_NUM_SHIFT		0
#define SQ_PAGE_SIZE_SHIFT		4
#define SQ_BUF_SIZE_SHIFT		8
#define SQ_SQE_SIZE_SHIFT		12
#define SQ_HEAD_IDX_SIG_SHIFT		0
#define SQ_TAIL_IDX_SIG_SHIFT		0
#define SQ_CQN_SHIFT			0
#define SQ_PRIORITY_SHIFT		0
#define SQ_ORDERS_SHIFT			4
#define SQ_TYPE_SHIFT			8

#define SQ_TYPE_MASK			0xf

/* cqc shift */
#define CQ_HEAD_SHIFT			0
#define CQ_TAIL_SHIFI			16
#define CQ_HOP_NUM_SHIFT		0
#define CQ_PAGE_SIZE_SHIFT		4
#define CQ_BUF_SIZE_SHIFT		8
#define CQ_SQE_SIZE_SHIFT		12
#define CQ_PASID			0
#define CQ_HEAD_IDX_SIG_SHIFT		0
#define CQ_TAIL_IDX_SIG_SHIFT		0
#define CQ_CQN_SHIFT			0
#define CQ_PRIORITY_SHIFT		16
#define CQ_ORDERS_SHIFT			0
#define CQ_TYPE_SHIFT			0
#define CQ_PHASE_SHIFT			0
#define CQ_FLAG_SHIFT			1

#define CQC_HEAD_INDEX(cqc)		((cqc)->cq_head)
#define CQC_PHASE(cqc)			(((cqc)->dw6) & 0x1)
#define CQC_CQ_ADDRESS(cqc)		(((u64)((cqc)->cq_base_h) << 32) | \
					 ((cqc)->cq_base_l))
#define CQC_PHASE_BIT			0x1

/* eqc shift */
#define MB_EQC_EQE_SHIFT		12
#define MB_EQC_PHASE_SHIFT		16

#define EQC_HEAD_INDEX(eqc)		((eqc)->eq_head)
#define EQC_TAIL_INDEX(eqc)		((eqc)->eq_tail)
#define EQC_PHASE(eqc)			((((eqc)->dw6) >> 16) & 0x1)

#define EQC_PHASE_BIT		   0x00010000

/* aeqc shift */
#define MB_AEQC_AEQE_SHIFT		12
#define MB_AEQC_PHASE_SHIFT		16

/* cqe shift */
#define CQE_PHASE(cqe)			((cqe)->w7 & 0x1)
#define CQE_SQ_NUM(cqe)			((cqe)->sq_num)
#define CQE_SQ_HEAD_INDEX(cqe)		((cqe)->sq_head)

/* eqe shift */
#define EQE_PHASE(eqe)			(((eqe)->dw0 >> 16) & 0x1)
#define EQE_CQN(eqe)			(((eqe)->dw0) & 0xffff)

#define QM_EQE_CQN_MASK		 0xffff

/* aeqe shift */

/* doorbell */
#define DOORBELL_CMD_SQ			0
#define DOORBELL_CMD_CQ			1
#define DOORBELL_CMD_EQ			2
#define DOORBELL_CMD_AEQ		3

#define DOORBELL_CMD_SEND_BASE		0x340

/* qm 0x100000: cfg registers */
#define QM_MEM_START_INIT		0x100040
#define QM_MEM_INIT_DONE		0x100044
#define QM_VFT_CFG_RDY			0x10006c
#define QM_VFT_CFG_OP_WR		0x100058
#define QM_VFT_CFG_TYPE			0x10005c
#define QM_SQC_VFT			0x0
#define QM_CQC_VFT			0x1
#define QM_VFT_CFG_ADDRESS		0x100060
#define QM_VFT_CFG_OP_ENABLE		0x100054

#define QM_VFT_CFG_DATA_L		0x100064
#define QM_VFT_CFG_DATA_H		0x100068
#define QM_SQC_VFT_BUF_SIZE		(7ULL << 8)
#define QM_SQC_VFT_SQC_SIZE		(5ULL << 12)
#define QM_SQC_VFT_INDEX_NUMBER		(1ULL << 16)
#define QM_SQC_VFT_BT_INDEX_SHIFT	22
#define QM_SQC_VFT_START_SQN_SHIFT	28
#define QM_SQC_VFT_VALID		(1ULL << 44)
#define QM_CQC_VFT_BUF_SIZE		(7ULL << 8)
#define QM_CQC_VFT_SQC_SIZE		(5ULL << 12)
#define QM_CQC_VFT_INDEX_NUMBER		(1ULL << 16)
#define QM_CQC_VFT_BT_INDEX_SHIFT	22
#define QM_CQC_VFT_VALID		(1ULL << 28)

/* qm user domain */
#define QM_ARUSER_M_CFG_1		0x100088
#define QM_ARUSER_M_CFG_ENABLE	0x100090
#define QM_AWUSER_M_CFG_1		0x100098
#define QM_AWUSER_M_CFG_ENABLE	0x1000a0
#define QM_WUSER_M_CFG_ENABLE		0x1000a8
/* qm cache */
#define QM_CACHE_CTL			0x100050
#define QM_AXI_M_CFG			0x1000ac
#define QM_AXI_M_CFG_ENABLE		0x1000b0
#define QM_PEH_AXUSER_CFG	       	0x1000cc
#define QM_PEH_AXUSER_CFG_ENABLE	0x1000d0

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7; /* phase, status */
};

struct eqe {
	__le32 dw0; /* cqn, phase */
};

struct aeqe {
	__le32 dw0; /* qn, phase, type */
};

struct sqc {
	__le16 sq_head;
	__le16 sq_tail;
	__le32 sq_base_l;
	__le32 sq_base_h;
	__le32 dw3; /* v1: v2: sqe_size */
	__le16 qes;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11; /* tail_idx_sig, head_idx_sig, burst_cnt_shift */
	__le16 cq_num;
	__le16 w13; /* type, order, priority */
	__le32 rsvd1;
};

struct cqc {
	__le16 cq_head;
	__le16 cq_tail;
	__le32 cq_base_l;
	__le32 cq_base_h;
	__le32 dw3; /* v1: v2: cqe_size */
	__le16 qes;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11; /* tail_idx_sig, head_idx_sig */
	__le32 dw6; /* c_flag, phase */
	__le32 rsvd1;
};

struct eqc {
	__le16 eq_head;
	__le16 eq_tail;
	__le32 eq_base_l;
	__le32 eq_base_h;
	__le32 dw3; /* v1: v2: */
	__le32 rsvd[2];
	__le32 dw6; /* qes, phase */
};

struct aeqc {
	__le16 aeq_head;
	__le16 aeq_tail;
	__le32 aeq_base_l;
	__le32 aeq_base_h;
	__le32 rsvd[3];
	__le32 dw6; /* qes, phase */
};

struct mailbox {
	__le16 w0; /* op_type, busy, status, event, cmd */
	__le16 queue_num;
	__le32 mb_base_l;
	__le32 mb_base_h;
	__le32 rsvd;
};

struct doorbell {
	__le16 queue_num;
	__le16 cmd;
	__le16 index;
	__le16 priority;
};

struct qm_info;

struct hisi_acc_qm_hw_ops {
	int (*vft_config)(struct qm_info *qm, u16 base, u32 number);
	int (*aeq_config)(struct qm_info *qm);
	int (*get_vft_info)(struct qm_info *qm, u32 *base, u32 *number);
};

/* qm_info should be in qm.c as a private. */
struct qm_info {
	void __iomem *fun_base;
	u32 fun_num;

	u32 qp_base;
	u32 qp_num;

	struct sqc *sqc_base;
	dma_addr_t sqc_base_dma;

	struct cqc *cqc_base;
	dma_addr_t cqc_base_dma;

	struct eqc *eqc;
	dma_addr_t eqc_dma;

	struct eqe *eq_base;
	dma_addr_t eq_base_dma;
	u32 eq_head;

	struct aeqc *aeqc;
	struct aeqe *aeq_base;

	unsigned long *qp_bitmap;
	spinlock_t qp_bitmap_lock;
	struct hisi_acc_qp **qp_array;

	int node_id;

	bool qpn_fixed;

	spinlock_t mailbox_lock;

	void *priv;

	struct list_head qm;

	struct hisi_acc_qm_hw_ops *ops;

	struct dma_pool *eqc_aeqc_pool;

	struct device *dev;
};

/**
 * true: busy
 * false: ready
 */
static inline int hacc_qm_mb_is_busy(struct qm_info *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(qm->fun_base + MAILBOX_CMD_SEND_BASE,
		val, !((val >> MAILBOX_BUSY_SHIFT ) & 0x1), 10, 1000);
}

static inline void mb_write(struct qm_info *qm, void *src)
{
	void __iomem *fun_base = qm->fun_base + MAILBOX_CMD_SEND_BASE;
	unsigned long tmp0 = 0, tmp1 = 0;

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
}

/**
 * hacc_mb - Send HiSilicon accelarator mailbox command.
 * @qm: Queue Management struct
 * @cmd: Mailbox command
 * @phys_addr: ...
 * @queue: Queue number for SQC/CQC, function number for SQC_BT/CQC_BT
 * @op: 0 for writing, 1 for reading
 * @event: 0 for polling mode, 1 for event mode
 */
/* fix: how to do read mb */
static int hacc_mb(struct qm_info *qm, u8 cmd, u64 phys_addr, u16 queue,
		   bool op, bool event)
{
	struct mailbox mailbox;
	int i = 0;

	memset(&mailbox, 0, sizeof(struct mailbox));

	/* to do: prepare mb date */
	mailbox.w0 = cmd |
		     (event ? 0x1 << MAILBOX_EVENT_SHIFT : 0) |
		     (op ? 0x1 << MAILBOX_OP_SHIFT : 0) |
		     (0x1 << MAILBOX_BUSY_SHIFT);
	mailbox.queue_num = queue;
	mailbox.mb_base_l = lower_32_bits(phys_addr);
	mailbox.mb_base_h = upper_32_bits(phys_addr);
	mailbox.rsvd = 0;

	spin_lock(&qm->mailbox_lock);

	while (hacc_qm_mb_is_busy(qm) && i < 10)
		i++;
	if (i >= 10) {
		spin_unlock(&qm->mailbox_lock);
		pr_err("\n%s:qm mail box is busy!", __func__);
		return -1;
	}
	mb_write(qm, &mailbox);
	i = 0;
	while (hacc_qm_mb_is_busy(qm) && i < 10)
		i++;
	if (i >= 10) {
		spin_unlock(&qm->mailbox_lock);
		pr_err("\n%s:qm mail box is still busy!", __func__);
		return -1;
	}

	spin_unlock(&qm->mailbox_lock);

	return 0;
}

/**
 * hacc_db - Send HiSilicon accelarator doorbell command.
 * @qm:
 * @qn:
 * @cmd:
 * @index:
 * @prority:
 */
static int hacc_db(struct qm_info *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	void *base = qm->fun_base;
	u64 doorbell = 0;

	doorbell = (u64)qn | ((u64)cmd << 16);
	doorbell |= ((u64)index | ((u64)priority << 16)) << 32;

	writeq(doorbell, base + DOORBELL_CMD_SEND_BASE);

	return 0;
}

u32 hisi_acc_get_irq_source(struct qm_info *qm)
{
	return readl(qm->fun_base + QM_VF_EQ_INT_SOURCE);
}
EXPORT_SYMBOL_GPL(hisi_acc_get_irq_source);

static inline struct hisi_acc_qp *to_hisi_acc_qp(struct qm_info *qm,
						    struct eqe *eqe)
{
	u16 cqn = eqe->dw0 & QM_EQE_CQN_MASK;

	return qm->qp_array[cqn];
}

static inline struct cqe *to_current_cqe(struct hisi_acc_qp *qp)
{
	return qp->cq_base + qp->cq_head;
}

irqreturn_t hacc_irq_thread(int irq, void *data)
{
	struct qm_info *qm = (struct qm_info *)data;
	struct eqe *eqe = qm->eq_base + qm->eq_head;
	struct eqc *eqc = qm->eqc;
	struct hisi_acc_qp *qp;
	struct cqe *cqe;

	/* to do: if no new eqe, there is no irq, do nothing or reture error */

	while (EQE_PHASE(eqe) == EQC_PHASE(eqc)) {

		qp = to_hisi_acc_qp(qm, eqe);

		if (qp->type == CRYPTO_QUEUE) {

			cqe = to_current_cqe(qp);

			while (CQE_PHASE(cqe) == CQC_PHASE(qp->cqc)) {
				/* ? */
				dma_rmb();

				/* crypto sync interface: wakeup */

				/* crypto async interface: callback */
				/* handle each cqe */
				qp->sqe_handler(qp, qp->sq_base +
						CQE_SQ_HEAD_INDEX(cqe));

				if (qp->cq_head == QM_Q_DEPTH - 1) {
					qp->cqc->dw6 = qp->cqc->dw6 ^
						       CQC_PHASE_BIT;
					cqe = qp->cq_base;
					qp->cq_head = 0;
				} else {
					cqe++;
					qp->cq_head++;
				}
			}

			hacc_db(qm, qp->queue_id, DOORBELL_CMD_CQ,
				qp->cq_head, 0);
			/* set c_flag */
			hacc_db(qm, qp->queue_id, DOORBELL_CMD_CQ,
				qp->cq_head, 1);
		}

		if (qp->type == WD_QUEUE) {
			/* wd sync interface: if cq_head finished, wakeup;
			 *		    update cq head which is used both
			 *		    in user space and kernel.
			 */
		}

		if (qm->eq_head == QM_Q_DEPTH - 1) {
			eqc->dw6 = eqc->dw6 ^ EQC_PHASE_BIT;
			eqe = qm->eq_base;
			qm->eq_head = 0;
		} else {
			eqe++;
			qm->eq_head++;
		}
	}

	hacc_db(qm, 0, DOORBELL_CMD_EQ, qm->eq_head, 0);

	return IRQ_HANDLED;
}
EXPORT_SYMBOL_GPL(hacc_irq_thread);

/* check if bit in regs is 1 */
static inline int hisi_acc_check(struct qm_info *qm, u32 offset, u32 bit)
{
	int val;

	return readl_relaxed_poll_timeout(qm->fun_base + offset,
				    val, val & BIT(bit), 10, 1000);
}

/* init qm memory will erase configure in vft */
int hisi_acc_init_qm_mem(struct qm_info *qm)
{
	writel(0x1, qm->fun_base + QM_MEM_START_INIT);

	return hisi_acc_check(qm, QM_MEM_INIT_DONE, 0);
}
EXPORT_SYMBOL_GPL(hisi_acc_init_qm_mem);

void hisi_acc_set_user_domain(struct qm_info *qm, enum acc_dev dev)
{
	u32 val;

	if (dev == ZIP) {
		/* user domain */
		writel(0x40001070, qm->fun_base + QM_ARUSER_M_CFG_1);
		writel(0xfffffffe, qm->fun_base + QM_ARUSER_M_CFG_ENABLE);
		writel(0x40001070, qm->fun_base + QM_AWUSER_M_CFG_1);
		writel(0xfffffffe, qm->fun_base + QM_AWUSER_M_CFG_ENABLE);
		writel(0xffffffff, qm->fun_base + QM_WUSER_M_CFG_ENABLE);

		writel(0x4893, qm->fun_base + QM_CACHE_CTL);

		val = readl(qm->fun_base + QM_PEH_AXUSER_CFG);
		val |= (1 << 11);
		writel(val, qm->fun_base + QM_PEH_AXUSER_CFG);
	} else if (dev == HPRE) {
		/* user domain */
		writel(0x40000070, qm->fun_base + QM_ARUSER_M_CFG_1);
		writel(0x007ffffc, qm->fun_base + QM_ARUSER_M_CFG_ENABLE);
		//writel(0x007fffff, qm->fun_base + QM_ARUSER_M_CFG_ENABLE);
		writel(0x40000070, qm->fun_base + QM_AWUSER_M_CFG_1);
		writel(0x007ffffc, qm->fun_base + QM_AWUSER_M_CFG_ENABLE);
		//writel(0x007fffff, qm->fun_base + QM_AWUSER_M_CFG_ENABLE);
		writel(0x00000001, qm->fun_base + QM_WUSER_M_CFG_ENABLE);

		//writel(0x4083, qm->fun_base + QM_CACHE_CTL);
		writel(0x1833, qm->fun_base + QM_CACHE_CTL);
		writel(0x00400001, qm->fun_base + QM_PEH_AXUSER_CFG);
	}
}
EXPORT_SYMBOL_GPL(hisi_acc_set_user_domain);

void hisi_acc_set_cache(struct qm_info *qm, enum acc_dev dev)
{
	if (dev == ZIP) {
		/* cache */
		writel(0xffff,     qm->fun_base + QM_AXI_M_CFG);
		writel(0xffffffff, qm->fun_base + QM_AXI_M_CFG_ENABLE);
		writel(0xffffffff, qm->fun_base + QM_PEH_AXUSER_CFG_ENABLE);
	} else if (dev == HPRE) {
		/* cache */
		writel_relaxed(0x0303, /* 0xffff IT */
			qm->fun_base + QM_AXI_M_CFG);
		writel_relaxed(0xf,
			qm->fun_base + QM_AXI_M_CFG_ENABLE);
		writel_relaxed(0x7f,
			qm->fun_base + QM_PEH_AXUSER_CFG_ENABLE);
	}
}
EXPORT_SYMBOL_GPL(hisi_acc_set_cache);

/* v1 qm hw ops */
/* before call this at first time, please call hisi_acc_init_qm_mem */
static int vft_config_v1(struct qm_info *qm, u16 base, u32 number)
{
	u64 tmp;
	int ret;

	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	writel(0x0, qm->fun_base + QM_VFT_CFG_OP_WR);
	writel(QM_SQC_VFT, qm->fun_base + QM_VFT_CFG_TYPE);
	writel(qm->fun_num, qm->fun_base + QM_VFT_CFG_ADDRESS);

	tmp = QM_SQC_VFT_BUF_SIZE		       |
	      QM_SQC_VFT_SQC_SIZE			|
	      QM_SQC_VFT_INDEX_NUMBER			|
	      QM_SQC_VFT_VALID				|
	      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;

	writel(tmp & 0xffffffff, qm->fun_base + QM_VFT_CFG_DATA_L);
	writel(tmp >> 32, qm->fun_base + QM_VFT_CFG_DATA_H);

	writel(0x0, qm->fun_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->fun_base + QM_VFT_CFG_OP_ENABLE);
	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	tmp = 0;

	writel(0x0, qm->fun_base + QM_VFT_CFG_OP_WR);
	writel(QM_CQC_VFT, qm->fun_base + QM_VFT_CFG_TYPE);
	writel(qm->fun_num, qm->fun_base + QM_VFT_CFG_ADDRESS);

	tmp = QM_CQC_VFT_BUF_SIZE		       |
	      QM_CQC_VFT_SQC_SIZE			|
	      QM_CQC_VFT_INDEX_NUMBER			|
	      QM_CQC_VFT_VALID;

	writel(tmp & 0xffffffff, qm->fun_base + QM_VFT_CFG_DATA_L);
	writel(tmp >> 32, qm->fun_base + QM_VFT_CFG_DATA_H);

	writel(0x0, qm->fun_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->fun_base + QM_VFT_CFG_OP_ENABLE);
	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	return 0;
}

static struct hisi_acc_qm_hw_ops qm_hw_ops_v1 = {
	.vft_config = vft_config_v1,
	.aeq_config = NULL,
	.get_vft_info = NULL,
};

/* v2 qm hw ops */
static int aeq_config_v2(struct qm_info *qm)
{
	return 0;
} /* v1 = NULL */

static int vft_config_v2(struct qm_info *qm, u16 base, u32 number)
{
	u64 tmp;
	int ret;

	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	writel(0x0, qm->fun_base + QM_VFT_CFG_OP_WR);
	writel(QM_SQC_VFT, qm->fun_base + QM_VFT_CFG_TYPE);
	writel(qm->fun_num, qm->fun_base + QM_VFT_CFG_ADDRESS);

	tmp = QM_SQC_VFT_BUF_SIZE		       |
	      QM_SQC_VFT_SQC_SIZE			|
	      QM_SQC_VFT_INDEX_NUMBER			|
	      QM_SQC_VFT_VALID				|
	      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;

	writel(tmp & 0xffffffff, qm->fun_base + QM_VFT_CFG_DATA_L);
	writel(tmp >> 32, qm->fun_base + QM_VFT_CFG_DATA_H);

	writel(0x0, qm->fun_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->fun_base + QM_VFT_CFG_OP_ENABLE);
	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	tmp = 0;

	writel(0x0, qm->fun_base + QM_VFT_CFG_OP_WR);
	writel(QM_CQC_VFT, qm->fun_base + QM_VFT_CFG_TYPE);
	writel(qm->fun_num, qm->fun_base + QM_VFT_CFG_ADDRESS);

	tmp = QM_CQC_VFT_BUF_SIZE		       |
	      QM_CQC_VFT_SQC_SIZE			|
	      QM_CQC_VFT_INDEX_NUMBER			|
	      QM_CQC_VFT_VALID;

	writel(tmp & 0xffffffff, qm->fun_base + QM_VFT_CFG_DATA_L);
	writel(tmp >> 32, qm->fun_base + QM_VFT_CFG_DATA_H);

	writel(0x0, qm->fun_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->fun_base + QM_VFT_CFG_OP_ENABLE);
	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	return 0;
}

static int get_vft_info_v2(struct qm_info *qm, u32 *base, u32 *number)
{
	return 0;
}

static struct hisi_acc_qm_hw_ops qm_hw_ops_v2 = {
	.vft_config = vft_config_v2,
	.aeq_config = aeq_config_v2,
	.get_vft_info = get_vft_info_v2,
};

int hisi_acc_qm_info_create(struct device *dev, void __iomem *base, u32 number,
			    enum hw_version hw_v, struct qm_info **res)
{
	struct qm_info *qm;

	qm = (struct qm_info *)devm_kzalloc(dev, sizeof(*qm), GFP_KERNEL);
	if (!qm)
		return -ENOMEM;

	qm->fun_base = base;
	qm->fun_num = number;
	qm->eq_head = 0;
	qm->node_id = dev->numa_node;
	qm->dev = dev;
	spin_lock_init(&qm->mailbox_lock);
	spin_lock_init(&qm->qp_bitmap_lock);

	if (hw_v == ES)
		qm->ops = &qm_hw_ops_v1;
	else
		qm->ops = &qm_hw_ops_v2;

	*res = qm;

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_info_create);

int hisi_acc_qm_info_create_eq(struct qm_info *qm)
{
	size_t size = max_t(size_t, sizeof(struct eqc), sizeof(struct aeqc));
	struct device *dev = qm->dev;

	qm->eqc_aeqc_pool = dma_pool_create("eqc_aeqc", dev, size, 32, 0);
	if (!qm->eqc_aeqc_pool)
		goto err_out;

	qm->eqc = dma_pool_alloc(qm->eqc_aeqc_pool, GFP_ATOMIC, &qm->eqc_dma);
	if (!qm->eqc)
		goto err_out;

	size = sizeof(struct eqe) * QM_Q_DEPTH;
	qm->eq_base = dma_alloc_coherent(dev, size, &qm->eq_base_dma,
					 GFP_KERNEL);
	if (!qm->eq_base)
		goto err_eq;

	qm->eqc->eq_base_l = lower_32_bits(qm->eq_base_dma);
	qm->eqc->eq_base_h = upper_32_bits(qm->eq_base_dma);
	qm->eqc->dw3 = 2 << MB_EQC_EQE_SHIFT;
	qm->eqc->dw6 = (QM_Q_DEPTH - 1) | (1 << MB_EQC_PHASE_SHIFT);
	return hacc_mb(qm, MAILBOX_CMD_EQC, qm->eqc_dma, 0, 0, 0);
err_eq:
	dma_pool_free(qm->eqc_aeqc_pool, qm->eqc, qm->eqc_dma);
err_out:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_info_create_eq);

int hisi_acc_get_vft_info(struct qm_info *qm, u32 *base, u32 *number)
{
	if (!base || !number)
		return -EINVAL;

	if (!qm->ops->get_vft_info) {
		dev_err(qm->dev, "Don't support vft read!\n");
		return -EINVAL;
	}

	return qm->ops->get_vft_info(qm, base, number);
}
EXPORT_SYMBOL_GPL(hisi_acc_get_vft_info);

int hisi_acc_qm_info_vft_config(struct qm_info *qm, u32 base, u32 number)
{
	if (!number)
		return -EINVAL;

	return qm->ops->vft_config(qm, base, number);
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_info_vft_config);

int hisi_acc_qm_info_add_queue(struct qm_info *qm, u32 base, u32 number)
{
	size_t size;
	int ret = -1;

	if (!number)
		return -EINVAL;

	if (qm->qp_bitmap && qm->qp_array) {
		kfree(qm->qp_bitmap);
		kfree(qm->qp_array);
	}

	size = BITS_TO_LONGS(number) * sizeof(long);
	qm->qp_bitmap = kzalloc(size, GFP_KERNEL);
	if (!qm->qp_bitmap)
		goto err_bitmap;

	size = number * sizeof(struct hisi_acc_qp *);
	qm->qp_array = kzalloc(size, GFP_KERNEL);
	if (!qm->qp_array)
		goto err_qp_array;

	qm->qp_base = base;
	qm->qp_num = number;

	/* Init sqc_bt */
	size = sizeof(struct sqc) * number;
	qm->sqc_base = dma_alloc_coherent(qm->dev, size, &qm->sqc_base_dma,
					  GFP_KERNEL);
	if (!qm->sqc_base) {
		ret = -ENOMEM;
		goto err_vft_config;
	}
	ret = hacc_mb(qm, MAILBOX_CMD_SQC_BT, qm->sqc_base_dma, 0, 0, 0);
	if (ret) {
		pr_err("\nhacc_mb SQC fail!");
		goto err_vft_config;
	}
	/* Init cqc_bt */
	size = sizeof(struct cqc) * number;
	qm->cqc_base = dma_alloc_coherent(qm->dev, size, &qm->cqc_base_dma,
					  GFP_KERNEL);
	if (!qm->cqc_base) {
		ret = -ENOMEM;
		goto err_cqc;
	}
	ret = hacc_mb(qm, MAILBOX_CMD_CQC_BT, qm->cqc_base_dma, 0, 0, 0);
	if (ret) {
		pr_err("\nhacc_mb CQC fail!");
		goto err_cqc;
	}

	return 0;
err_cqc:
	dma_free_coherent(qm->dev, sizeof(struct sqc) * number, qm->sqc_base,
			  qm->sqc_base_dma);
err_vft_config:
	kfree(qm->qp_array);
err_qp_array:
	kfree(qm->qp_bitmap);
err_bitmap:
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_info_add_queue);

void hisi_acc_qm_info_release(struct qm_info *qm)
{
	dma_pool_free(qm->eqc_aeqc_pool, qm->eqc, qm->eqc_dma);
	dma_free_coherent(qm->dev, sizeof(struct eqe) * QM_Q_DEPTH, qm->eq_base,
			  qm->eq_base_dma);

	dma_pool_destroy(qm->eqc_aeqc_pool);

	kfree(qm->qp_bitmap);
	kfree(qm->qp_array);
	if (qm->sqc_base)
		dma_free_coherent(qm->dev, sizeof(struct sqc) * QM_Q_DEPTH,
				  qm->sqc_base, qm->sqc_base_dma);
	if (qm->cqc_base)
		dma_free_coherent(qm->dev, sizeof(struct cqc) * QM_Q_DEPTH,
				  qm->cqc_base, qm->cqc_base_dma);
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_info_release);

void hisi_acc_qm_set_priv(struct qm_info *qm, void *priv)
{
	qm->priv = priv;
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_set_priv);

void *hisi_acc_qm_get_priv(struct qm_info *qm)
{
	return qm->priv;
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_get_priv);

int hisi_acc_create_qp(struct qm_info *qm, struct hisi_acc_qp **res,
		       u32 sqe_size, u8 alg_type)
{
	struct hisi_acc_qp *qp;
	struct sqc *sqc;
	struct cqc *cqc;
	struct cqe *cq_base;
	void *sq_base;
	int qp_index;
	size_t size;
	int ret, order;

	spin_lock(&qm->qp_bitmap_lock);
	/* fix me: no q */
	qp_index = find_first_zero_bit(qm->qp_bitmap, qm->qp_num);
	set_bit(qp_index, qm->qp_bitmap);
	spin_unlock(&qm->qp_bitmap_lock);

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp)
		goto err_qp;

	qp->queue_id = qp_index;
	qp->sq_tail = 0;
	qp->cq_head = 0;
	qp->sqe_size = sqe_size;
	qp->parent = qm;
	qp->p_dev = qm->dev;

	sqc = qm->sqc_base + qp_index;
	qp->sqc = sqc;
	qp->sqc_dma = qm->sqc_base_dma + qp_index * sizeof(struct sqc);

	size = sqe_size * QM_Q_DEPTH;
	sq_base = dma_alloc_coherent(qm->dev, size, &qp->sq_base_dma,
				     GFP_KERNEL | GFP_ATOMIC);
	if (!sq_base)
		goto err_sq_base;
	memset(sq_base, 0, size);
	qp->sq_base = sq_base;
	if (sqe_size == 64)
		order = 6;
	if (sqe_size == 128)
		order = 7;
	sqc->sq_head = 0;
	sqc->sq_tail = 0;
	sqc->sq_base_l = lower_32_bits(qp->sq_base_dma);
	sqc->sq_base_h = upper_32_bits(qp->sq_base_dma);
	sqc->dw3 = (0 << SQ_HOP_NUM_SHIFT)      |
		   (0 << SQ_PAGE_SIZE_SHIFT)    |
		   (0 << SQ_BUF_SIZE_SHIFT)     |
		   (order << SQ_SQE_SIZE_SHIFT);
	sqc->qes = QM_Q_DEPTH - 1;
	sqc->pasid = 0;
	sqc->w11 = 0; /* fix me */
	sqc->cq_num = qp_index;
	sqc->w13 = 0 << SQ_PRIORITY_SHIFT	|
		   1 << SQ_ORDERS_SHIFT		|
		   (alg_type & SQ_TYPE_MASK) << SQ_TYPE_SHIFT;
	sqc->rsvd1 = 0;

	ret = hacc_mb(qm, MAILBOX_CMD_SQC, qp->sqc_dma, qp_index, 0, 0);
	if (ret) {
		pr_err("\nhacc_mb SQC fail!");
		goto err_cq_base;
	}
	cqc = qm->cqc_base + qp_index;
	qp->cqc = cqc;
	qp->cqc_dma = qm->cqc_base_dma + qp_index * sizeof(struct cqc);

	size = sizeof(struct cqe) * QM_Q_DEPTH;
	cq_base = dma_alloc_coherent(qm->dev, size, &qp->cq_base_dma,
				     GFP_KERNEL | GFP_ATOMIC);
	if (!cq_base)
		goto err_cq_base;
	memset(cq_base, 0, size);
	qp->cq_base = cq_base;

	cqc->cq_head = 0;
	cqc->cq_tail = 0;
	cqc->cq_base_l = lower_32_bits(qp->cq_base_dma);
	cqc->cq_base_h = upper_32_bits(qp->cq_base_dma);
	cqc->dw3 = (0 << CQ_HOP_NUM_SHIFT)      |
		   (0 << CQ_PAGE_SIZE_SHIFT)    |
		   (0 << CQ_BUF_SIZE_SHIFT)     |
		   (4 << CQ_SQE_SIZE_SHIFT);
	cqc->qes = QM_Q_DEPTH - 1;
	cqc->pasid = 0;
	cqc->w11 = 0; /* fix me */
	cqc->dw6 = 1 << CQ_PHASE_SHIFT | 1 << CQ_FLAG_SHIFT;
	cqc->rsvd1 = 0;

	ret = hacc_mb(qm, MAILBOX_CMD_CQC, qp->cqc_dma, qp_index, 0, 0);
	if (ret) {
		dma_free_coherent(qm->dev, size, qp->cq_base,
			  qp->cq_base_dma);
		pr_err("\nhacc_mb CQC fail!");
		goto err_cq_base;
	}
	qm->qp_array[qp_index] = qp;
	*res = qp;

	return qp_index;
err_cq_base:
	dma_free_coherent(qm->dev, qp->sqe_size * QM_Q_DEPTH, qp->sq_base,
			  qp->sq_base_dma);
err_sq_base:
	kfree(qp);
err_qp:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(hisi_acc_create_qp);

int hisi_acc_release_qp(struct hisi_acc_qp *qp)
{
	struct qm_info *qm = qp->parent;

	dma_free_coherent(qm->dev, qp->sqe_size * QM_Q_DEPTH, qp->sq_base,
			  qp->sq_base_dma);
	dma_free_coherent(qm->dev, sizeof(struct cqe) * QM_Q_DEPTH, qp->cq_base,
			  qp->cq_base_dma);

	spin_lock(&qm->qp_bitmap_lock);
	bitmap_clear(qm->qp_bitmap, qp->queue_id, 1);
	spin_unlock(&qm->qp_bitmap_lock);

	kfree(qp);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_acc_release_qp);

int hisi_acc_get_pasid(struct hisi_acc_qp *qp, u16 *pasid)
{
	int ret;

	ret = hacc_mb(qp->parent, MAILBOX_CMD_SQC, qp->sqc_dma, qp->queue_id, 1, 0);
	if (ret)
		return ret;
	*pasid = qp->sqc->pasid;

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_acc_get_pasid);

int hisi_acc_set_pasid(struct hisi_acc_qp *qp, u16 pasid)
{
	int ret;
	qp->sqc->pasid = pasid;

	/* to check */
	ret = hacc_mb(qp->parent, MAILBOX_CMD_SQC, qp->sqc_dma, qp->queue_id, 0, 0);
	if (ret)
		return ret;
	return 0;
}
EXPORT_SYMBOL_GPL(hisi_acc_set_pasid);

int hisi_acc_unset_pasid(struct hisi_acc_qp *qp)
{
	int ret;

	qp->sqc->pasid = 0;

	/* to check */
	ret = hacc_mb(qp->parent, MAILBOX_CMD_SQC, qp->sqc_dma, qp->queue_id, 0, 0);
	if (ret)
		return ret;
	return 0;
}
EXPORT_SYMBOL_GPL(hisi_acc_unset_pasid);

u16 hisi_acc_get_sq_tail(struct hisi_acc_qp *qp)
{
	return qp->sq_tail;
}
EXPORT_SYMBOL_GPL(hisi_acc_get_sq_tail);

/* fix me */
int hisi_acc_send(struct hisi_acc_qp *qp, u16 sq_tail, void *priv)
{
	hacc_db(qp->parent, qp->queue_id, DOORBELL_CMD_SQ, sq_tail, 0);

	qp->sq_tail++; /* fix me: wrap */

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_acc_send);

/* fix me */
int hisi_acc_receive(struct hisi_acc_qp *qp, void *priv)
{
	return 0;
}
EXPORT_SYMBOL_GPL(hisi_acc_receive);

/* add this temporarily to dump sq vft, better to merge with vft_config_v1 */
static u64 vft_read_v1(struct qm_info *qm)
{
	u32 vft_l, vft_h;
	int ret;

	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	writel(0x1, qm->fun_base + QM_VFT_CFG_OP_WR);
	writel(QM_SQC_VFT, qm->fun_base + QM_VFT_CFG_TYPE);
	writel(qm->fun_num, qm->fun_base + QM_VFT_CFG_ADDRESS);

	writel(0x0, qm->fun_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->fun_base + QM_VFT_CFG_OP_ENABLE);
	ret = hisi_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	vft_l = readl(qm->fun_base + QM_VFT_CFG_DATA_L);
	vft_h = readl(qm->fun_base + QM_VFT_CFG_DATA_H);

	return ((u64)vft_h << 32 | vft_l);
}

/* add this temporarily to dump sqc */
void hisi_acc_qm_read_sqc(struct hisi_acc_qp *qp)
{
	int ret;

	memset(qp->sqc, 0, sizeof(struct sqc));

	ret = hacc_mb(qp->parent, MAILBOX_CMD_SQC, qp->sqc_dma, qp->queue_id, 1, 0);
	if (ret)
		pr_err("\nhacc_mb read sqc fail!");
}
EXPORT_SYMBOL_GPL(hisi_acc_qm_read_sqc);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
