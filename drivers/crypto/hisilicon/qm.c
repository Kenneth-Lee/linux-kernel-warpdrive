// SPDX-License-Identifier: GPL-2.0+
#include <linux/io.h>
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/irqreturn.h>
#include <asm/page.h>
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
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
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
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3; /* v1: v2: cqe_size */
	__le16 qes;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11; /* tail_idx_sig, head_idx_sig */
	__le32 dw6; /* c_flag, phase */
	__le32 rsvd1;
};

#define INIT_QC(qc, base) do { \
	(qc)->head = 0; \
	(qc)->tail = 0; \
	(qc)->base_l = lower_32_bits(base); \
	(qc)->base_h = upper_32_bits(base); \
	(qc)->pasid = 0; \
	(qc)->w11 = 0; /* fix me */ \
	(qc)->rsvd1 = 0; \
	(qc)->qes = QM_Q_DEPTH - 1; \
} while (0)

struct eqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3; /* v1: v2: */
	__le32 rsvd[2];
	__le32 dw6; /* qes, phase */
};

struct aeqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 rsvd[3];
	__le32 dw6; /* qes, phase */
};

struct mailbox {
	__le16 w0; /* op_type, busy, status, event, cmd */
	__le16 queue_num;
	__le32 base_l;
	__le32 base_h;
	__le32 rsvd;
};

struct doorbell {
	__le16 queue_num;
	__le16 cmd;
	__le16 index;
	__le16 priority;
};

#define QM_DMA_BUF(p, buf) ((struct buf *)(p)->buf.addr)
#define QM_SQC(p) QM_DMA_BUF(p, sqc)
#define QM_CQC(p) QM_DMA_BUF(p, cqc)
#define QM_EQC(p) QM_DMA_BUF(p, eqc)
#define QM_EQE(p) QM_DMA_BUF(p, eqe)
#define QM_AEQC(p) QM_DMA_BUF(p, aeqc)
#define QM_AEQE(p) QM_DMA_BUF(p, aeqe)

#define QP_SQE_DMA(qp) ((qp)->scqe.dma)
#define QP_CQE(qp) ((struct cqe *)((qp)->scqe.addr + \
		qp->qm->sqe_size * QM_Q_DEPTH))
#define QP_CQE_DMA(qp) ((qp)->scqe.dma + qp->qm->sqe_size * QM_Q_DEPTH)

/* todo: most of write in this file may replace with writeX_relax */
/* note: I assume the qm variable's name is "qm" */
#define _IOWL(val, offset) writel(val, QM_ADDR(qm, offset))

struct qm_info;

struct hisi_acc_qm_hw_ops {
	int (*vft_config)(struct qm_info *qm, u16 base, u32 number);
	int (*aeq_config)(struct qm_info *qm);
	int (*get_vft_info)(struct qm_info *qm, u32 *base, u32 *number);
};

static inline int hacc_qm_mb_is_busy(struct qm_info *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(QM_ADDR(qm, MAILBOX_CMD_SEND_BASE),
		val, !((val >> MAILBOX_BUSY_SHIFT) & 0x1), 10, 1000);
}

static inline void mb_write(struct qm_info *qm, void *src)
{
	void __iomem *fun_base = QM_ADDR(qm, MAILBOX_CMD_SEND_BASE);
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
 * _hacc_mb - Send HiSilicon accelarator mailbox command.
 * @qm: Queue Management struct
 * @cmd: Mailbox command
 * @phys_addr: ...
 * @queue: Queue number for SQC/CQC, function number for SQC_BT/CQC_BT
 * @op: 0 for writing, 1 for reading
 * @event: 0 for polling mode, 1 for event mode
 */
/* fix: how todo read mb */
static int _hacc_mb(struct qm_info *qm, u8 cmd, u64 phys_addr, u16 queue,
		   bool op, bool event)
{
	struct mailbox mailbox;
	int i = 0;
	int ret = 0;

	memset(&mailbox, 0, sizeof(struct mailbox));

	/* todo: prepare mb date */
	mailbox.w0 = cmd |
		     (event ? 0x1 << MAILBOX_EVENT_SHIFT : 0) |
		     (op ? 0x1 << MAILBOX_OP_SHIFT : 0) |
		     (0x1 << MAILBOX_BUSY_SHIFT);
	mailbox.queue_num = queue;
	mailbox.base_l = lower_32_bits(phys_addr);
	mailbox.base_h = upper_32_bits(phys_addr);
	mailbox.rsvd = 0;

	mutex_lock(&qm->mailbox_lock);

	while (hacc_qm_mb_is_busy(qm) && i < 10)
		i++;
	if (i >= 10) {
		ret = -EBUSY;
		pr_err("\n%s:qm mail box is busy!", __func__);
		goto busy_unlock;
	}
	mb_write(qm, &mailbox);
	i = 0;
	while (hacc_qm_mb_is_busy(qm) && i < 10)
		i++;
	if (i >= 10) {
		ret = -EBUSY;
		pr_err("\n%s:qm mail box is still busy!", __func__);
		goto busy_unlock;
	}

busy_unlock:
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

/* send doorbell */
static int _hacc_db(struct qm_info *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell = 0;

	doorbell = (u64)qn | ((u64)cmd << 16);
	doorbell |= ((u64)index | ((u64)priority << 16)) << 32;

	writeq(doorbell, QM_ADDR(qm, DOORBELL_CMD_SEND_BASE));

	return 0;
}

/* @return 0 - cq/eq event, 1 - async event, 2 - abnormal error */
static u32 _get_irq_source(struct qm_info *qm)
{
	return readl(QM_ADDR(qm, QM_VF_EQ_INT_SOURCE));
}

static inline struct hisi_qp *to_hisi_qp(struct qm_info *qm,
						    struct eqe *eqe)
{
	u16 cqn = eqe->dw0 & QM_EQE_CQN_MASK;
	struct hisi_qp *qp;

	read_lock(&qm->qps_lock);
	qp = qm->qp_array[cqn];
	read_unlock(&qm->qps_lock);

	return qm->qp_array[cqn];
}

static inline void _cq_head_update(struct hisi_qp *qp)
{
	if (qp->qp_status.cq_head == QM_Q_DEPTH - 1) {
		QM_CQC(qp)->dw6 = QM_CQC(qp)->dw6 ^ CQC_PHASE_BIT;
		qp->qp_status.cq_head = 0;
	} else {
		qp->qp_status.cq_head++;
	}
}

/* fixme: this is just for receive, but what for send? */
static irqreturn_t _qm_irq_thread(int irq, void *data)
{
	struct qm_info *qm = (struct qm_info *)data;
	struct eqe *eqe = QM_EQE(qm) + qm->eq_head;
	struct eqc *eqc = QM_EQC(qm);
	struct hisi_qp *qp;
	struct cqe *cqe;

	while (EQE_PHASE(eqe) == EQC_PHASE(eqc)) {
		qp = to_hisi_qp(qm, eqe);
		if (qp) {
			cqe = QP_CQE(qp) + qp->qp_status.cq_head;

			if (qp->req_cb) {
				while (CQE_PHASE(cqe) == CQC_PHASE(QM_CQC(qp))) {
					dma_rmb();
					qp->req_cb(qp, QP_SQE_ADDR(qp) +
						     CQE_SQ_HEAD_INDEX(cqe));
					_cq_head_update(qp);
					cqe = QP_CQE(qp) + qp->qp_status.cq_head;
				}
			} else if (qp->event_cb) {
				qp->event_cb(qp);
				_cq_head_update(qp);
				cqe = QP_CQE(qp) + qp->qp_status.cq_head;
			}

			_hacc_db(qm, qp->queue_id, DOORBELL_CMD_CQ,
				qp->qp_status.cq_head, 0);

			/* set c_flag */
			_hacc_db(qm, qp->queue_id, DOORBELL_CMD_CQ,
				qp->qp_status.cq_head, 1);
		}

		if (qm->eq_head == QM_Q_DEPTH - 1) {
			eqc->dw6 = eqc->dw6 ^ EQC_PHASE_BIT;
			eqe = QM_EQE(qm);
			qm->eq_head = 0;
		} else {
			eqe++;
			qm->eq_head++;
		}
	}

	_hacc_db(qm, 0, DOORBELL_CMD_EQ, qm->eq_head, 0);

	return IRQ_HANDLED;
}

static void _init_qp_status(struct hisi_qp *qp)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;

	qp_status->sq_tail = 0;
	qp_status->sq_head = 0;
	qp_status->cq_head = 0;
	qp_status->sqn = 0;
	qp_status->cqc_phase = 1;
	qp_status->is_sq_full = 0;
}

/* check if bit in regs is 1 */
static inline int _acc_check(struct qm_info *qm, u32 offset, u32 bit)
{
	int val;

	return readl_relaxed_poll_timeout(QM_ADDR(qm, offset),
				    val, val & BIT(bit), 10, 1000);
}

/* fixme: some old code neec GFP_ATOMIC, but I don't think so, don't I */
static inline int _init_q_buffer(struct device *dev, size_t size,
		struct qm_dma_buffer *db)
{
	db->size = size;
	db->addr = dma_alloc_coherent(dev, size, &db->dma, GFP_KERNEL);
	if (!db->addr)
		return -ENOMEM;
	memset(db->addr, 0, size);
	return 0;
}

static inline void _uninit_q_buffer(struct device *dev,
		struct qm_dma_buffer *db)
{
	dma_free_coherent(dev, db->size, db->addr, db->dma);
}

static inline int _init_bt(struct qm_info *qm, struct device *dev, size_t size,
		struct qm_dma_buffer *db, int mb_cmd)
{
	int ret;

	ret = _init_q_buffer(dev, size, db);
	if (ret)
		return -ENOMEM;

	ret = _hacc_mb(qm, mb_cmd, db->dma, 0, 0, 0);
	if (ret) {
		_uninit_q_buffer(dev, db);
		return ret;
	}

	return 0;
}

/* the config should be conducted after hisi_acc_init_qm_mem() */
static int _vft_common_config(struct qm_info *qm, u16 base, u32 number)
{
	u64 tmp;
	int ret;

	ret = _acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	_IOWL(0x0, QM_VFT_CFG_OP_WR);
	_IOWL(QM_SQC_VFT, QM_VFT_CFG_TYPE);
	_IOWL(qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = QM_SQC_VFT_BUF_SIZE		       |
	      QM_SQC_VFT_SQC_SIZE			|
	      QM_SQC_VFT_INDEX_NUMBER			|
	      QM_SQC_VFT_VALID				|
	      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;

	_IOWL(tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	_IOWL(tmp >> 32, QM_VFT_CFG_DATA_H);

	_IOWL(0x0, QM_VFT_CFG_RDY);
	_IOWL(0x1, QM_VFT_CFG_OP_ENABLE);
	ret = _acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	tmp = 0;

	_IOWL(0x0, QM_VFT_CFG_OP_WR);
	_IOWL(QM_CQC_VFT, QM_VFT_CFG_TYPE);
	_IOWL(qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = QM_CQC_VFT_BUF_SIZE		       |
	      QM_CQC_VFT_SQC_SIZE			|
	      QM_CQC_VFT_INDEX_NUMBER			|
	      QM_CQC_VFT_VALID;

	_IOWL(tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	_IOWL(tmp >> 32, QM_VFT_CFG_DATA_H);

	_IOWL(0x0, QM_VFT_CFG_RDY);
	_IOWL(0x1, QM_VFT_CFG_OP_ENABLE);
	ret = _acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	return 0;
}

/* v1 qm hw ops */
static struct hisi_acc_qm_hw_ops qm_hw_ops_v1 = {
	.vft_config = _vft_common_config,
	.aeq_config = NULL,
	.get_vft_info = NULL,
};

/* v2 qm hw ops */
static int aeq_config_v2(struct qm_info *qm)
{
	return 0;
}

static int get_vft_info_v2(struct qm_info *qm, u32 *base, u32 *number)
{
	return 0;
}

static struct hisi_acc_qm_hw_ops qm_hw_ops_v2 = {
	.vft_config = _vft_common_config,
	.aeq_config = aeq_config_v2,
	.get_vft_info = get_vft_info_v2,
};

struct hisi_qp *hisi_qm_create_qp(struct qm_info *qm, u8 alg_type)
{
	struct hisi_qp *qp;
	int qp_index;
	int ret;

	/* allocate queue id */
	write_lock(&qm->qps_lock);
	qp_index = find_first_zero_bit(qm->qp_bitmap, qm->qp_num);
	if (qp_index >= qm->qp_num) {
		write_unlock(&qm->qps_lock);
		return ERR_PTR(-EBUSY);
	}
	set_bit(qp_index, qm->qp_bitmap);

	/* allocate qp struct */
	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		ret = -ENOMEM;
		write_unlock(&qm->qps_lock);
		goto err_with_bitset;
	}

	qp->queue_id = qp_index;
	qp->qm = qm;
	qp->alg_type = alg_type;
	_init_qp_status(qp);

	write_unlock(&qm->qps_lock);
	return qp;

err_with_bitset:
	clear_bit(qp_index, qm->qp_bitmap);
	write_unlock(&qm->qps_lock);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(hisi_qm_create_qp);

int hisi_qm_start_qp(struct hisi_qp *qp)
{
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	int ret, order;
	struct sqc *sqc;
	struct cqc *cqc;
	int qp_index = qp->queue_id;

	write_lock(&qm->qps_lock);

	/* set sq and cq context */
	qp->sqc.addr = QM_SQC(qm) + qp_index;
	qp->sqc.dma = qm->sqc.dma + qp_index * sizeof(struct sqc);
	sqc = QM_SQC(qp);

	qp->cqc.addr = QM_CQC(qm) + qp_index;
	qp->cqc.dma = qm->cqc.dma + qp_index * sizeof(struct cqc);
	cqc = QM_CQC(qp);

	/* allocate sq and cq */
	ret = _init_q_buffer(dev,
		qm->sqe_size * QM_Q_DEPTH + sizeof(struct cqe) * QM_Q_DEPTH,
		&qp->scqe);
	if (ret)
		goto err_with_lock;

	QM_ASSERT(sqe_size == 64 || sqe_size == 128);
	if (qm->sqe_size == 64)
		order = 6;
	if (qm->sqe_size == 128)
		order = 7;
	INIT_QC(sqc, qp->scqe.dma);
	sqc->dw3 = (0 << SQ_HOP_NUM_SHIFT)      |
		   (0 << SQ_PAGE_SIZE_SHIFT)    |
		   (0 << SQ_BUF_SIZE_SHIFT)     |
		   (order << SQ_SQE_SIZE_SHIFT);
	sqc->cq_num = qp_index;
	sqc->w13 = 0 << SQ_PRIORITY_SHIFT	|
		   1 << SQ_ORDERS_SHIFT		|
		   (qp->alg_type & SQ_TYPE_MASK) << SQ_TYPE_SHIFT;

	ret = _hacc_mb(qm, MAILBOX_CMD_SQC, qp->sqc.dma, qp_index, 0, 0);
	if (ret) {
		pr_err("\n_hacc_mb SQC fail!");
		goto err_with_lock;
	}


	INIT_QC(cqc, qp->scqe.dma + qm->sqe_size * QM_Q_DEPTH);
	cqc->dw3 = (0 << CQ_HOP_NUM_SHIFT)	|
		(0 << CQ_PAGE_SIZE_SHIFT)	|
		(0 << CQ_BUF_SIZE_SHIFT)	|
		(4 << CQ_SQE_SIZE_SHIFT);
	cqc->dw6 = 1 << CQ_PHASE_SHIFT | 1 << CQ_FLAG_SHIFT;

	ret = _hacc_mb(qm, MAILBOX_CMD_CQC, qp->cqc.dma, qp_index, 0, 0);
	if (ret)
		goto err_with_lock;

	qm->qp_array[qp_index] = qp;

	write_unlock(&qm->qps_lock);
	return 0;

err_with_lock:
	write_unlock(&qm->qps_lock);
	return -EBUSY;
}
EXPORT_SYMBOL_GPL(hisi_qm_start_qp);

void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	int qid = qp->queue_id;

	write_lock(&qm->qps_lock);
	qm->qp_array[qp->queue_id] = NULL;
	_uninit_q_buffer(dev, &qp->scqe);
	kfree(qp);
	bitmap_clear(qm->qp_bitmap, qid, 1);
	write_unlock(&qm->qps_lock);
}
EXPORT_SYMBOL_GPL(hisi_qm_release_qp);

static void *_get_avail_sqe(struct hisi_qp *qp)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;
	void *sq_base = QP_SQE_ADDR(qp);
	u16 sq_tail = qp_status->sq_tail;

	if (qp_status->is_sq_full == 1)
		return NULL;

	return sq_base + sq_tail * qp->qm->sqe_size;
}

int hisi_qp_send(struct hisi_qp *qp, void *msg)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;
	u16 sq_tail = qp_status->sq_tail;
	u16 sq_tail_next = (sq_tail + 1) % QM_Q_DEPTH;
	unsigned long timeout = 100;

	void *sqe = _get_avail_sqe(qp);
	if (sqe == NULL)
		return -1;

	memcpy(sqe, msg, qp->qm->sqe_size);

	/* fix me: support both ES and CS, and db fails */
	_hacc_db(qp->qm, qp->queue_id, DOORBELL_CMD_SQ, sq_tail_next, 0);

	/* wait until job finished */
	wait_for_completion_timeout(&qp->completion, timeout);

	qp_status->sq_tail = sq_tail_next;

	if (qp_status->sq_tail == qp_status->sq_head)
		qp_status->is_sq_full = 1;

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qp_send);

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
/* mdev->supported_type_groups */
static struct attribute *hisi_qm_type_attrs[] = {
	VFIO_SPIMDEV_DEFAULT_MDEV_TYPE_ATTRS,
	NULL,
};
static struct attribute_group hisi_qm_type_group = {
	.attrs = hisi_qm_type_attrs,
};
static struct attribute_group *mdev_type_groups[] = {
	&hisi_qm_type_group,
	NULL,
};

static void _qp_event_notifier(struct hisi_qp *qp)
{
	vfio_spimdev_wake_up(qp->spimdev_q);
}

static int hisi_qm_get_queue(struct vfio_spimdev *spimdev, unsigned long arg,
			  struct vfio_spimdev_queue **q)
{
	struct qm_info *qm = spimdev->priv;
	struct hisi_qp *qp = NULL;
	struct vfio_spimdev_queue *wd_q;
	u8 alg_type = 0; /* fix me here */
	int ret;
	int pasid = arg;

	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	wd_q = kzalloc(sizeof(struct vfio_spimdev_queue), GFP_KERNEL);
	if (!wd_q) {
		ret = -ENOMEM;
		goto err_with_qp;
	}
	wd_q->priv = qp;
	wd_q->spimdev = spimdev;
	wd_q->qid = (u16)ret;
	*q = wd_q;
	qp->spimdev_q = wd_q;
	qp->event_cb = _qp_event_notifier;

	QM_SQC(qp)->pasid = pasid;
	ret = _hacc_mb(qp->qm, MAILBOX_CMD_SQC, qp->sqc.dma, qp->queue_id, 0,
		       0);
	if (ret)
		goto err_with_wd_q;

	ret = hisi_qm_start_qp(qp);
	if (ret)
		goto err_with_wd_q;

	return 0;

err_with_wd_q:
	kfree(wd_q);
err_with_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static int hisi_qm_put_queue(struct vfio_spimdev_queue *q)
{
	struct hisi_qp *qp = q->priv;

	/* todo: need to stop hardware (but cannot in ES) */
	hisi_qm_release_qp(qp);
	kfree(q);
	return 0;
}

static int hisi_qm_is_q_updated(struct vfio_spimdev_queue *q)
{
	/* todo: support wd sync interface */
	return 0;
}

/* map sq/cq/doorbell to user space */
static int hisi_qm_mmap(struct vfio_spimdev_queue *q,
			struct vm_area_struct *vma)
{
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	size_t sz = vma->vm_end - vma->vm_start;
	u8 region;

	vma->vm_flags |= (VM_IO | VM_LOCKED | VM_DONTEXPAND | VM_DONTDUMP);
	region = _VFIO_SPIMDEV_REGION(vma->vm_pgoff);

	switch (region) {
	case 0:
		if (sz > PAGE_SIZE)
			return -EINVAL;

		/* Warning: This is not safe as multiple queues use the same
		 * doorbell. It is a hardware interface problem. 1620CS will
		 * fix it
		 */
		return remap_pfn_range(vma, vma->vm_start,
				       qm->phys_base >> PAGE_SHIFT,
				       sz, pgprot_noncached(vma->vm_page_prot));
	case 1:
		vma->vm_pgoff = 0;
		if (sz > qp->scqe.size)
			return -EINVAL;

		return dma_mmap_coherent(dev, vma, qp->scqe.addr, qp->scqe.dma,
				sz);

	default:
		return -EINVAL;
	}
}

static const struct vfio_spimdev_ops qm_ops = {
	.get_queue = hisi_qm_get_queue,
	.put_queue = hisi_qm_put_queue,
	.is_q_updated = hisi_qm_is_q_updated,
	.mmap = hisi_qm_mmap,
};

static int _qm_register_spimdev(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct vfio_spimdev *spimdev = &qm->spimdev;

	spimdev->iommu_type = VFIO_TYPE1_IOMMU;
	spimdev->dma_flag = VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP;
	spimdev->owner = THIS_MODULE;
	spimdev->name = qm->dev_name;
	spimdev->dev = &pdev->dev;
	spimdev->is_vf = pdev->is_virtfn;
	spimdev->priv = qm;
	spimdev->api_ver = "hisi_qm_v1";
	spimdev->flags = 0;

	spimdev->mdev_fops.mdev_attr_groups = qm->mdev_dev_groups;
	hisi_qm_type_group.name = qm->dev_name;
	spimdev->mdev_fops.supported_type_groups = mdev_type_groups;
	spimdev->ops = &qm_ops;

	return vfio_spimdev_register(spimdev);
}
#endif

int hisi_qm_init(const char *dev_name, struct qm_info *qm)
{
	int ret;
	u16 ecam_val16;
	struct pci_dev *pdev = qm->pdev;

	pci_set_power_state(pdev, PCI_D0);
	ecam_val16 = PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY;
	pci_write_config_word(pdev, PCI_COMMAND, ecam_val16);

	ret = pci_enable_device_mem(pdev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Can't enable device mem!\n");
		return ret;
	}

	ret = pci_request_mem_regions(pdev, dev_name);
	if (ret < 0) {
		dev_err(&pdev->dev, "Can't request mem regions!\n");
		goto err_with_pcidev;
	}

	/* todo: ras */

	qm->dev_name = dev_name;
	qm->phys_base = pci_resource_start(pdev, 2);
	qm->size = pci_resource_len(qm->pdev, 2);
	qm->io_base = devm_ioremap(&pdev->dev, qm->phys_base,
					 qm->size);
	if (!qm->io_base) {
		ret = -EIO;
		goto err_with_mem_regions;
	}

	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	pci_set_master(pdev);

	ret = pci_alloc_irq_vectors(pdev, 1, 2, PCI_IRQ_MSI);
	if (ret < 2) {
		dev_err(&pdev->dev, "Enable MSI vectors fail!\n");
		if (ret > 0)
			goto err_with_irqs;
		else
			goto err_with_mem_regions;
	}

	qm->eq_head = 0;
	mutex_init(&qm->mailbox_lock);
	rwlock_init(&qm->qps_lock);

	if (qm->ver)
		qm->ops = &qm_hw_ops_v1;
	else
		qm->ops = &qm_hw_ops_v2;

	return 0;

err_with_irqs:
	pci_free_irq_vectors(pdev);
err_with_mem_regions:
	pci_release_mem_regions(pdev);
err_with_pcidev:
	pci_disable_device(pdev);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_init);

void hisi_qm_uninit(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;

	pci_free_irq_vectors(pdev);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}
EXPORT_SYMBOL_GPL(hisi_qm_uninit);

static irqreturn_t _qm_irq(int irq, void *data)
{
	struct qm_info *qm = (struct qm_info *)data;
	u32 int_source;

	int_source = _get_irq_source(qm);
	if (int_source)
		return IRQ_WAKE_THREAD;

	dev_err(&qm->pdev->dev, "invalid int source %d\n", int_source);
	return IRQ_HANDLED;
}

int hisi_qm_start(struct qm_info *qm)
{
	/* create eq */
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	int ret;

	if (qm->pdev->is_physfn)
		qm->ops->vft_config(qm, qm->qp_base, qm->qp_num);
	else {
		/* get queue base and number, ES did not support to get this
		 * from mailbox. so fix me...
		 */
		qm->ops->get_vft_info(qm, &qm->qp_base, &qm->qp_num);
	}

	ret = _init_q_buffer(dev,
		max_t(size_t, sizeof(struct eqc), sizeof(struct aeqc)),
		&qm->eqc);
	if (ret)
		goto err_out;

	ret = _init_q_buffer(dev, sizeof(struct eqe) * QM_Q_DEPTH, &qm->eqe);
	if (ret)
		goto err_with_eqc;

	QM_EQC(qm)->base_l = lower_32_bits(qm->eqe.dma);
	QM_EQC(qm)->base_h = upper_32_bits(qm->eqe.dma);
	QM_EQC(qm)->dw3 = 2 << MB_EQC_EQE_SHIFT;
	QM_EQC(qm)->dw6 = (QM_Q_DEPTH - 1) | (1 << MB_EQC_PHASE_SHIFT);
	ret = _hacc_mb(qm, MAILBOX_CMD_EQC, qm->eqc.dma, 0, 0, 0);
	if (ret)
		goto err_with_eqe;

	qm->qp_bitmap = kcalloc(BITS_TO_LONGS(qm->qp_num), sizeof(long),
		GFP_KERNEL);
	if (!qm->qp_bitmap)
		goto err_with_eqe;

	qm->qp_array = kcalloc(qm->qp_num, sizeof(struct hisi_qp *),
		GFP_KERNEL);
	if (!qm->qp_array)
		goto err_with_bitmap;

	/* Init sqc_bt */
	ret = _init_bt(qm, dev, sizeof(struct sqc) * qm->qp_num, &qm->sqc,
			MAILBOX_CMD_SQC_BT);
	if (ret)
		goto err_with_qp_array;

	/* Init cqc_bt */
	ret = _init_bt(qm, dev, sizeof(struct cqc) * qm->qp_num, &qm->cqc,
			MAILBOX_CMD_CQC_BT);
	if (ret)
		goto err_with_sqc;

	/* todo: exception irq handler register, ES did not support */
	ret = devm_request_threaded_irq(dev, pci_irq_vector(pdev, 0),
					_qm_irq, _qm_irq_thread,
					IRQF_SHARED, qm->dev_name, (void *)qm);
	if (ret)
		goto err_with_cqc;
	writel_relaxed(0x0, QM_ADDR(qm, QM_VF_EQ_INT_MASK));

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	ret = _qm_register_spimdev(qm);
	if (ret)
		goto err_with_irq;

	writel_relaxed(0x0, QM_ADDR(qm, QM_VF_EQ_INT_MASK));
#endif

	return 0;

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
err_with_irq:
	devm_free_irq(dev, pci_irq_vector(pdev, 0), qm);
#endif
err_with_cqc:
	_uninit_q_buffer(dev, &qm->cqc);
err_with_sqc:
	_uninit_q_buffer(dev, &qm->sqc);
err_with_qp_array:
	kfree(qm->qp_array);
err_with_bitmap:
	kfree(qm->qp_bitmap);
err_with_eqe:
	_uninit_q_buffer(dev, &qm->eqe);
err_with_eqc:
	_uninit_q_buffer(dev, &qm->eqc);
err_out:
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start);

void hisi_qm_stop(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	vfio_spimdev_unregister(&qm->spimdev);
#endif

	devm_free_irq(dev, pci_irq_vector(pdev, 0), qm);
	_uninit_q_buffer(dev, &qm->cqc);
	kfree(qm->qp_array);
	kfree(qm->qp_bitmap);
	_uninit_q_buffer(dev, &qm->eqe);
	_uninit_q_buffer(dev, &qm->eqc);
}
EXPORT_SYMBOL_GPL(hisi_qm_stop);

/* put qm into init state, so the acce config become avaliable */
int hisi_qm_mem_start(struct qm_info *qm)
{
	u32 val;

	_IOWL(0x1, QM_MEM_START_INIT);
	return readl_relaxed_poll_timeout(QM_ADDR(qm, QM_MEM_INIT_DONE),
			    val, val & BIT(0), 10, 1000);
}
EXPORT_SYMBOL_GPL(hisi_qm_mem_start);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
