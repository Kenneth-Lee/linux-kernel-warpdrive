// SPDX-License-Identifier: GPL-2.0+
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/irqreturn.h>
#include <linux/log2.h>
#include <linux/uacce.h>
#include "qm.h"

#define QM_DEF_Q_NUM			128

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
#define SQ_TAIL_SHIFT			16
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
#define CQ_TAIL_SHIFT			16
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

#define EQC_PHASE_BIT			0x00010000

/* aeqc shift */
#define MB_AEQC_AEQE_SHIFT		12
#define MB_AEQC_PHASE_SHIFT		16

/* cqe shift */
#define CQE_PHASE(cqe)			((cqe)->w7 & 0x1)

/* eqe shift */
#define EQE_PHASE(eqe)			(((eqe)->dw0 >> 16) & 0x1)
#define EQE_CQN(eqe)			(((eqe)->dw0) & 0xffff)

#define QM_EQE_CQN_MASK			0xffff

/* doorbell */
#define DOORBELL_CMD_SQ			0
#define DOORBELL_CMD_CQ			1
#define DOORBELL_CMD_EQ			2
#define DOORBELL_CMD_AEQ		3

#define DOORBELL_CMD_SEND_BASE		0x340

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


#define QM_MK_SQC_DW3(hop_num, page_sz, buf_sz, sqe_sz) \
	((hop_num << SQ_HOP_NUM_SHIFT) | \
	 (page_sz << SQ_PAGE_SIZE_SHIFT) | \
	 (buf_sz << SQ_BUF_SIZE_SHIFT) | \
	 (sqe_sz << SQ_SQE_SIZE_SHIFT))
#define QM_MK_SQC_W13(priority, orders, type) \
	((priority << SQ_PRIORITY_SHIFT) | \
	 (orders << SQ_ORDERS_SHIFT) | \
	 ((type & SQ_TYPE_MASK) << SQ_TYPE_SHIFT))
#define QM_MK_CQC_DW3(hop_num, page_sz, buf_sz, sqe_sz) \
	((hop_num << CQ_HOP_NUM_SHIFT) | \
	 (page_sz << CQ_PAGE_SIZE_SHIFT) | \
	 (buf_sz << CQ_BUF_SIZE_SHIFT) | \
	 (sqe_sz << CQ_SQE_SIZE_SHIFT))
#define QM_MK_CQC_DW6(phase, flag) \
	((phase << CQ_PHASE_SHIFT) | (flag << CQ_FLAG_SHIFT))

#define USE_PHY_IN_NOIOMMU_MODE 1

static int __hisi_qm_start(struct qm_info *qm);
static inline void qm_writel(struct qm_info *qm, u32 val, u32 offset)
{
	writel(val, qm->io_base + offset);
}

struct qm_info;

struct hisi_acc_qm_hw_ops {
	int (*vft_config)(struct qm_info *qm, u16 base, u32 number);
};

static inline int hacc_qm_mb_is_busy(struct qm_info *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(QM_ADDR(qm, MAILBOX_CMD_SEND_BASE),
		val, !((val >> MAILBOX_BUSY_SHIFT) & 0x1), 10, 1000);
}

static inline void qm_mb_write(struct qm_info *qm, void *src)
{
	void __iomem *fun_base = QM_ADDR(qm, MAILBOX_CMD_SEND_BASE);
	unsigned long tmp0 = 0, tmp1 = 0;

#ifndef __UT__
	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
#endif
}

static int qm_mb(struct qm_info *qm, u8 cmd, phys_addr_t phys_addr, u16 queue,
		   bool op, bool event)
{
	struct mailbox mailbox;
	int ret;

	dev_dbg(&qm->pdev->dev, "QM HW request to q-%u: %d-%llx\n", queue, cmd,
		phys_addr);

	mailbox.w0 = cmd |
		     (event ? 0x1 << MAILBOX_EVENT_SHIFT : 0) |
		     (op ? 0x1 << MAILBOX_OP_SHIFT : 0) |
		     (0x1 << MAILBOX_BUSY_SHIFT);
	mailbox.queue_num = queue;
	mailbox.base_l = lower_32_bits(phys_addr);
	mailbox.base_h = upper_32_bits(phys_addr);
	mailbox.rsvd = 0;

	mutex_lock(&qm->mailbox_lock);

	ret = hacc_qm_mb_is_busy(qm);
	if (unlikely(ret))
		goto out_with_lock;

	qm_mb_write(qm, &mailbox);
	ret = hacc_qm_mb_is_busy(qm);

out_with_lock:
	mutex_unlock(&qm->mailbox_lock);
	return ret;
}

static void qm_db(struct qm_info *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell = 0;

	dev_dbg(&qm->pdev->dev, "doorbell(qn=%d, cmd=%d, index=%d, pri=%d)\n",
		qn, cmd, index, priority);

	doorbell = qn | (cmd << 16) | ((u64)((index | (priority << 16)))) << 32;
	writeq(doorbell, QM_ADDR(qm, DOORBELL_CMD_SEND_BASE));
}

/* @return 0 - cq/eq event, 1 - async event, 2 - abnormal error */
static u32 qm_get_irq_source(struct qm_info *qm)
{
	return readl(QM_ADDR(qm, QM_VF_EQ_INT_SOURCE));
}

static inline struct hisi_qp *to_hisi_qp(struct qm_info *qm, struct eqe *eqe)
{
	u16 cqn = eqe->dw0 & QM_EQE_CQN_MASK;
	struct hisi_qp *qp;

	read_lock(&qm->qps_lock);
	qp = qm->qp_array[cqn];
	read_unlock(&qm->qps_lock);

	return qp;
}

static inline void qm_cq_head_update(struct hisi_qp *qp)
{
	if (qp->qp_status.cq_head == QM_Q_DEPTH - 1) {
		qp->cqc->dw6 = qp->cqc->dw6 ^ CQC_PHASE_BIT;
		qp->qp_status.cq_head = 0;
	} else
		qp->qp_status.cq_head++;
}

static inline void qm_poll_qp(struct hisi_qp *qp, struct qm_info *qm)
{
	struct cqe *cqe;

	cqe = qp->cqe + qp->qp_status.cq_head;

	if (qp->req_cb) {
		while (CQE_PHASE(cqe) == CQC_PHASE(qp->cqc)) {
			dma_rmb();
			qp->req_cb(qp, (unsigned long)(qp->sqe +
				   qm->sqe_size * cqe->sq_head));
			qm_cq_head_update(qp);
			cqe = qp->cqe + qp->qp_status.cq_head;
		}
	} else if (qp->event_cb) {
		qp->event_cb(qp);
		qm_cq_head_update(qp);
		cqe = qp->cqe + qp->qp_status.cq_head;
	}

	qm_db(qm, qp->queue_id, DOORBELL_CMD_CQ, qp->qp_status.cq_head, 0);
	qm_db(qm, qp->queue_id, DOORBELL_CMD_CQ, qp->qp_status.cq_head, 1);
}

static irqreturn_t qm_irq_thread(int irq, void *data)
{
	struct qm_info *qm = data;
	struct eqe *eqe = qm->eqe + qm->eq_head;
	struct eqc *eqc = qm->eqc;
	struct hisi_qp *qp;

	while (EQE_PHASE(eqe) == EQC_PHASE(eqc)) {
		qp = to_hisi_qp(qm, eqe);
		if (qp)
			qm_poll_qp(qp, qm);

		if (qm->eq_head == QM_Q_DEPTH - 1) {
			eqc->dw6 = eqc->dw6 ^ EQC_PHASE_BIT;
			eqe = qm->eqe;
			qm->eq_head = 0;
		} else {
			eqe++;
			qm->eq_head++;
		}
	}

	qm_db(qm, 0, DOORBELL_CMD_EQ, qm->eq_head, 0);

	return IRQ_HANDLED;
}

static void qm_init_qp_status(struct hisi_qp *qp)
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
static inline int qm_reg_wait_bit(struct qm_info *qm, u32 offset, u32 bit)
{
	int val;

	return readl_relaxed_poll_timeout(QM_ADDR(qm, offset), val,
					  val & BIT(bit), 10, 1000);
}

/* the config should be conducted after hisi_acc_init_qm_mem() */
static int qm_vft_common_config(struct qm_info *qm, u16 base, u32 number)
{
	u64 tmp;
	int ret;

	ret = qm_reg_wait_bit(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	qm_writel(qm, 0x0, QM_VFT_CFG_OP_WR);
	qm_writel(qm, QM_SQC_VFT, QM_VFT_CFG_TYPE);
	qm_writel(qm, qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = QM_SQC_VFT_BUF_SIZE			|
	      QM_SQC_VFT_SQC_SIZE			|
	      QM_SQC_VFT_INDEX_NUMBER			|
	      QM_SQC_VFT_VALID				|
	      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;

	qm_writel(qm, tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	qm_writel(qm, tmp >> 32, QM_VFT_CFG_DATA_H);

	qm_writel(qm, 0x0, QM_VFT_CFG_RDY);
	qm_writel(qm, 0x1, QM_VFT_CFG_OP_ENABLE);
	ret = qm_reg_wait_bit(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	tmp = 0;

	qm_writel(qm, 0x0, QM_VFT_CFG_OP_WR);
	qm_writel(qm, QM_CQC_VFT, QM_VFT_CFG_TYPE);
	qm_writel(qm, qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = QM_CQC_VFT_BUF_SIZE			|
	      QM_CQC_VFT_SQC_SIZE			|
	      QM_CQC_VFT_INDEX_NUMBER			|
	      QM_CQC_VFT_VALID;

	qm_writel(qm, tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	qm_writel(qm, tmp >> 32, QM_VFT_CFG_DATA_H);

	qm_writel(qm, 0x0, QM_VFT_CFG_RDY);
	qm_writel(qm, 0x1, QM_VFT_CFG_OP_ENABLE);
	ret = qm_reg_wait_bit(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	return 0;
}

/*
 * v1: For Hi1620ES
 * v2: For Hi1620CS (Not implemented yet)
 */
static struct hisi_acc_qm_hw_ops qm_hw_ops_v1 = {
	.vft_config = qm_vft_common_config,
};

struct hisi_qp *hisi_qm_create_qp(struct qm_info *qm, u8 alg_type)
{
	struct hisi_qp *qp;
	struct device *dev = &qm->pdev->dev;
	int qp_index;
	int ret;

	write_lock(&qm->qps_lock);
	qp_index = find_first_zero_bit(qm->qp_bitmap, qm->qp_num);
	if (qp_index >= qm->qp_num) {
		write_unlock(&qm->qps_lock);
		return ERR_PTR(-EBUSY);
	}

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		ret = -ENOMEM;
		write_unlock(&qm->qps_lock);
		goto err_with_bitset;
	}

	qp->queue_id = qp_index;
	qp->qm = qm;
	qp->alg_type = alg_type;
	qm_init_qp_status(qp);
	set_bit(qp_index, qm->qp_bitmap);

	/* allocate qp dma memory */
	if (qm->uacce_mode == UACCE_MODE_NOUACCE) {
		qp->qdma.size = qm->sqe_size * QM_Q_DEPTH +
				sizeof(struct cqe) * QM_Q_DEPTH,
		qp->qdma.va = dma_alloc_coherent(dev, qp->qdma.size,
						 &qp->qdma.dma,
						 GFP_KERNEL | __GFP_ZERO);
		if (!qp->qdma.va)
			goto err_with_qp;

		dev_dbg(dev, "allocate qp dma buf(va=%p, dma=%pad, size=%lx)\n",
			qp->qdma.va, &qp->qdma.dma, qp->qdma.size);
	}

	write_unlock(&qm->qps_lock);
	return qp;

err_with_qp:
	kfree(qp);
err_with_bitset:
	bitmap_clear(qm->qp_bitmap, qp_index, 1);
	write_unlock(&qm->qps_lock);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(hisi_qm_create_qp);

int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg)
{
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;
	struct sqc *sqc;
	struct cqc *cqc;
	int qp_index = qp->queue_id;
	int pasid = arg;
	size_t off = 0;

#define QP_INIT_BUF(qp, type, size) do { \
	(qp)->type = (struct type *)((void *)(qp)->qdma.va + (off)); \
	(qp)->type##_dma = (qp)->qdma.dma + (off); \
	off += size; \
} while (0)

	if (!qp->qdma.dma) {
		dev_err(dev, "cannot get qm dma buffer\n");
		return -EINVAL;
	}

	WARN_ON(!qm->sqc);
	WARN_ON(!qm->cqc);

	sqc = qp->sqc = qm->sqc + qp_index;
	cqc = qp->cqc = qm->cqc + qp_index;
	qp->sqc_dma = qm->sqc_dma + qp_index * sizeof(struct sqc);
	qp->cqc_dma = qm->cqc_dma + qp_index * sizeof(struct cqc);

	QP_INIT_BUF(qp, sqe, qm->sqe_size * QM_Q_DEPTH);
	QP_INIT_BUF(qp, cqe, sizeof(struct cqe) * QM_Q_DEPTH);

	INIT_QC(sqc, qp->sqe_dma);
	sqc->pasid = pasid;
	sqc->dw3 = QM_MK_SQC_DW3(0, 0, 0, ilog2(qm->sqe_size));
	sqc->cq_num = qp_index;
	sqc->w13 = QM_MK_SQC_W13(0, 1, qp->alg_type);

	ret = qm_mb(qm, MAILBOX_CMD_SQC, qp->sqc_dma, qp_index, 0, 0);
	if (ret)
		return ret;

	INIT_QC(cqc, qp->cqe_dma);
	cqc->dw3 = QM_MK_CQC_DW3(0, 0, 0, 4);
	cqc->dw6 = QM_MK_CQC_DW6(1, 1);
	ret = qm_mb(qm, MAILBOX_CMD_CQC, (u64)qp->cqc_dma, qp_index, 0, 0);
	if (ret)
		return ret;

	write_lock(&qm->qps_lock);
	qm->qp_array[qp_index] = qp;
	init_completion(&qp->completion);
	write_unlock(&qm->qps_lock);

	dev_dbg(&qm->pdev->dev, "qp %d started\n", qp_index);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qm_start_qp);

void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct qm_info *qm = qp->qm;
	struct qm_dma *qdma = &qp->qdma;
	struct device *dev = &qm->pdev->dev;
	int qid = qp->queue_id;

	write_lock(&qm->qps_lock);
	qm->qp_array[qp->queue_id] = NULL;
	bitmap_clear(qm->qp_bitmap, qid, 1);
	write_unlock(&qm->qps_lock);

	if (qm->uacce_mode == UACCE_MODE_NOUACCE)
		dma_free_coherent(dev, qdma->size, qdma->va, qdma->dma);

	kfree(qp);
}
EXPORT_SYMBOL_GPL(hisi_qm_release_qp);

static void *qm_get_avail_sqe(struct hisi_qp *qp)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;
	u16 sq_tail = qp_status->sq_tail;

	if (qp_status->is_sq_full == 1)
		return NULL;

	return qp->sqe + sq_tail * qp->qm->sqe_size;
}

int hisi_qp_send(struct hisi_qp *qp, void *msg)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;
	u16 sq_tail = qp_status->sq_tail;
	u16 sq_tail_next = (sq_tail + 1) % QM_Q_DEPTH;
	unsigned long timeout = 100;
	void *sqe = qm_get_avail_sqe(qp);

	if (!sqe)
		return -EBUSY;

	memcpy(sqe, msg, qp->qm->sqe_size);

	qm_db(qp->qm, qp->queue_id, DOORBELL_CMD_SQ, sq_tail_next, 0);

	/* wait until job finished */
	wait_for_completion_timeout(&qp->completion, timeout);

	qp_status->sq_tail = sq_tail_next;

	if (qp_status->sq_tail == qp_status->sq_head)
		qp_status->is_sq_full = 1;

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qp_send);

#ifdef CONFIG_CRYPTO_QM_UACCE
static void qm_qp_event_notifier(struct hisi_qp *qp)
{
	uacce_wake_up(qp->uacce_q);
}

static int hisi_qm_uacce_get_queue(struct uacce *uacce, unsigned long arg,
			     struct uacce_queue **q)
{
	struct qm_info *qm = uacce->priv;
	struct hisi_qp *qp = NULL;
	struct uacce_queue *wd_q;
	u8 alg_type = 0; /* fix me here */
	int ret;

	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	wd_q = kzalloc(sizeof(struct uacce_queue), GFP_KERNEL);
	if (!wd_q) {
		ret = -ENOMEM;
		goto err_with_qp;
	}

	wd_q->priv = qp;
	wd_q->uacce = uacce;
	*q = wd_q;
	qp->uacce_q = wd_q;
	qp->event_cb = qm_qp_event_notifier;
	qp->pasid = arg;

	return 0;

err_with_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_qm_uacce_put_queue(struct uacce_queue *q)
{
	struct hisi_qp *qp = q->priv;

	/* need to stop hardware, but can not support in v1 */
	hisi_qm_release_qp(qp);
	kfree(q);
}

/* map sq/cq/doorbell to user space */
static int hisi_qm_uacce_mmap(struct uacce_queue *q,
			struct vm_area_struct *vma,
			struct uacce_qfile_region *qfr)
{
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct qm_info *qm = qp->qm;
	size_t sz = vma->vm_end - vma->vm_start;
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;

	switch (qfr->type) {
	case UACCE_QFRT_MMIO:
		WARN_ON(sz > PAGE_SIZE);
		vma->vm_flags |= VM_IO;
		/*
		 * Warning: This is not safe as multiple queues use the same
		 * doorbell, v1 hardware interface problem. will fix it in v2
		 */
		return remap_pfn_range(vma, vma->vm_start,
				       qm->phys_base >> PAGE_SHIFT,
				       sz, pgprot_noncached(vma->vm_page_prot));
	case UACCE_QFRT_DUS:
		if (qm->uacce_mode == UACCE_MODE_NOIOMMU) {
			if (sz != qp->qdma.size) {
				dev_warn(dev, "wrong queue size %ld vs %ld\n",
					 sz, qp->qdma.size);
				return -EINVAL;
			}
			return remap_pfn_range(vma, vma->vm_start,
				qp->qdma.dma >> PAGE_SHIFT, sz,
				vma->vm_page_prot);
		}
		return -EINVAL;

	default:
		return -EINVAL;
	}
}

static int hisi_qm_uacce_start_queue(struct uacce_queue *q)
{
	int ret;
	struct qm_info *qm = q->uacce->priv;
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;

	dev_dbg(&q->uacce->dev, "uacce queue start\n");

	/* without SVA, qm has to start with qp in UACCE_MODE_UACCE mode */
	if (qm->uacce_mode == UACCE_MODE_UACCE) {
		qm->qdma.dma = q->qfrs[UACCE_QFRT_DKO]->iova;
		qm->qdma.va = q->qfrs[UACCE_QFRT_DKO]->kaddr;
		qm->qdma.size = q->qfrs[UACCE_QFRT_DKO]->nr_pages >> PAGE_SHIFT;
		ret = __hisi_qm_start(qm);
		if (ret)
			return ret;

		qp->qdma.dma = q->qfrs[UACCE_QFRT_DUS]->iova;
		qp->qdma.va = q->qfrs[UACCE_QFRT_DUS]->kaddr;
		qp->qdma.size = q->qfrs[UACCE_QFRT_DUS]->nr_pages >> PAGE_SHIFT;
	}

	ret = hisi_qm_start_qp(qp, qp->pasid);
	if (ret && qm->uacce_mode == UACCE_MODE_UACCE)
		hisi_qm_stop(qm);

	return ret;
}

static void hisi_qm_uacce_stop_queue(struct uacce_queue *q)
{
	struct qm_info *qm = q->uacce->priv;

	if (qm->uacce_mode == UACCE_MODE_UACCE)
		hisi_qm_stop(qm);
}

static int hisi_qm_uacce_map(struct uacce_queue *q,
			     struct uacce_qfile_region *qfr)
{
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct device *dev = &q->uacce->dev;

	if (qfr->type == UACCE_QFRT_DUS) {
		if (!qfr->cont_pages) {
			dev_err(dev, "noiommu mode need continue pages only\n");
			return -EINVAL;
		}

		qp->qdma.dma = page_to_phys(qfr->cont_pages);
		qp->qdma.va = qfr->kaddr; /* it can be 0 */
		qp->qdma.size = qfr->nr_pages >> PAGE_SHIFT;

		dev_dbg(dev, "hisi_qm_uacce_map dus dma=0x%lx, %d pages\n",
			(unsigned long)qp->qdma.dma, qfr->nr_pages);

	}
	return 0;
}

static int qm_set_sqctype(struct uacce_queue *q, u16 type)
{
	struct qm_info *qm = q->uacce->priv;
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct device *dev = &q->uacce->dev;
	struct sqc *sqc;
	int ret;

	write_lock(&qm->qps_lock);
	if (!qp->sqc_dma) {
		dev_info(dev, "Please start queue before set sqc type\n");
		ret = -EBUSY;
		goto out_with_lock;
	}

	sqc = qp->sqc;
	qp->alg_type = type;
	sqc->w13 = QM_MK_SQC_W13(0, 1, qp->alg_type);
	ret = qm_mb(qm, MAILBOX_CMD_SQC, qp->sqc_dma, qp->queue_id, 0, 0);

out_with_lock:
	write_unlock(&qm->qps_lock);
	return ret;
}

static long hisi_qm_uacce_ioctl(struct uacce_queue *q, unsigned int cmd,
				unsigned long arg)
{
	if (cmd == UACCE_CMD_QM_SET_OPTYPE)
		return qm_set_sqctype(q, (u16)arg);

	return -EINVAL;
}

/*
 * the device is set the UACCE_DEV_SVA, but it will be cut if SVA patch is not
 * available
 */
static struct uacce_ops uacce_qm_ops = {
	.owner = THIS_MODULE,
	.flags = UACCE_DEV_SVA | UACCE_DEV_KMAP_DUS,

	.get_queue = hisi_qm_uacce_get_queue,
	.put_queue = hisi_qm_uacce_put_queue,
	.start_queue = hisi_qm_uacce_start_queue,
	.stop_queue = hisi_qm_uacce_stop_queue,
	.mmap = hisi_qm_uacce_mmap,
	.ioctl = hisi_qm_uacce_ioctl,
};

static int qm_register_uacce(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct uacce *uacce = &qm->uacce;


	uacce->name = dev_name(&pdev->dev);
	uacce->drv_name = pdev->driver->name;
	uacce->pdev = &pdev->dev;
	uacce->is_vf = pdev->is_virtfn;
	uacce->priv = qm;
	uacce->ops = &uacce_qm_ops;
	uacce->algs = qm->algs;

	if (qm->uacce_mode == UACCE_MODE_NOIOMMU) {
#if USE_PHY_IN_NOIOMMU_MODE
		uacce->ops->flags = UACCE_DEV_NOIOMMU | UACCE_DEV_CONT_PAGE;
#else
		uacce->ops->flags = UACCE_DEV_NOIOMMU | UACCE_DEV_DRVMAP_DUS;
#endif
		uacce->ops->api_ver = HISI_QM_API_VER_BASE
				      UACCE_API_VER_NOIOMMU_SUBFIX;
		uacce->ops->qf_pg_start[UACCE_QFRT_MMIO] = 0;
		uacce->ops->qf_pg_start[UACCE_QFRT_DKO]  = UACCE_QFR_NA;
		uacce->ops->qf_pg_start[UACCE_QFRT_DUS]  = QM_DOORBELL_PAGE_NR;
		uacce->ops->qf_pg_start[UACCE_QFRT_SS]   = QM_DOORBELL_PAGE_NR +
							   QM_DUS_PAGE_NR;
		uacce->ops->map = hisi_qm_uacce_map;
	} else {
		uacce->ops->flags = UACCE_DEV_SVA | UACCE_DEV_KMAP_DUS;
		uacce->ops->api_ver = HISI_QM_API_VER_BASE;
		uacce->ops->qf_pg_start[UACCE_QFRT_MMIO] = 0;
		uacce->ops->qf_pg_start[UACCE_QFRT_DKO]  = QM_DOORBELL_PAGE_NR;
		uacce->ops->qf_pg_start[UACCE_QFRT_DUS]  = QM_DOORBELL_PAGE_NR +
							   QM_DKO_PAGE_NR;
		uacce->ops->qf_pg_start[UACCE_QFRT_SS]   = QM_DOORBELL_PAGE_NR +
							   QM_DKO_PAGE_NR +
							   QM_DUS_PAGE_NR;
	}

	return uacce_register(uacce);
}
#endif

static irqreturn_t qm_irq(int irq, void *data)
{
	struct qm_info *qm = data;
	u32 int_source;

	int_source = qm_get_irq_source(qm);
	if (int_source)
		return IRQ_WAKE_THREAD;

	dev_err(&qm->pdev->dev, "invalid int source %d\n", int_source);

	return IRQ_HANDLED;
}

/* put qm into init state, so the acce config become available */
static int hisi_qm_mem_start(struct qm_info *qm)
{
	u32 val;

	qm_writel(qm, 0x1, QM_MEM_START_INIT);
	return readl_relaxed_poll_timeout(QM_ADDR(qm, QM_MEM_INIT_DONE), val,
					  val & BIT(0), 10, 1000);
}

/* todo: The VF case is not considerred carefullly */
int hisi_qm_init(struct qm_info *qm)
{
	int ret;
	u16 ecam_val16;
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;

	pci_set_power_state(pdev, PCI_D0);
	ecam_val16 = PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY;
	pci_write_config_word(pdev, PCI_COMMAND, ecam_val16);

	ret = pci_enable_device_mem(pdev);
	if (ret < 0) {
		dev_err(dev, "Can't enable device mem!\n");
		return ret;
	}

	ret = pci_request_mem_regions(pdev, dev_name(dev));
	if (ret < 0) {
		dev_err(dev, "Can't request mem regions!\n");
		goto err_with_pcidev;
	}

	qm->phys_base = pci_resource_start(pdev, 2);
	qm->size = pci_resource_len(qm->pdev, 2);
	qm->io_base = devm_ioremap(dev, qm->phys_base, qm->size);
	if (!qm->io_base) {
		dev_err(dev, "Map IO space fail!\n");
		ret = -EIO;
		goto err_with_mem_regions;
	}

	dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	pci_set_master(pdev);

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (ret < 0) {
		dev_err(dev, "Enable MSI vectors fail!\n");
		goto err_with_mem_regions;
	}

	qm->eq_head = 0;
	mutex_init(&qm->mailbox_lock);
	rwlock_init(&qm->qps_lock);

	if (qm->ver == 1)
		qm->ops = &qm_hw_ops_v1;
	else {
		dev_err(dev, "qm version not support %d\n", qm->ver);
		return -EINVAL;
	}

	ret = devm_request_threaded_irq(dev, pci_irq_vector(pdev, 0),
					qm_irq, qm_irq_thread, IRQF_SHARED,
					dev_name(dev), qm);
	if (ret)
		goto err_with_irq_vec;

	qm->qp_bitmap = devm_kcalloc(dev, BITS_TO_LONGS(qm->qp_num),
				     sizeof(long), GFP_KERNEL);
	qm->qp_array = devm_kcalloc(dev, qm->qp_num,
				    sizeof(struct hisi_qp *), GFP_KERNEL);
	if (!qm->qp_bitmap || !qm->qp_array) {
		ret = -ENOMEM;
		goto err_with_irq;
	}

	if (pdev->is_physfn) {
		ret = hisi_qm_mem_start(qm);
		if (ret) {
			dev_err(dev, "mem start fail\n");
			goto err_with_irq;
		}
	}

	if (qm->uacce_mode) {
#ifdef CONFIG_CRYPTO_QM_UACCE
		ret = qm_register_uacce(qm);
#else
		dev_err(dev, "qm uacce feature is not enabled\n");
		ret = -EINVAL;
#endif
	}

	if (qm->uacce_mode != UACCE_MODE_UACCE) {
		qm->qdma.size = max_t(size_t, sizeof(struct eqc),
				      sizeof(struct aeqc)) +
				sizeof(struct eqe) * QM_Q_DEPTH +
				sizeof(struct sqc) * qm->qp_num +
				sizeof(struct cqc) * qm->qp_num;
		qm->qdma.va = dma_alloc_coherent(dev, qm->qdma.size,
						 &qm->qdma.dma,
						 GFP_KERNEL | __GFP_ZERO);
		dev_dbg(dev, "allocate qm dma buf(va=%p, dma=%pad, size=%lx)\n",
			qm->qdma.va, &qm->qdma.dma, qm->qdma.size);
		ret = qm->qdma.va ? 0 : -ENOMEM;
	}

	if (ret)
		goto err_with_uacce;

	dev_dbg(dev, "init qm %s to uacce mode %d\n",
		pdev->is_physfn ? "pf" : "vf", qm->uacce_mode);

	return 0;

err_with_uacce:
#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->uacce_mode)
		uacce_unregister(&qm->uacce);
#endif
err_with_irq:
	/* even for devm, it should be removed for the irq vec to be freed */
	devm_free_irq(dev, pci_irq_vector(pdev, 0), qm);
err_with_irq_vec:
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

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->uacce_mode)
		uacce_unregister(&qm->uacce);
#endif

	if (qm->uacce_mode != UACCE_MODE_UACCE)
		dma_free_coherent(&pdev->dev, qm->qdma.size, qm->qdma.va,
				  qm->qdma.dma);

	devm_free_irq(&pdev->dev, pci_irq_vector(pdev, 0), qm);
	pci_free_irq_vectors(pdev);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}
EXPORT_SYMBOL_GPL(hisi_qm_uninit);

static int __hisi_qm_start(struct qm_info *qm)
{
	size_t off = 0;
	int ret;

#define QM_INIT_BUF(qm, type, size) do { \
	(qm)->type = (struct type *)((void *)(qm)->qdma.va + (off)); \
	(qm)->type##_dma = (qm)->qdma.dma + (off); \
	off += size; \
} while (0)

	WARN_ON(!qm->qdma.dma);

	if (qm->pdev->is_physfn)
		qm->ops->vft_config(qm, qm->qp_base, qm->qp_num);

	/*
	 * notes: the order is important because the buffer should be stay in
	 * alignment boundary
	 */
	QM_INIT_BUF(qm, eqe, sizeof(struct eqe) * QM_Q_DEPTH);
	QM_INIT_BUF(qm, sqc, sizeof(struct sqc) * qm->qp_num);
	QM_INIT_BUF(qm, cqc, sizeof(struct cqc) * qm->qp_num);
	QM_INIT_BUF(qm, eqc,
		    max_t(size_t, sizeof(struct eqc), sizeof(struct aeqc)));

	/* check if the size exceed the DKO boundary */
	if (qm->uacce_mode == UACCE_MODE_UACCE) {
		dev_dbg(&qm->pdev->dev, "kernel-only buffer used (0x%lx/0x%x)\n",
			off, QM_DKO_PAGE_NR << PAGE_SHIFT);
		if (off > (QM_DKO_PAGE_NR << PAGE_SHIFT))
			return -EINVAL;
	}

	qm->eqc->base_l = lower_32_bits(qm->eqe_dma);
	qm->eqc->base_h = upper_32_bits(qm->eqe_dma);
	qm->eqc->dw3 = 2 << MB_EQC_EQE_SHIFT;
	qm->eqc->dw6 = (QM_Q_DEPTH - 1) | (1 << MB_EQC_PHASE_SHIFT);
	ret = qm_mb(qm, MAILBOX_CMD_EQC, qm->eqc_dma, 0, 0, 0);
	if (ret)
		return ret;

	ret = qm_mb(qm, MAILBOX_CMD_SQC_BT, qm->sqc_dma, 0, 0, 0);
	if (ret)
		return ret;

	ret = qm_mb(qm, MAILBOX_CMD_CQC_BT, qm->cqc_dma, 0, 0, 0);
	if (ret)
		return ret;

	writel(0x0, QM_ADDR(qm, QM_VF_EQ_INT_MASK));

	dev_dbg(&qm->pdev->dev, "qm started\n");

	return 0;
}

int hisi_qm_start(struct qm_info *qm)
{
	if (qm->uacce_mode == UACCE_MODE_UACCE) {
		dev_dbg(&qm->pdev->dev, "qm delay start\n");
		return 0;
	}

	return __hisi_qm_start(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_start);

void hisi_qm_stop(struct qm_info *qm)
{
	/* todo: recheck if this is the right way to disable the hw irq */
	writel(0x1, QM_ADDR(qm, QM_VF_EQ_INT_MASK));

}
EXPORT_SYMBOL_GPL(hisi_qm_stop);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
