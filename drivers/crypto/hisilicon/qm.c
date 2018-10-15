// SPDX-License-Identifier: GPL-2.0+
#include <asm/page.h>
#include <linux/uacce.h>
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/irqreturn.h>
#include <linux/log2.h>
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

#define EQC_PHASE_BIT			0x00010000

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

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
}

static int qm_mb(struct qm_info *qm, u8 cmd, u64 phys_addr, u16 queue,
		   bool op, bool event)
{
	struct mailbox mailbox;
	int i = 0;
	int ret = 0;

	memset(&mailbox, 0, sizeof(struct mailbox));

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
		dev_err(&qm->pdev->dev, "QM mail box is busy!");
		goto busy_unlock;
	}
	qm_mb_write(qm, &mailbox);
	i = 0;
	while (hacc_qm_mb_is_busy(qm) && i < 10)
		i++;
	if (i >= 10) {
		ret = -EBUSY;
		dev_err(&qm->pdev->dev, "QM mail box is still busy!");
		goto busy_unlock;
	}

busy_unlock:
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

static int qm_db(struct qm_info *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell = 0;

	doorbell = (u64)qn | ((u64)cmd << 16);
	doorbell |= ((u64)index | ((u64)priority << 16)) << 32;

	writeq(doorbell, QM_ADDR(qm, DOORBELL_CMD_SEND_BASE));

	return 0;
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

	return qm->qp_array[cqn];
}

static inline void qm_cq_head_update(struct hisi_qp *qp)
{
	if (qp->qp_status.cq_head == QM_Q_DEPTH - 1) {
		qp->cqc->dw6 = qp->cqc->dw6 ^ CQC_PHASE_BIT;
		qp->qp_status.cq_head = 0;
	} else {
		qp->qp_status.cq_head++;
	}
}

static inline void qm_poll_qp(struct hisi_qp *qp, struct qm_info *qm)
{
	struct cqe *cqe;

	cqe = qp->cqe + qp->qp_status.cq_head;

	if (qp->req_cb) {
		while (CQE_PHASE(cqe) == CQC_PHASE(qp->cqc)) {
			dma_rmb();
			qp->req_cb(qp, (unsigned long)(qp->sqe + qm->sqe_size *
				   CQE_SQ_HEAD_INDEX(cqe)));
			qm_cq_head_update(qp);
			cqe = qp->cqe + qp->qp_status.cq_head;
		}
	} else if (qp->event_cb) {
		qp->event_cb(qp);
		qm_cq_head_update(qp);
		cqe = qp->cqe + qp->qp_status.cq_head;
	}

	qm_db(qm, qp->queue_id, DOORBELL_CMD_CQ,
		qp->qp_status.cq_head, 0);

	/* set c_flag */
	qm_db(qm, qp->queue_id, DOORBELL_CMD_CQ,
		qp->qp_status.cq_head, 1);
}

static irqreturn_t qm_irq_thread(int irq, void *data)
{
	struct qm_info *qm = data;
	struct eqe *eqe = qm->eqe + qm->eq_head;
	struct eqc *eqc = qm->eqc;
	struct hisi_qp *qp;

	while (EQE_PHASE(eqe) == EQC_PHASE(eqc)) {
		qp = to_hisi_qp(qm, eqe);
		if (qp) {
			qm_poll_qp(qp, qm);
		}

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
static inline int qm_acc_check(struct qm_info *qm, u32 offset, u32 bit)
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

	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
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
	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
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
	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	return 0;
}

static struct hisi_acc_qm_hw_ops qm_hw_ops_v1 = {
	.vft_config = qm_vft_common_config,
};

struct hisi_qp *hisi_qm_create_qp(struct qm_info *qm, u8 alg_type)
{
	struct hisi_qp *qp;
	int qp_index;
	int ret;

	write_lock(&qm->qps_lock);
	qp_index = find_first_zero_bit(qm->qp_bitmap, qm->qp_num);
	if (qp_index >= qm->qp_num) {
		write_unlock(&qm->qps_lock);
		return ERR_PTR(-EBUSY);
	}
	set_bit(qp_index, qm->qp_bitmap);

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

	write_unlock(&qm->qps_lock);
	return qp;

err_with_bitset:
	clear_bit(qp_index, qm->qp_bitmap);
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

	/* set sq and cq context */
	sqc = qp->sqc = qm->sqc + qp_index;
	cqc = qp->cqc = qm->cqc + qp_index * sizeof(struct cqc);

	/* allocate sq and cq */
	qp->sm = uacce_alloc_shared_mem(dev,
			qm->sqe_size * QM_Q_DEPTH +
				sizeof(struct cqe) * QM_Q_DEPTH,
			IOMMU_READ | IOMMU_WRITE);
	if (PTR_ERR_OR_ZERO(qp->sm))
		return PTR_ERR(qp->sm);

	qp->sqe = qp->sm->va;
	qp->cqe = qp->sm->va + qm->sqe_size * QM_Q_DEPTH;

	INIT_QC(sqc, qp->sqe);
	sqc->pasid = pasid;
	sqc->dw3 = (0 << SQ_HOP_NUM_SHIFT)      |
		   (0 << SQ_PAGE_SIZE_SHIFT)    |
		   (0 << SQ_BUF_SIZE_SHIFT)     |
		   (ilog2(qm->sqe_size) << SQ_SQE_SIZE_SHIFT);
	sqc->cq_num = qp_index;
	sqc->w13 = 0 << SQ_PRIORITY_SHIFT	|
		   1 << SQ_ORDERS_SHIFT		|
		   (qp->alg_type & SQ_TYPE_MASK) << SQ_TYPE_SHIFT;

	ret = qm_mb(qm, MAILBOX_CMD_SQC, (u64)qp->sqc, qp_index, 0, 0);
	if (ret)
		goto err_with_shared_mem;

	INIT_QC(cqc, qp->cqe);
	cqc->dw3 = (0 << CQ_HOP_NUM_SHIFT)	|
		   (0 << CQ_PAGE_SIZE_SHIFT)	|
		   (0 << CQ_BUF_SIZE_SHIFT)	|
		   (4 << CQ_SQE_SIZE_SHIFT);
	cqc->dw6 = 1 << CQ_PHASE_SHIFT | 1 << CQ_FLAG_SHIFT;

	ret = qm_mb(qm, MAILBOX_CMD_CQC, (u64)qp->cqc, qp_index, 0, 0);
	if (ret)
		goto err_with_shared_mem;

	write_lock(&qm->qps_lock);
	qm->qp_array[qp_index] = qp;
	init_completion(&qp->completion);
	write_unlock(&qm->qps_lock);

	return qp_index;

err_with_shared_mem:
	uacce_free_shared_mem(qp->sm);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start_qp);

void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct qm_info *qm = qp->qm;
	int qid = qp->queue_id;

	write_lock(&qm->qps_lock);
	qm->qp_array[qp->queue_id] = NULL;
	write_unlock(&qm->qps_lock);

	uacce_free_shared_mem(qp->sm);
	kfree(qp);
	bitmap_clear(qm->qp_bitmap, qid, 1);
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

	if (sqe == NULL)
		return -1;

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

#ifdef CONFIG_UACCE
static void qm_qp_event_notifier(struct hisi_qp *qp)
{
	uacce_wake_up(qp->uacce_q);
}

static int hisi_qm_get_queue(struct uacce *uacce, unsigned long arg,
			     struct uacce_queue **q)
{
	struct qm_info *qm = uacce->priv;
	struct hisi_qp *qp = NULL;
	struct uacce_queue *wd_q;
	u8 alg_type = 0; /* fix me here */
	//int pasid = arg; fixme: set it into device
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

	ret = hisi_qm_start_qp(qp, arg);
	if (ret < 0)
		goto err_with_wd_q;

	return ret;

err_with_wd_q:
	kfree(wd_q);
err_with_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_qm_put_queue(struct uacce_queue *q)
{
	struct hisi_qp *qp = q->priv;

	/* need to stop hardware, but can not support in v1 */
	hisi_qm_release_qp(qp);
	kfree(q);
}

/* map sq/cq/doorbell to user space */
static int hisi_qm_mmap(struct uacce_queue *q,
			struct vm_area_struct *vma)
{
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct qm_info *qm = qp->qm;
	size_t sz = vma->vm_end - vma->vm_start;
	u8 region;

	region = vma->vm_pgoff;

	switch (region) {
	case 0:
		if (sz > PAGE_SIZE)
			return -EINVAL;

		vma->vm_flags |= VM_IO;
		/*
		 * Warning: This is not safe as multiple queues use the same
		 * doorbell, v1 hardware interface problem. v2 will fix it
		 */
		return remap_pfn_range(vma, vma->vm_start,
				       qm->phys_base >> PAGE_SHIFT,
				       sz, pgprot_noncached(vma->vm_page_prot));
	case 1:
		return uacce_mmap_shared_mem(qp->sm, vma);

	default:
		return -EINVAL;
	}
}

static const struct uacce_ops uacce_qm_ops = {
	.get_queue = hisi_qm_get_queue,
	.put_queue = hisi_qm_put_queue,
	.mmap = hisi_qm_mmap,
};

static int qm_register_uacce(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct uacce *uacce = &qm->uacce;

	/* fime me */
	uacce->iommu_type = 0;
#ifdef CONFIG_IOMMU_SVA
	/* fixe me */
	uacce->dma_flag = 0;
#else
	/* fixe me */
	uacce->dma_flag = 0;
#endif
	uacce->owner = THIS_MODULE;
	uacce->name = qm->dev_name;
	uacce->dev = &pdev->dev;
	uacce->is_vf = pdev->is_virtfn;
	uacce->priv = qm;
	uacce->api_ver = "hisi_qm_v1";
	uacce->flags = 0;
	uacce->io_nr_pages = (4096 + (qm->sqe_size + sizeof(struct cqe)) *
					QM_Q_DEPTH) >> PAGE_SHIFT;
	uacce->ops = &uacce_qm_ops;

	return uacce_register(uacce);
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

	qm->dev_name = dev_name;
	qm->phys_base = pci_resource_start(pdev, 2);
	qm->size = pci_resource_len(qm->pdev, 2);
	qm->io_base = devm_ioremap(&pdev->dev, qm->phys_base, qm->size);
	if (!qm->io_base) {
		ret = -EIO;
		goto err_with_mem_regions;
	}

	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	pci_set_master(pdev);

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (ret < 0) {
		dev_err(&pdev->dev, "Enable MSI vectors fail!\n");
		goto err_with_mem_regions;
	}

	qm->eq_head = 0;
	mutex_init(&qm->mailbox_lock);
	rwlock_init(&qm->qps_lock);

	if (qm->ver)
		qm->ops = &qm_hw_ops_v1;

	ret = uacce_set_iommu_domain(&pdev->dev);
	if (ret)
		goto err_with_irq;

	return 0;

err_with_irq:
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

	uacce_unset_iommu_domain(&pdev->dev);
	pci_free_irq_vectors(pdev);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}
EXPORT_SYMBOL_GPL(hisi_qm_uninit);

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

int hisi_qm_start(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	int ret;
	size_t smem_sz =
		max_t(size_t, sizeof(struct eqc), sizeof(struct aeqc)) +
		sizeof(struct eqe) * QM_Q_DEPTH +
		sizeof(struct sqc) * qm->qp_num +
		sizeof(struct cqc) * qm->qp_num;

	if (qm->pdev->is_physfn)
		qm->ops->vft_config(qm, qm->qp_base, qm->qp_num);

	qm->sm = uacce_alloc_shared_mem(dev, smem_sz, IOMMU_READ | IOMMU_WRITE);
	if (PTR_ERR_OR_ZERO(qm->sm))
		return -ENOMEM;

	/* todo: make sure the alignment is right */
	qm->eqc = qm->sm->va;
	qm->eqe = (void *)qm->eqc +
		max_t(size_t, sizeof(struct eqc), sizeof(struct aeqc));
	qm->sqc = (void *)qm->eqe + sizeof(struct eqe) * QM_Q_DEPTH;
	qm->cqc = (void *)qm->sqc + sizeof(struct cqc) * qm->qp_num;

	qm->eqc->base_l = lower_32_bits((unsigned long)qm->eqe);
	qm->eqc->base_h = upper_32_bits((unsigned long)qm->eqe);
	qm->eqc->dw3 = 2 << MB_EQC_EQE_SHIFT;
	qm->eqc->dw6 = (QM_Q_DEPTH - 1) | (1 << MB_EQC_PHASE_SHIFT);
	ret = qm_mb(qm, MAILBOX_CMD_EQC, (u64)qm->eqc, 0, 0, 0);
	if (ret)
		goto err_with_smem;

	qm->qp_bitmap = kcalloc(BITS_TO_LONGS(qm->qp_num), sizeof(long),
				GFP_KERNEL);
	if (!qm->qp_bitmap)
		goto err_with_smem;

	qm->qp_array = kcalloc(qm->qp_num, sizeof(struct hisi_qp *),
			       GFP_KERNEL);
	if (!qm->qp_array)
		goto err_with_bitmap;

	if (qm_mb(qm, MAILBOX_CMD_SQC_BT, (u64)qm->sqc, 0, 0, 0))
		goto err_with_qp_array;

	if (qm_mb(qm, MAILBOX_CMD_CQC_BT, (u64)qm->cqc, 0, 0, 0))
		goto err_with_qp_array;

	ret = request_threaded_irq(pci_irq_vector(pdev, 0), qm_irq,
				   qm_irq_thread, IRQF_SHARED, qm->dev_name,
				   qm);
	if (ret)
		goto err_with_qp_array;

#ifdef CONFIG_UACCE
	ret = qm_register_uacce(qm);
	if (ret) {
		free_irq(pci_irq_vector(pdev, 0), qm);
		goto err_with_qp_array;
	}
#endif

	writel(0x0, QM_ADDR(qm, QM_VF_EQ_INT_MASK));

	return 0;

err_with_qp_array:
	kfree(qm->qp_array);
err_with_bitmap:
	kfree(qm->qp_bitmap);
err_with_smem:
	uacce_free_shared_mem(qm->sm);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start);

void hisi_qm_stop(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;

#ifdef CONFIG_UACCE
	uacce_unregister(&qm->uacce);
#endif

	free_irq(pci_irq_vector(pdev, 0), qm);
	kfree(qm->qp_array);
	kfree(qm->qp_bitmap);
	uacce_free_shared_mem(qm->sm);
}
EXPORT_SYMBOL_GPL(hisi_qm_stop);

/* put qm into init state, so the acce config become available */
int hisi_qm_mem_start(struct qm_info *qm)
{
	u32 val;

	qm_writel(qm, 0x1, QM_MEM_START_INIT);
	return readl_relaxed_poll_timeout(QM_ADDR(qm, QM_MEM_INIT_DONE), val,
					  val & BIT(0), 10, 1000);
}
EXPORT_SYMBOL_GPL(hisi_qm_mem_start);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
