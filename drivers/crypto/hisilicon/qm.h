/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_ACC_QM_H
#define HISI_ACC_QM_H

#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include "qm_usr_if.h"

#ifdef CONFIG_CRYPTO_QM_UACCE
#include <linux/uacce.h>
#endif

/* qm user domain */
#define QM_ARUSER_M_CFG_1		0x100088
#define QM_ARUSER_M_CFG_ENABLE		0x100090
#define QM_AWUSER_M_CFG_1		0x100098
#define QM_AWUSER_M_CFG_ENABLE		0x1000a0
#define QM_WUSER_M_CFG_ENABLE		0x1000a8

/* qm cache */
#define QM_CACHE_CTL			0x100050
#define QM_AXI_M_CFG			0x1000ac
#define QM_AXI_M_CFG_ENABLE		0x1000b0
#define QM_PEH_AXUSER_CFG		0x1000cc
#define QM_PEH_AXUSER_CFG_ENABLE	0x1000d0

struct eqe {
	__le32 dw0;
};

struct aeqe {
	__le32 dw0;
};

struct sqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le16 qes;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11;
	__le16 cq_num;
	__le16 w13;
	__le32 rsvd1;
};

struct cqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le16 qes;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11;
	__le32 dw6;
	__le32 rsvd1;
};

#define INIT_QC(qc, base) do { \
	(qc)->head = 0; \
	(qc)->tail = 0; \
	(qc)->base_l = lower_32_bits((unsigned long)base); \
	(qc)->base_h = upper_32_bits((unsigned long)base); \
	(qc)->pasid = 0; \
	(qc)->w11 = 0; \
	(qc)->rsvd1 = 0; \
	(qc)->qes = QM_Q_DEPTH - 1; \
} while (0)

struct eqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le32 rsvd[2];
	__le32 dw6;
};

struct aeqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 rsvd[3];
	__le32 dw6;
};

struct mailbox {
	__le16 w0;
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

struct qm_dma {
	void *va;
	dma_addr_t dma;
	size_t size;
};

struct qm_info {
	int ver;
	struct pci_dev *pdev;

	resource_size_t phys_base;
	resource_size_t size;
	void __iomem *io_base;

	u32 sqe_size;
	u32 qp_base;
	u32 qp_num;

	struct qm_dma qdma;
	struct sqc *sqc;
	struct cqc *cqc;
	struct eqc *eqc;
	struct eqe *eqe;
	struct aeqc *aeqc;
	struct aeqe *aeqe;
	unsigned long sqc_dma,
		      cqc_dma,
		      eqc_dma,
		      eqe_dma,
		      aeqc_dma,
		      aeqe_dma;

	u32 eq_head;

	rwlock_t qps_lock;
	unsigned long *qp_bitmap;
	struct hisi_qp **qp_array;

	struct mutex mailbox_lock;

	struct hisi_acc_qm_hw_ops *ops;

	int uacce_mode;
	const char *algs;

#ifdef CONFIG_CRYPTO_QM_UACCE
	struct uacce uacce;
#endif
};
#define QM_ADDR(qm, off) ((qm)->io_base + off)

struct hisi_acc_qp_status {
	u16 sq_tail;
	u16 sq_head;
	u16 cq_head;
	u16 sqn;
	bool cqc_phase;
	int is_sq_full;
};

struct hisi_qp;

struct hisi_qp_ops {
	int (*fill_sqe)(void *sqe, void *q_parm, void *d_parm);
};

struct hisi_qp {
	/* sq number in this function */
	u32 queue_id;
	u8 alg_type;
	u8 req_type;
	int pasid;

	struct qm_dma qdma;
	struct sqc *sqc;
	struct cqc *cqc;
	void *sqe;
	struct cqe *cqe;

	unsigned long sqc_dma,
		      cqc_dma,
		      sqe_dma,
		      cqe_dma;

	struct hisi_acc_qp_status qp_status;

	struct qm_info *qm;

#ifdef CONFIG_CRYPTO_QM_UACCE
	struct uacce_queue *uacce_q;
#endif

	/* for crypto sync API */
	struct completion completion;

	struct hisi_qp_ops *hw_ops;
	void *qp_ctx;
	void (*event_cb)(struct hisi_qp *qp);
	void (*req_cb)(struct hisi_qp *qp, unsigned long data);
};

/* QM external interface for accelerator driver.
 * To use qm:
 * 1. Set qm with pdev, uacce_mode, and sqe_size set accordingly
 * 2. hisi_qm_init()
 * 3. config the accelerator hardware
 * 4. hisi_qm_start()
 */
extern int hisi_qm_init(struct qm_info *qm);
extern void hisi_qm_uninit(struct qm_info *qm);
extern int hisi_qm_start(struct qm_info *qm);
extern void hisi_qm_stop(struct qm_info *qm);
extern struct hisi_qp *hisi_qm_create_qp(struct qm_info *qm, u8 alg_type);
extern int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg);
extern void hisi_qm_release_qp(struct hisi_qp *qp);
extern int hisi_qp_send(struct hisi_qp *qp, void *msg);
#endif
