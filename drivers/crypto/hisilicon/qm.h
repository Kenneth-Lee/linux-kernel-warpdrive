/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_ACC_QM_H
#define HISI_ACC_QM_H

#include <linux/dmapool.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>

#define QM_CQE_SIZE			16
/* default queue depth for sq/cq/eq */
#define QM_Q_DEPTH			1024

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

#define QP_SQE_ADDR(qp) ((qp)->scqe.addr)

struct qm_dma_buffer {
	int size;
	void *addr;
	dma_addr_t dma;
};

struct qm_info {
	int ver;
	const char *dev_name;
	struct pci_dev *pdev;

	resource_size_t phys_base;
	resource_size_t size;
	void __iomem *io_base;

	u32 sqe_size;
	u32 qp_base;
	u32 qp_num;

	struct qm_dma_buffer sqc, cqc, eqc, eqe;

	u32 eq_head;

	rwlock_t qps_lock;
	unsigned long *qp_bitmap;
	struct hisi_qp **qp_array;

	struct mutex mailbox_lock;

	struct hisi_acc_qm_hw_ops *ops;

};
#define QM_ADDR(qm, off) ((qm)->io_base + off)

struct hisi_acc_qp_status {
	u16 sq_tail;
	u16 sq_head;
	u16 cq_head;
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

	struct qm_dma_buffer sqc, cqc;
	struct qm_dma_buffer scqe;

	struct hisi_acc_qp_status qp_status;

	struct qm_info *qm;

	/* for crypto sync API */
	struct completion completion;

	struct hisi_qp_ops *hw_ops;
	void *qp_ctx;
	void (*event_cb)(struct hisi_qp *qp);
	void (*req_cb)(struct hisi_qp *qp, void *data);
};

extern int hisi_qm_init(const char *dev_name, struct qm_info *qm);
extern void hisi_qm_uninit(struct qm_info *qm);
extern int hisi_qm_start(struct qm_info *qm);
extern void hisi_qm_stop(struct qm_info *qm);
extern int hisi_qm_mem_start(struct qm_info *qm);
extern struct hisi_qp *hisi_qm_create_qp(struct qm_info *qm, u8 alg_type);
extern int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg);
extern void hisi_qm_release_qp(struct hisi_qp *qp);
extern int hisi_qp_send(struct hisi_qp *qp, void *msg);
#endif
