/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_ACC_QM_H
#define HISI_ACC_QM_H

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/iopoll.h>
#include <linux/dmapool.h>
#include <linux/pci.h>

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
#include <linux/vfio_spimdev.h>
#endif

#define QM_CQE_SIZE			16
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

/* fix me: temporary move here */
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

	struct qm_dma_buffer sqc, cqc, eqc, eqe, aeqc, aeqe;

	u32 eq_head;

	rwlock_t qps_lock;
	unsigned long *qp_bitmap;
	struct hisi_qp **qp_array;

	bool qpn_fixed;

	struct mutex mailbox_lock;

	struct hisi_acc_qm_hw_ops *ops;

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	struct vfio_spimdev spimdev;
	const struct attribute_group **mdev_dev_groups;
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

	struct qm_dma_buffer sqc, cqc; /* qc, taken from pm */
	struct qm_dma_buffer scqe; /* submit/complete qe, allocated for qp */

	struct hisi_acc_qp_status qp_status;

	struct qm_info *qm;
	struct vfio_spimdev_queue *spimdev_q;

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

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
extern int hisi_qm_register_spimdev(struct qm_info *qm, const char *api_ver);
extern void hisi_qm_deregister_spimdev(struct qm_info *qm);
#endif

#define QM_ASSERT(cond)

#endif
