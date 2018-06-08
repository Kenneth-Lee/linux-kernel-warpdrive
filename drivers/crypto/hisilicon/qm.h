/*
 * Copyright (c) 2018 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef HISI_ACC_QM_H
#define HISI_ACC_QM_H

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/iopoll.h>
#include <linux/dmapool.h>

#define QM_CQE_SIZE			16
#define QM_Q_DEPTH			1024

enum hw_version {
	ES = 0,
	CS,
};
enum acc_dev {
	ZIP = 1,
	HPRE,
	SEC,
	RDE,
};
enum queue_type {
	CRYPTO_QUEUE = 0,
	WD_QUEUE,
};

struct hisi_acc_qp {
	/* sq number in this function */
	u32 queue_id;
	u32 alg_type;

	void *sq_base;
	dma_addr_t sq_base_dma;
	struct cqe *cq_base;
	dma_addr_t cq_base_dma;

	struct sqc *sqc;
	dma_addr_t sqc_dma;
	struct cqc *cqc;
	dma_addr_t cqc_dma;

	u32 sq_tail;
	u32 cq_head;

	u32 sqe_size;

	enum queue_type type;

	struct qm_info *parent;
	struct device *p_dev;

	int (*sqe_handler)(struct hisi_acc_qp *qp, void *sqe);
};
extern u32 hisi_acc_get_irq_source(struct qm_info *qm);
extern irqreturn_t hacc_irq_thread(int irq, void *data);

extern int hisi_acc_init_qm_mem(struct qm_info *qm);
extern void hisi_acc_set_user_domain(struct qm_info *qm, enum acc_dev dev);
extern void hisi_acc_set_cache(struct qm_info *qm, enum acc_dev dev);
extern int hisi_acc_qm_info_create(struct device *dev, void __iomem *base,
				   u32 number, enum hw_version hw_v,
				   struct qm_info **res);
extern int hisi_acc_qm_info_create_eq(struct qm_info *qm);
extern int hisi_acc_get_vft_info(struct qm_info *qm, u32 *base, u32 *number);
extern int hisi_acc_qm_info_vft_config(struct qm_info *qm, u32 base,
				       u32 number);
extern int hisi_acc_qm_info_add_queue(struct qm_info *qm, u32 base, u32 number);
extern void hisi_acc_qm_info_release(struct qm_info *qm);
extern void hisi_acc_qm_set_priv(struct qm_info *qm, void *priv);
extern void *hisi_acc_qm_get_priv(struct qm_info *qm);
extern int hisi_acc_create_qp(struct qm_info *qm, struct hisi_acc_qp **res,
			      u32 sqe_size, u8 alg_type);
extern int hisi_acc_release_qp(struct hisi_acc_qp *qp);
extern int hisi_acc_get_pasid(struct hisi_acc_qp *qp, u16 *pasid);
extern int hisi_acc_set_pasid(struct hisi_acc_qp *qp, u16 pasid);
extern int hisi_acc_unset_pasid(struct hisi_acc_qp *qp);
extern u16 hisi_acc_get_sq_tail(struct hisi_acc_qp *qp);
extern int hisi_acc_send(struct hisi_acc_qp *qp, u16 sq_tail, void *priv);
extern int hisi_acc_receive(struct hisi_acc_qp *qp, void *priv);

/* helper function to debug */
extern void hisi_acc_qm_read_sqc(struct hisi_acc_qp *qp);

#endif
