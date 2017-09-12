/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/irqreturn.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

#include "../wd/wd_usr_if.h"
#include "../wd/wd_cipher_usr_if.h"
#include "../wd/wd.h"
#include "hisi_sec_drv_if.h"
#include "hisi_sec_drv_v1.h"

static int sec_num;

//todo: static table should not be a good way to manage
static struct wd_dev *sec_devices[HISI_MAX_SEC_DEVICES];

/* Status of devices/queues under SEC drv */
enum _queue_status {
	WDQ_STATE_IDLE,
	WDQ_STATE_INITED,
	WDQ_STATE_USING,
	WDQ_STATE_SCHED,
};

/* This is inner data of SEC, please don't care */
struct _sec_wd_capa {
	__u8 ver;
	__u8 alg_type;
	wd_throughput_level_t throughput_level;
	wd_latency_level_t latency_level;
	__u32 flags;
	const char *alg_name;
	void *priv;
};

#define SEC_ALG_FLAGS	WD_CAPA_SGL

#define SEC_CALG_PARAM(key, iv, name) 			    \
	static struct wd_calg_param sec_##name##_param = { \
		.key_size = key,				    \
		.iv_size = iv,				    \
	}

#define SEC_AALG_PARAM(key, mac, min, max, inc, name)       \
	static struct wd_aalg_param sec_##name##_param = { \
		.key_size = key,				\
		.mac_size = mac,				\
		.aad_ssize = {				\
			.min_size = min, 			\
			.max_ssize = max, 			\
			.inc_ssize = inc,			\
		}, 					\
	}

#define SEC_CAPA(atype, thrghpt, latency, name)	\
	static const struct _sec_wd_capa sec_##name##_capa = {\
		.ver = WD_VER,				\
		.alg_type = atype,				\
		.throughput_level = thrghpt,			\
		.latency_level = latency,			\
		.flags = SEC_ALG_FLAGS, 			\
		.alg_name = name, 			\
		.priv = &sec_##name##_param,		\
	}

SEC_CALG_PARAM(16, 16, cbc_aes_128);
SEC_CAPA(WD_AT_CY_SYM,  10, 10, cbc_aes_128);
SEC_CALG_PARAM(24, 16, cbc_aes_192);
SEC_CAPA(WD_AT_CY_SYM,  10, 10, cbc_aes_192);
SEC_CALG_PARAM(32, 16, cbc_aes_256);
SEC_CAPA(WD_AT_CY_SYM,  10, 10, cbc_aes_256);

SEC_CALG_PARAM(16, 16, ctr_aes_128);
SEC_CAPA(WD_AT_CY_SYM, 10, 10, ctr_aes_128);
SEC_CALG_PARAM(24, 16, ctr_aes_192);
SEC_CAPA(WD_AT_CY_SYM, 10, 10, ctr_aes_192);
SEC_CALG_PARAM(32, 16, ctr_aes_256);
SEC_CAPA(WD_AT_CY_SYM, 10, 10, ctr_aes_256);

SEC_CALG_PARAM(16, 16, ecb_aes_128);
SEC_CAPA(WD_AT_CY_SYM,  10, 10, ecb_aes_128);
SEC_CALG_PARAM(24, 16, ecb_aes_192);
SEC_CAPA(WD_AT_CY_SYM,  10, 10, ecb_aes_192);
SEC_CALG_PARAM(32, 16, ecb_aes_256);
SEC_CAPA(WD_AT_CY_SYM,  10, 10, ecb_aes_256);

static const struct _sec_wd_capa  *sec_sym_capa_tbl[] = {
	&sec_cbc_aes_128_capa,
	&sec_cbc_aes_192_capa,
	&sec_cbc_aes_256_capa,
	&sec_ctr_aes_128_capa,
	&sec_ctr_aes_192_capa,
	&sec_ctr_aes_256_capa,
	&sec_ecb_aes_128_capa,
	&sec_ecb_aes_192_capa,
	&sec_ecb_aes_256_capa,
	/* To be extended */
};

SEC_AALG_PARAM(-1, 16, -1, -1, -1, md5);
SEC_CAPA(WD_AT_CY_AUTH,  10, 10, md5);
SEC_AALG_PARAM(-1, 20, -1, -1, -1, sha160);
SEC_CAPA(WD_AT_CY_AUTH,  10, 10, sha160);
SEC_AALG_PARAM(-1, 28, -1, -1, -1, sha224);
SEC_CAPA(WD_AT_CY_AUTH,  10, 10, sha224);
SEC_AALG_PARAM(-1, 32, -1, -1, -1, sha256);
SEC_CAPA(WD_AT_CY_AUTH,  10, 10, sha256);
static const struct _sec_wd_capa *sec_dgst_capa_tbl[] = {
	&sec_md5_capa,
	&sec_sha160_capa,
	&sec_sha224_capa,
	&sec_sha256_capa,
	/* To be extended */
};

#define SEC_CAPA_NUM (ARRAY_SIZE(sec_dgst_capa_tbl) + \
			ARRAY_SIZE(sec_sym_capa_tbl))
static void hisi_sec_queue_free_ring_pages(struct wd_queue *queue);
static int hisi_sec_queue_abnrml_int_mask_set(struct wd_queue *queue,
						u32 mask);
static void hisi_sec_unmap_io(struct wd_dev *dev);
extern void sec_alg_callback(void *resp);
extern int hisi_sec_algs_register(void);
extern void hisi_sec_algs_unregister(void);

static int hisi_sec_queue_map_io(struct wd_queue *sec_queue)
{
	Q_IO_ADDR(sec_queue, 0) = ioremap(Q_IO_PADDR(sec_queue, 0),
				Q_IO_SIZE(sec_queue, 0));
	if (!Q_IO_ADDR(sec_queue, 0))
		return -ENOMEM;

	return 0;
}

static int hisi_sec_queue_ar_pkgattr_set(struct wd_queue *queue,
						u32 ar_pkg)
{
	U_SEC_Q_ARUSER_CFG sec_queue_ar_cfg;
	void *base = Q_IO_ADDR(queue, 0);

	sec_queue_ar_cfg.u32 = readl_relaxed(base + HISI_SEC_Q_ARUSER_CFG_REG);
	sec_queue_ar_cfg.bits.ar_pkg = ar_pkg;
	writel_relaxed(sec_queue_ar_cfg.u32, base + HISI_SEC_Q_ARUSER_CFG_REG);

	return 0;
}

static int hisi_sec_queue_aw_pkgattr_set(struct wd_queue *queue,
							u32 aw_pkg)
{
	U_SEC_Q_AWUSER_CFG sec_queue_aw_cfg;
	void *base;

	base = Q_IO_ADDR(queue, 0);
	sec_queue_aw_cfg.u32 = readl_relaxed(base + HISI_SEC_Q_AWUSER_CFG_REG);
	sec_queue_aw_cfg.bits.aw_pkg = aw_pkg;
	writel_relaxed(sec_queue_aw_cfg.u32, base + HISI_SEC_Q_AWUSER_CFG_REG);

	return 0;
}

static int hisi_sec_set_clk(struct wd_dev *sec, u32 en)
{
	u32 cnt = 10;
	u32 i = 0;
	u32 var;
	void *base;
	struct device *dev = sec->dev;

	base = DEV_IO_ADDR(sec, 0);
	if (en) {
		while (1) {
			writel_relaxed(0x7,  base + HISI_SEC_CLK_EN);
			mdelay(1);
			var = readl_relaxed(base + HISI_SEC_CLK_ST) & 0x7;
			if (0x7 == var)
				return 0;
			i++;
			if (i > cnt) {
				dev_err(dev, "sec clock enable fail!\n");
				return -EIO;
			}
		}
	} else {
		while (1) {
			writel_relaxed(0x7, base + HISI_SEC_CLK_DIS);
			mdelay(1);
			var = readl_relaxed(base + HISI_SEC_CLK_ST) & 0x7;
			if (0 == var)
				return 0;
			i++;
			if (i > cnt) {
				dev_err(dev, "sec clock disable fail!\n");
				return -EIO;
			}
		}
	}

	return 0;
}

static int hisi_sec_reset_whole_module(struct wd_dev *sec)
{
	u32 cnt = 10;
	u32 i = 0;
	void *base = DEV_IO_ADDR(sec, 0);
	struct device *dev  = sec->dev;

	while (1) {
		writel_relaxed(1, base + HISI_SEC_RST_REQ);
		writel_relaxed(1, base + HISI_SEC_BUILD_RST_REQ);
		mdelay(1);
		if ((SEC_RESET_ST == (readl_relaxed(base + HISI_SEC_RESET_ST) &
			0x1)) && (SEC_RESET_ST == (readl_relaxed(base +
			HISI_SEC_BUILD_RESET_ST) & 0x1)))

			break;
		i++;
		if (i > cnt) {
			dev_err(dev, "sec reset req fail!\n");
			return -EIO;
		}
	}

	cnt = 10;
	i = 0;
	while (1) {
		writel_relaxed(1, base + HISI_SEC_RESET_DREQ);
		writel_relaxed(1, base + HISI_SEC_BUILD_RESET_DREQ);
		mdelay(1);
		if ((SEC_NOT_RESET_ST == (readl_relaxed(base + HISI_SEC_RESET_ST) &
			0x1)) && (SEC_NOT_RESET_ST == (readl_relaxed(base +
			HISI_SEC_BUILD_RESET_ST) & 0x1)))

			break;

		i++;
		if (i > cnt) {
			dev_err(dev, "sec reset dreq fail!\n");
			return -EIO;
		}
	}

	return 0;
}

static int hisi_sec_saa_clk_en(struct wd_dev *dev, u32 saa_mask)
{
	u32 saa_clk_en;

	saa_clk_en = readl_relaxed(DEV_IO_ADDR(dev, 1) + HISI_SEC_CLK_EN_REG);
	saa_clk_en |= (saa_mask & 0x3FFUL);
	writel_relaxed(saa_clk_en, DEV_IO_ADDR(dev, 1) + HISI_SEC_CLK_EN_REG);

	return 0;
}

static int hisi_sec_bd_endian_set(struct wd_dev *dev, u32 endian)
{
	union sec_control2_info sec_ctrl2;
	void *base = DEV_IO_ADDR(dev, 1);

	sec_ctrl2.u32 = readl_relaxed(base + HISI_SEC_CONTROL_2_REG);
	sec_ctrl2.bits.sec_endian_bd = endian;
	writel_relaxed(sec_ctrl2.u32, base + HISI_SEC_CONTROL_2_REG);

	return 0;
}

static int hisi_sec_bd_endian_type_set(struct wd_dev *dev,
					u32 endian_type)
{
	union sec_control2_info sec_ctrl2;
	void *base = DEV_IO_ADDR(dev, 1);

	sec_ctrl2.u32 = readl_relaxed(base + HISI_SEC_CONTROL_2_REG);
	sec_ctrl2.bits.sec_endian_bd_type = endian_type;
	writel_relaxed(sec_ctrl2.u32, base + HISI_SEC_CONTROL_2_REG);

	return 0;
}

static int hisi_sec_cache_config_set(struct wd_dev *dev)
{
#if defined(CONFIG_ARM_SMMU_V3)
	writel_relaxed(0x44cf9e, DEV_IO_ADDR(dev, 1) + HISI_SEC_CONTROL_REG);
#else
	writel_relaxed(0x4cfd9, DEV_IO_ADDR(dev, 1) + HISI_SEC_CONTROL_REG);
#endif
	return 0;
}

static int hisi_sec_data_axiwr_otsd_cfg(struct wd_dev *dev, u32 cfg)
{
	union sec_control2_info sec_ctrl2;
	void *base = DEV_IO_ADDR(dev, 1);

	sec_ctrl2.u32 = readl_relaxed(base + HISI_SEC_CONTROL_2_REG);
	sec_ctrl2.bits.data_axi_wr_otsd_config = cfg;
	writel_relaxed(sec_ctrl2.u32, base + HISI_SEC_CONTROL_2_REG);

	return 0;
}

static int hisi_sec_data_axird_otsd_cfg(struct wd_dev *dev, u32 cfg)
{
	union sec_control2_info sec_ctrl2;
	void *base = DEV_IO_ADDR(dev, 1);

	sec_ctrl2.u32 = readl_relaxed(base + HISI_SEC_CONTROL_2_REG);
	sec_ctrl2.bits.data_axi_rd_otsd_config = cfg;
	writel_relaxed(sec_ctrl2.u32, base + HISI_SEC_CONTROL_2_REG);

	return 0;
}

static int hisi_sec_clk_gate_en(struct wd_dev *dev, u32 clkgate)
{
	union sec_control2_info sec_ctrl2;
	void *base = DEV_IO_ADDR(dev, 1);

	sec_ctrl2.u32 = readl_relaxed(base + HISI_SEC_CONTROL_2_REG);
	sec_ctrl2.bits.clk_gate_enable = clkgate;
	writel_relaxed(sec_ctrl2.u32, base + HISI_SEC_CONTROL_2_REG);

	return 0;
}

static int hisi_sec_comm_cnt_cfg(struct wd_dev *dev, u32 clr_ce)
{
	union sec_common_cnt_info sec_common_cntclrce;
	void *base = DEV_IO_ADDR(dev, 1);

	sec_common_cntclrce.u32 =
		readl_relaxed(base + HISI_SEC_COMMON_CNT_CLR_CE_REG);
	sec_common_cntclrce.bits.cnt_clr_ce = clr_ce;
	writel_relaxed(sec_common_cntclrce.u32,
			     base + HISI_SEC_COMMON_CNT_CLR_CE_REG);

	return 0;
}

static int hisi_sec_commsnap_en(struct wd_dev *dev, u32 snap_en)
{
	union sec_common_cnt_info sec_common_cntclrce;

	sec_common_cntclrce.u32 = readl_relaxed(DEV_IO_ADDR(dev, 1) +
		HISI_SEC_COMMON_CNT_CLR_CE_REG);
	sec_common_cntclrce.bits.snap_en = snap_en;
	writel_relaxed(sec_common_cntclrce.u32, DEV_IO_ADDR(dev, 1) +
		HISI_SEC_COMMON_CNT_CLR_CE_REG);

	return 0;
}

static int hisi_sec_fsm_maxcnt_set(struct wd_dev *dev, u32 cnt)
{
	writel_relaxed(cnt, DEV_IO_ADDR(dev, 1) +
		HISI_SEC_FSM_MAX_CNT_REG);

	return 0;
}

static int hisi_sec_ipv6_hashmask_set(struct wd_dev *dev, u32 hash_mask[])
{
	void *base = DEV_IO_ADDR(dev, 1);

	writel_relaxed(hash_mask[0], base + HISI_SEC_IPV6_MASK_TABLE_0_REG);
	writel_relaxed(hash_mask[1], base + HISI_SEC_IPV6_MASK_TABLE_1_REG);
	writel_relaxed(hash_mask[2], base + HISI_SEC_IPV6_MASK_TABLE_2_REG);
	writel_relaxed(hash_mask[3], base + HISI_SEC_IPV6_MASK_TABLE_3_REG);
	writel_relaxed(hash_mask[4], base + HISI_SEC_IPV6_MASK_TABLE_4_REG);
	writel_relaxed(hash_mask[5], base + HISI_SEC_IPV6_MASK_TABLE_5_REG);
	writel_relaxed(hash_mask[6], base + HISI_SEC_IPV6_MASK_TABLE_6_REG);
	writel_relaxed(hash_mask[7], base + HISI_SEC_IPV6_MASK_TABLE_7_REG);
	writel_relaxed(hash_mask[8], base + HISI_SEC_IPV6_MASK_TABLE_8_REG);
	writel_relaxed(hash_mask[9], base + HISI_SEC_IPV6_MASK_TABLE_9_REG);

	return 0;
}

static int hisi_sec_ipv4_hashmask_set(struct wd_dev *dev, u32 hash_mask)
{
	if (hash_mask & HISI_SEC_HASH_IPV4_MASK) {
		dev_err(dev->dev,
			"Sec Ipv4 Hash Mask Input Error!\n ");
		return -EINVAL;
	}

	writel_relaxed(hash_mask, DEV_IO_ADDR(dev, 1) +
			HISI_SEC_IPV4_MASK_TABLE_REG);

	return 0;
}

static int hisi_sec_set_dbg_bd_cfg(struct wd_dev *dev, u32 cfg)
{
	union dbg_bd_cfg sec_bd_cfg;
	void *base = DEV_IO_ADDR(dev, 1);

	sec_bd_cfg.u32 = readl_relaxed(base + HISI_SEC_DEBUG_BD_CFG_REG);
	if (cfg) {
		sec_bd_cfg.bits.back_bd_info_msk = 0;
		sec_bd_cfg.bits.back_bd_info_en = 0;
	} else {
		sec_bd_cfg.bits.back_bd_info_msk = 1;
		sec_bd_cfg.bits.back_bd_info_en = 0;
	}

	writel_relaxed(sec_bd_cfg.u32, base + HISI_SEC_DEBUG_BD_CFG_REG);

	return 0;
}

static int hisi_sec_saa_getqm_en(struct wd_dev *dev, u32 saa_indx, u32 en)
{
	union saa_control_info saa_ctrl;
	void *base = DEV_IO_ADDR(dev, 1);

	saa_ctrl.u32 = readl_relaxed(base + HISI_SEC_SAA_BASE +
		HISI_SEC_SAA_CONTROL_REG + saa_indx * HISI_SEC_SAA_ADDR_SIZE);
	saa_ctrl.bits.get_qm_en = (en & 0x1);
 	writel_relaxed(saa_ctrl.u32, base + HISI_SEC_SAA_BASE +
		HISI_SEC_SAA_CONTROL_REG  + saa_indx * HISI_SEC_SAA_ADDR_SIZE);
	return 0;
}

static int hisi_sec_saa_set_int_mask(struct wd_dev *dev,
				u32 saa_indx, u32 saa_int_mask)
{
	writel_relaxed(saa_int_mask,  DEV_IO_ADDR(dev, 1) + HISI_SEC_SAA_BASE +
		HISI_SEC_ST_INTMSK1_REG +
		saa_indx * HISI_SEC_SAA_ADDR_SIZE);

	return 0;
}
#if defined(CONFIG_ARM_SMMU_V3)
static int hisi_sec_streamid_set(struct wd_dev *dev)
{
	#define SEC_ASID	0x600
	#define SEC_VMID	0
	int i;

	for (i = 0; i < HISI_SEC_V1_Q_NUM; i++)
		writel_relaxed((SEC_VMID|((SEC_ASID & 0xffff) << 8)),
			DEV_IO_ADDR(dev, 1) +
			HISI_SEC_Q0_VMID_CFG_REG + 4 * i);

	return 0;
}

static int hisi_sec_weight_set(struct wd_dev *dev)
{
	int i;

	for (i = 0; i < HISI_SEC_V1_Q_NUM; i++)
		writel_relaxed(0x3f,  DEV_IO_ADDR(dev, 1) +
			HISI_SEC_Q0_WEIGHT_CFG_REG + 4 * i);
	return 0;
}
#endif
static int hisi_sec_queue_ar_alloc_set(struct wd_queue *queue, u32 alloc)
{
	U_SEC_Q_ARUSER_CFG sec_queue_ar_cfg;
	void *base = Q_IO_ADDR(queue, 0);

	sec_queue_ar_cfg.u32 = readl_relaxed(base + HISI_SEC_Q_ARUSER_CFG_REG);
	if (U_SEC_QUEUE_AR_FROCE_ALLOC == alloc) {
		sec_queue_ar_cfg.bits.ar_fa  = 1;
		sec_queue_ar_cfg.bits.ar_fna = 0;
	} else {
		sec_queue_ar_cfg.bits.ar_fa  = 0;
		sec_queue_ar_cfg.bits.ar_fna = 1;
	}

	writel_relaxed(sec_queue_ar_cfg.u32, base + HISI_SEC_Q_ARUSER_CFG_REG);

	return 0;
}

static int hisi_sec_queue_aw_alloc_set(struct wd_queue *queue, u32 alloc)
{
	U_SEC_Q_AWUSER_CFG sec_queue_aw_cfg;
	void *base = Q_IO_ADDR(queue, 0);

	sec_queue_aw_cfg.u32 = readl_relaxed(base + HISI_SEC_Q_AWUSER_CFG_REG);
	if (U_SEC_QUEUE_AW_FROCE_ALLOC == alloc) {
		sec_queue_aw_cfg.bits.aw_fa  = 1;
		sec_queue_aw_cfg.bits.aw_fna = 0;
	} else {
		sec_queue_aw_cfg.bits.aw_fa  = 0;
		sec_queue_aw_cfg.bits.aw_fna = 1;
	}

	writel_relaxed(sec_queue_aw_cfg.u32, base + HISI_SEC_Q_AWUSER_CFG_REG);
	return 0;
}

static void hisi_sec_queue_unmap_io(struct wd_queue *sec_queue)
{
	 iounmap(Q_IO_ADDR(sec_queue, 0));
}

static int hisi_sec_queue_enable(struct wd_queue *queue, u32 en)
{
	writel_relaxed(en, Q_IO_ADDR(queue, 0) + HISI_SEC_QUEUE_ENB_REG);
	return 0;
}

static int hisi_sec_queue_reorder_set(struct wd_queue *queue, u32 reorder)
{
	union sec_q_info sec_q_cfg;
	void *base = Q_IO_ADDR(queue, 0);

	sec_q_cfg.u32 = readl_relaxed(base + HISI_SEC_Q_CFG_REG);
	sec_q_cfg.bits.sec_q_reorder = reorder;
	writel_relaxed(sec_q_cfg.u32, base + HISI_SEC_Q_CFG_REG);

	return 0;
}
static int hisi_sec_queue_swproc_ptr_set(struct wd_queue *queue, u32 value)
{
	writel_relaxed(value, Q_IO_ADDR(queue, 0) + HISI_SEC_Q_SOFT_PROC_PTR_REG);
	return 0;
}

static int hisi_sec_queue_procnum_cfg(struct wd_queue *queue, u32 num)
{
	writel_relaxed(num, Q_IO_ADDR(queue, 0) + HISI_SEC_Q_PROC_NUM_CFG_REG);
	return 0;
}

static int hisi_sec_queue_depth_set(struct wd_queue *queue, u32 depth)
{
	union sec_depth_info sec_depth_cfg;
	void *base = Q_IO_ADDR(queue, 0);

	sec_depth_cfg.u32 = readl_relaxed(base + HISI_SEC_Q_DEPTH_CFG_REG);
	sec_depth_cfg.bits.sec_q_depth = depth;
	writel_relaxed(sec_depth_cfg.u32, base + HISI_SEC_Q_DEPTH_CFG_REG);

	return 0;
}

static int hisi_sec_queue_cmdbase_haddr_set(struct wd_queue *queue, u32 haddr)
{
	writel_relaxed(haddr, Q_IO_ADDR(queue, 0) + HISI_SEC_Q_BASE_HADDR_REG);
	return 0;
}

static int hisi_sec_queue_cmdbase_laddr_set(struct wd_queue *queue, u32 laddr)
{
	writel_relaxed(laddr, Q_IO_ADDR(queue, 0) + HISI_SEC_Q_BASE_LADDR_REG);
	return 0;
}

static int hisi_sec_queue_outorder_haddr_set(struct wd_queue *queue, u32 haddr)
{
	writel_relaxed(haddr, Q_IO_ADDR(queue, 0) +
		HISI_SEC_Q_OUTORDER_BASE_HADDR_REG);
	return 0;
}

static int hisi_sec_queue_outorder_laddr_set(struct wd_queue *queue, u32 laddr)
{
	writel_relaxed(laddr, Q_IO_ADDR(queue, 0) +
		HISI_SEC_Q_OUTORDER_BASE_ADDR_REG);
	return 0;
}

static int hisi_sec_queue_errbase_haddr_set(struct wd_queue *queue, u32 hi_addr)
{
	writel_relaxed(hi_addr, Q_IO_ADDR(queue, 0) +
		HISI_SEC_Q_ERR_BASE_HADDR_REG);
	return 0;
}

static int hisi_sec_queue_errbase_laddr_set(struct wd_queue *queue, u32 low_addr)
{
	writel_relaxed(low_addr, Q_IO_ADDR(queue, 0) +
		HISI_SEC_Q_ERR_BASE_LADDR_REG);
	return 0;
}

static int hisi_sec_queue_ovrtmth_set(struct wd_queue *queue, u32 value)
{
	writel_relaxed(value, Q_IO_ADDR(queue, 0) + HISI_SEC_Q_OT_TH_REG);
	return 0;
}

static int hisi_sec_queue_abnrml_int_mask_set(struct wd_queue *queue, u32 mask)
{
	writel_relaxed(mask, Q_IO_ADDR(queue, 0) +
			HISI_SEC_Q_FAIL_INT_MSK_REG);
	return 0;
}

static int hisi_sec_queue_proc_int_mask_set(struct wd_queue *queue, u32 mask)
{
	writel_relaxed(mask, Q_IO_ADDR(queue, 0) +
			HISI_SEC_Q_FLOW_INT_MKS_REG);
	return 0;
}

static int hisi_sec_queue_init_set(struct wd_queue *queue, u32 value)
{
	writel_relaxed(value, Q_IO_ADDR(queue, 0) + HISI_SEC_Q_INIT_REG);
	return 0;
}

#ifdef HISI_SEC_DEBUG
static int hisi_sec_qm_rd_bd_cfg(struct wd_dev *dev, int bd_index, int offset, int bit_index)
{
	__u32 var = 0;

	if (bd_index > 19 ||offset > 3 || bit_index > 3) {
		pr_err("bd index = %d offset = %d, bit_index=%derror\n", bd_index, offset, bit_index);
		return 0;
	}
	/* Which bd among 20 bd from 0 to 19 */
	var |= (bd_index << 4);

	/* which 128bits in that bd from 0-3 */
	var |= (offset << 2);

	/* which 32bits in that 128bits from 0-3 */
	var |= bit_index;
	writel_relaxed(var, DEV_IO_ADDR(dev, 1) +
		HISI_SEC_QM_BD_DFX_CFG_REG);

	udelay(100);

	var = readl_relaxed(DEV_IO_ADDR(dev, 1) +
		HISI_SEC_QM_BD_DFX_RESULT_REG);

	printk("bd index = %d offset = %d, bit_index=%d, var=0x%x\n",
		bd_index, offset, bit_index, var);

	return 0;

}

static int hisi_sec_ooo_err_stat(struct wd_dev *dev)
{
	__u32 var1, var2;
	var1 = readl_relaxed(DEV_IO_ADDR(dev, 0) +
		0x180);
	var2 = readl_relaxed(DEV_IO_ADDR(dev, 0) +
		0x184);
	printk("warning 0x%x from read chanel 0x%x from write channel\n", var1, var2);

	return 0;
}
static void hisi_sec_queue_inner_hw_buf_print(struct wd_queue *q)
{
	(void)hisi_sec_ooo_err_stat(q->dev);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 0, 0);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 0, 1);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 0, 2);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 0, 3);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 1, 0);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 1, 1);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 1, 2);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 1, 3);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 2, 0);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 2, 1);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 2, 2);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 2, 3);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 3, 0);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 3, 1);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 3, 2);
	(void)hisi_sec_qm_rd_bd_cfg(q->dev, 0, 3, 3);
}
#endif

void hisi_sec_queue_irq_disable(struct wd_queue *queue)
{
	(void)hisi_sec_queue_abnrml_int_mask_set(queue, 0xffffffff);
}

void hisi_sec_queue_irq_enable(struct wd_queue *queue)
{
	(void)hisi_sec_queue_abnrml_int_mask_set(queue, 0);
}

int hisi_sec_queue_stop(struct wd_queue *queue)
{
	disable_irq(((struct sec_queue_info*)queue->priv)->task_irq);
	hisi_sec_queue_irq_disable(queue);
	(void)hisi_sec_queue_enable(queue, 0);

	return 0;
}

int hisi_sec_queue_start(struct wd_queue *queue)
{
	(void)hisi_sec_queue_enable(queue, 0x1);
	enable_irq(((struct sec_queue_info*)queue->priv)->task_irq);
	hisi_sec_queue_irq_enable(queue);

	return 0;
}
static int _alloc_queue(struct wd_dev *sec_dev,
			const char *alg, struct wd_queue **q)
{
	struct sec_dev_info *dev_info = sec_dev->priv;
	int i;

	/* For SEC, all the queue can supply the algorithms it supports */
	(void)alg;

	spin_lock(&dev_info->dev_lock);

	/* Get the first idle queue in SEC device */
	for (i = 0; i < HISI_SEC_V1_Q_NUM; i++) {
		if (dev_info->queue[i]->status == WDQ_STATE_USING)
			continue;
		if (dev_info->queue[i]->status == WDQ_STATE_IDLE) {
			dev_info->queue[i]->status = WDQ_STATE_USING;
			spin_unlock(&dev_info->dev_lock);

			*q = dev_info->queue[i];

			return 0;
		}
	}
	spin_unlock(&dev_info->dev_lock);

	return -ENODEV;
}

static int _free_queue(struct wd_queue *q)
{
	struct wd_dev *dev = q->wdev;
	struct sec_queue_info *info = q->priv;
	struct sec_dev_info *dev_info = dev->priv;
	spinlock_t *lock = &dev_info->dev_lock;
	int i;

	if (info->queue_id > HISI_SEC_V1_Q_NUM ||
		!dev_info->queue[info->queue_id]) {
		dev_err(dev->dev, "no queue %d in %s\n",
			info->queue_id, dev_info->name);
		return -ENODEV;
	}
	if (dev_info->queue[info->queue_id]->status ==
		WDQ_STATE_IDLE)
	{
		dev_err(dev->dev, "queue %d in %s is idle\n",
			info->queue_id, dev_info->name);
		return -ENODEV;
	}
	spin_lock(lock);
	for (i = 0; i < HISI_SEC_V1_Q_NUM; i++) {
		if (q == dev_info->queue[info->queue_id]) {
			q->status = WDQ_STATE_IDLE;
			spin_unlock(lock);
			return 0;
		}

	}
	spin_unlock(lock);

	return -ENODEV;
}

static irqreturn_t sec_irq_handler(int irq, void *dev_id)
{
	struct wd_queue *q = dev_id;

	hisi_sec_queue_irq_disable(q);
	wd_wake_up(q);
	hisi_sec_queue_irq_enable(q);

	return IRQ_HANDLED;
}

static int _open_queue(struct wd_queue *q)
{
	struct wd_dev *sec = q->wdev;
	struct sec_queue_info *qinfo = q->priv;
	int ret;

	/* This is used for checking whether task is finished */
	qinfo->ring[SEC_OUTORDER_RING].write = 0;

	(void)hisi_sec_queue_enable(q, 0x1);
	irq_set_status_flags(qinfo->task_irq, IRQ_TYPE_EDGE_RISING);
	ret = request_irq(qinfo->task_irq, sec_irq_handler, 0,
			qinfo->name, q);
	if (ret) {
		dev_err(sec->dev, "request irq(%d) fail\n",
			qinfo->task_irq);
		return ret;
	}
	disable_irq(qinfo->task_irq);
	return ret;
}

static int _close_queue(struct wd_queue *q)
{
	struct sec_queue_info *qinfo = q->priv;

	(void)hisi_sec_queue_enable(q, 0x0);
	irq_clear_status_flags(qinfo->task_irq, IRQ_TYPE_EDGE_RISING);
	free_irq(qinfo->task_irq, q);

	return 0;
}

int hisi_sec_queue_pinfo_init(struct wd_queue *queue,
			struct platform_device *pdev)
{

	struct sec_queue_info *qinfo = (struct sec_queue_info *)queue->priv;

	qinfo->task_irq = platform_get_irq(pdev, qinfo->queue_id * 2 + 1);
	qinfo->err_irq = platform_get_irq(pdev, qinfo->queue_id * 2 + 2);

	return 0;
}

int hisi_sec_poll(void *queue, int flag)
{
	struct wd_queue *sec_queue = queue;
	struct sec_queue_info *info = sec_queue->priv;
	struct sec_queue_ring *msg_ring = &info->ring[SEC_CMD_RING];
	struct sec_bd_info *msg;
	int num = 0;

	msg = (struct sec_bd_info *)(msg_ring->base) + msg_ring->read;
	while (msg->done) {
		msg_ring->callback((void *)msg);
		msg->done = 0;
		msg_ring->read = readl_relaxed(Q_IO_ADDR(sec_queue, 0) +
				HISI_SEC_Q_RD_PTR_REG);
		msg = (struct sec_bd_info *)(msg_ring->base) + msg_ring->read;
		hisi_sec_queue_swproc_ptr_set(queue, msg_ring->read);
		num++;
		atomic_dec(&msg_ring->used);
		if (flag && num == flag)
			break;
	}

	return num;
}

void hisi_sec_response_handler(uintptr_t queue_addr)
{
	struct wd_queue *queue = (struct wd_queue *)queue_addr;

	hisi_sec_queue_irq_disable(queue);
	(void)hisi_sec_poll((void *)queue_addr, 0);
	hisi_sec_queue_irq_enable(queue);

}

static int hisi_sec_queue_setup_bh(struct wd_queue *queue)
{
	struct sec_queue_info *priv_data = queue->priv;

	tasklet_init(&priv_data->resp_handler, hisi_sec_response_handler,
		     (unsigned long)queue);
	return 0;
}

static irqreturn_t hisi_isr_handle(int irq, void *queue)
{
	struct wd_queue *q = queue;
	struct sec_queue_info *info = q->priv;

	tasklet_hi_schedule(&info->resp_handler);

	return IRQ_HANDLED;
}

int hisi_sec_queue_irq_init(struct wd_queue *queue)
{
	int ret, irq;
	struct wd_dev *sec = queue->wdev;
	struct sec_queue_info *qinfo = queue->priv;
	struct sec_dev_info *dinfo = sec->priv;
	unsigned int cpu, cpus = num_online_cpus();

	irq = qinfo->task_irq;
	(void)hisi_sec_queue_setup_bh(queue);
	ret = request_irq(irq, hisi_isr_handle, 0, qinfo->name, queue);
	if (ret) {
		dev_err(sec->dev, "request irq(%d) fail\n", irq);
		return ret;
	}
	disable_irq(irq);
	cpu = ((dinfo->sec_id * dinfo->queue_num) +
		qinfo->queue_id) % cpus;
	irq_set_affinity_hint(irq, get_cpu_mask(cpu));
	enable_irq(irq);

	return 0;
}

int  hisi_sec_queue_irq_uninit(struct wd_queue *queue)
{
	struct sec_queue_info *qinfo = queue->priv;

	irq_set_affinity_hint(qinfo->task_irq, NULL);
	free_irq(qinfo->task_irq, queue);

	return 0;
}

struct wd_dev *hisi_get_sec_device(int cpu)
{
	if ((cpu < sec_num) && (cpu >= 0))
		return sec_devices[cpu];
	pr_err("sec device not found for cpu %d\n", cpu);
	return NULL;
}

struct wd_queue *hisi_alloc_crypto_queue(struct wd_dev *sec)
{
	struct wd_queue *sec_queue = NULL;
	int ret;

	ret = sec->ops.get_queue(sec, NULL, &sec_queue);
	if (ret) {
		dev_err(sec->dev, "alloc sec queue fai!\n");
		return NULL;
	}
	ret = hisi_sec_queue_irq_init(sec_queue);
	if (ret) {
		dev_err(sec->dev, "sec queue irq init fai!\n");
		return NULL;
	}
	(void)sec->ops.open(sec_queue);
	hisi_sec_queue_irq_enable(sec_queue);
	return (void *)sec_queue;
}

int hisi_release_crypto_queue(struct wd_queue *sec_queue)
{
	struct wd_dev *sec = sec_queue->wdev;
	int ret = 0;
	hisi_sec_queue_irq_disable(sec_queue);
	(void)sec->ops.close(sec_queue);
	ret = hisi_sec_queue_irq_uninit(sec_queue);
	if (ret) {
		dev_err(sec->dev, "sec queue irq uninit fai!\n");
		return ret;
	}
	ret = sec->ops.put_queue(sec_queue);
	if (ret) {
		dev_err(sec->dev, "free sec queue fai!\n");
		return ret;
	}

	return 0;
}

static int hisi_sec_set_io_info(struct wd_dev *dev)
{
	u32 res_idx = 0;
	struct sec_dev_info *info = dev->priv;
	struct resource *res;
	struct platform_device *pdev = to_platform_device(HISI_SEC_DEV(dev));

	for (res_idx = 0; res_idx < HISI_SEC_V1_ADDR_REGION; res_idx ++) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, res_idx);
		if (!res) {
			dev_err(HISI_SEC_DEV(dev), "memory resource not found!\n");
			return -ENOMEM;
		}
		info->info[res_idx].addr = res->start;
		info->info[res_idx].size = resource_size(res);
	}

	return 0;
}

int hisi_sec_queue_send(void *queue, void *msg)
{
	struct wd_queue* sec_queue = queue;
	struct sec_queue_info *info = sec_queue->priv;
	struct sec_queue_ring *msg_ring = &info->ring[SEC_CMD_RING];
	void *base = Q_IO_ADDR(sec_queue, 0);

	spin_lock_bh(&msg_ring->lock);
	msg_ring->read = readl_relaxed(base + HISI_SEC_Q_RD_PTR_REG);
	msg_ring->write = readl_relaxed(base + HISI_SEC_Q_WR_PTR_REG);
	if (msg_ring->write == msg_ring->read &&
		atomic_read(&msg_ring->used) == msg_ring->depth) {
		spin_unlock_bh(&msg_ring->lock);
		return -EAGAIN;
	}
	memcpy(msg_ring->base + msg_ring->write * msg_ring->msg_size,
				msg, msg_ring->msg_size);
	msg_ring->write = (msg_ring->write + 1) % msg_ring->depth;

	wmb();
	writel_relaxed(msg_ring->write, base + HISI_SEC_Q_WR_PTR_REG);
	atomic_inc(&msg_ring->used);
	spin_unlock_bh(&msg_ring->lock);

	return 0;
}

int hisi_sec_queue_hw_init(struct wd_queue *queue)
{
	struct sec_queue_info *qinfo = queue->priv;

	(void)hisi_sec_queue_ar_alloc_set(queue, 1);
	(void)hisi_sec_queue_aw_alloc_set(queue, 1);
	(void)hisi_sec_queue_ar_pkgattr_set(queue, 1);
	(void)hisi_sec_queue_aw_pkgattr_set(queue, 1);

	/*disable reorder queue, as this is set 0*/
	(void)hisi_sec_queue_reorder_set(queue, 1);

	(void)hisi_sec_queue_procnum_cfg(queue, 1);
	(void)hisi_sec_queue_depth_set(queue, qinfo->ring[SEC_CMD_RING].depth - 1);

	(void)hisi_sec_queue_cmdbase_haddr_set(queue,
		(((u64)Q_IO_IOVA(queue, SEC_CMD_RING)) >> 32) & 0xFFFFFFFF);
	(void)hisi_sec_queue_cmdbase_laddr_set(queue,
		((u64)Q_IO_IOVA(queue, SEC_CMD_RING)) & 0xFFFFFFFF);
	(void)hisi_sec_queue_outorder_haddr_set(queue,
		(((u64)Q_IO_IOVA(queue, SEC_OUTORDER_RING)) >> 32) & 0xFFFFFFFF);
	(void)hisi_sec_queue_outorder_laddr_set(queue,
		((u64)Q_IO_IOVA(queue, SEC_OUTORDER_RING)) & 0xFFFFFFFF);
	(void)hisi_sec_queue_errbase_haddr_set(queue,
		(((u64)Q_IO_IOVA(queue, SEC_DBG_RING)) >> 32) & 0xFFFFFFFF);
	(void)hisi_sec_queue_errbase_laddr_set(queue,
		((u64)Q_IO_IOVA(queue, SEC_DBG_RING)) & 0xFFFFFFFF);

	(void)hisi_sec_queue_ovrtmth_set(queue, 0xffffffff);
	hisi_sec_queue_irq_disable(queue);
	(void)hisi_sec_queue_proc_int_mask_set(queue, 0);
	(void)hisi_sec_queue_init_set(queue, 0x3);

	/* This is used for checking whether task is finished */
	qinfo->ring[SEC_OUTORDER_RING].write = 0;

	return 0;
}

int hisi_sec_queue_hw_uninit(struct wd_queue *queue)
{
	return 0;
}

static int hisi_sec_hw_init(struct wd_dev *dev)
{
	u32 sec_ipv4_mask;
	u32 sec_ipv6_mask[10];
	u32 i,ret;

	/* enable all saa clock */
#if defined(CONFIG_ARM_SMMU_V3)
	/* only the first cluster saa is usable on */
	(void)hisi_sec_saa_clk_en(dev, 0x01f);
#else
	(void)hisi_sec_saa_clk_en(dev, 0x3ff);
#endif

	/* 32 bit little endian */
	(void)hisi_sec_bd_endian_set(dev, 0);
	(void)hisi_sec_bd_endian_type_set(dev, 0);

	/* cache cfg */
	(void)hisi_sec_cache_config_set(dev);

	/* data axi port write and read outstanding config, config as suggestion */
	(void)hisi_sec_data_axiwr_otsd_cfg(dev, 0x7);
	(void)hisi_sec_data_axird_otsd_cfg(dev, 0x7);

	/* enable clock gating */
	(void)hisi_sec_clk_gate_en(dev, 1);

	/* set CNT_CYC register not read clear */
	(void)hisi_sec_comm_cnt_cfg(dev, 0);

	/* enable CNT_CYC */
	(void)hisi_sec_commsnap_en(dev, 0);

	(void)hisi_sec_fsm_maxcnt_set(dev, 0xffffffff);

	sec_ipv4_mask = 0;
	for (i = 0; i < 10; i++)
		sec_ipv6_mask[i] = 0;

	ret = hisi_sec_ipv4_hashmask_set(dev, sec_ipv4_mask);
	if (ret)
		return -EIO;

	(void)hisi_sec_ipv6_hashmask_set(dev, sec_ipv6_mask);

	/*  not use debug bd*/
	(void)hisi_sec_set_dbg_bd_cfg(dev, 0);

#if defined(CONFIG_ARM_SMMU_V3)
	(void)hisi_sec_streamid_set(dev);
	(void)hisi_sec_weight_set(dev);
#endif
	for(i = 0; i < HISI_SEC_MAX_SAA_NUM; i++) {

		/* all saa enable */
		(void)hisi_sec_saa_getqm_en(dev, i, 1);

		/* all saa interrupt not mask*/
		(void)hisi_sec_saa_set_int_mask(dev, i, 0);
	}

	return 0;
}

static int hisi_sec_queue_base_init(struct wd_dev *sec_dev,
				struct wd_queue *queue)
{
	struct sec_queue_info *qinfo;
	struct sec_dev_info *dev_info = sec_dev->priv;

	queue->wdev = sec_dev;
	queue->status = WDQ_STATE_IDLE;
	if (dev_info->queue_num > HISI_SEC_V1_Q_NUM)
		return -ENOSPC;

	qinfo = kzalloc_node(sizeof(struct sec_queue_info), GFP_KERNEL,
		    dev_to_node(HISI_SEC_Q_DEV(queue)));
	if (!qinfo)
		return -ENOMEM;
	qinfo->queue_id = dev_info->queue_num;
	snprintf(qinfo->name, sizeof(qinfo->name), HISI_SEC_DEV_NAME"%d_%d",
		 dev_info->sec_id, qinfo->queue_id);
	list_add(&qinfo->list, &dev_info->queue_list);

	queue->priv = (void *)qinfo;
	dev_info->queue[qinfo->queue_id] = queue;
	dev_info->queue_num++;

	return 0;
}

static  struct wd_queue *hisi_sec_create_wd_queue(struct wd_dev *sec_dev)
{
	struct wd_queue *queue;

	struct device *dev = HISI_SEC_DEV(sec_dev);
	int ret;

	queue = devm_kzalloc(dev, (sizeof(struct wd_queue)), GFP_KERNEL);
	if (!queue) {
		dev_err(dev, "devm_kzalloc queue fail!!\n");
		return ERR_PTR(-ENOMEM);
	}
	ret = hisi_sec_queue_base_init(sec_dev, queue);
	if (ret) {
		dev_err(dev, "sec queue base init fai!\n");
		return ERR_PTR(ret);
	}

	return queue;
}

static  void hisi_sec_destroy_wd_queue(struct wd_queue *queue)
{
	struct wd_dev *sec;
	struct device *dev;
	struct sec_dev_info *dev_info;
	struct sec_queue_info *qinfo;
	struct platform_device *pdevice;

	if (!queue)
		return;

	sec = queue->wdev;
	dev = sec->dev;
	dev_info = sec->priv;
	qinfo = queue->priv;

	dev_info->queue_num--;
	if (qinfo) {
		if (qinfo->qdev) {
			pdevice = to_platform_device(qinfo->qdev);
			platform_device_del(pdevice);
			platform_device_put(pdevice);
		}

		hisi_sec_queue_free_ring_pages(queue);
		kfree(qinfo);
	}
	hisi_sec_queue_unmap_io(queue);
}

static struct wd_dev *
	hisi_sec_create_wd_dev(struct platform_device *pdev)
{
	struct wd_dev *sec_dev;
	struct sec_dev_info *dev_info;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	u32 sec_id;

	for (sec_id = 0; sec_id < HISI_MAX_SEC_DEVICES; sec_id++) {
		if (!sec_devices[sec_id])
			break;
	}

	/* To ensure that the index is within the limit */
	if (sec_id == HISI_MAX_SEC_DEVICES) {
		dev_err(dev, "sec device list full\n");
		return ERR_PTR(-ENODEV);
	}

	/* identify version from DST or ACPI */
	if (!of_device_is_compatible(np, "hisilicon,hip06-sec")) {
		dev_err(dev, "hisilicon sec driver mismatching!\n");
		return ERR_PTR(-ENODEV);
	}

	sec_dev = devm_kzalloc(dev, (sizeof(struct wd_dev)), GFP_KERNEL);
	if (!sec_dev) {
		dev_err(dev, "devm_kzalloc wd_dev fail!!\n");
		return ERR_PTR(-ENOMEM);
	}

	dev_info = devm_kzalloc(dev, (sizeof(struct sec_dev_info)), GFP_KERNEL);
	if (!dev_info) {
		dev_err(dev, "devm_kzalloc sec_dev_info fail!!\n");
		return ERR_PTR(-ENOMEM);
	}

	platform_set_drvdata(pdev, sec_dev);
	sec_dev->owner = THIS_MODULE;
	sec_dev->dev = &pdev->dev;
	sec_dev->priv = dev_info;
	dev_info->sec_id = sec_id;

#if defined(CONFIG_ARM_SMMU_V3) && defined(CONFIG_VFIO_IOMMU_TYPE1)
	sec_dev->iommu_type = VFIO_TYPE1_IOMMU;
#elif !defined(CONFIG_ARM_SMMU_V3) && defined(CONFIG_VFIO_NOIOMMU)
	sec_dev->iommu_type = VFIO_NOIOMMU_IOMMU;
#else
	pr_err("Hisilicon Hi161x SEC Cannot Work In This SMMU Config!\n");
	return ERR_PTR(-ENODEV);
#endif

	spin_lock_init(&dev_info->dev_lock);
	INIT_LIST_HEAD(&dev_info->queue_list);
	snprintf(dev_info->name, HISI_SEC_NAME_SIZE, "%s%d",
			HISI_SEC_DEV_NAME, dev_info->sec_id);
	sec_devices[sec_id] = sec_dev;
	sec_num++;

	return sec_dev;
}

static  void hisi_sec_destroy_wd_dev(struct wd_dev *sec_dev)
{
	struct sec_dev_info *dev_info = sec_dev->priv;
	int i;

	for (i = 0; i < HISI_SEC_V1_Q_NUM; i++)
		hisi_sec_destroy_wd_queue(dev_info->queue[i]);

	sec_num--;
	if (dev_info) {
		sec_devices[dev_info->sec_id] = NULL;
		hisi_sec_unmap_io(sec_dev);
	}
}

static int hisi_sec_map_io(struct wd_dev *dev)
{
	struct sec_dev_info *info = dev->priv;
	void *ptr;

	ptr = ioremap(info->info[0].addr, info->info[0].size);
	if (!ptr)
		return -ENOMEM;

	info->info[0].vaddr = ptr;

	ptr = ioremap(info->info[1].addr, info->info[1].size);
	if (!ptr)
		return -ENOMEM;

	info->info[1].vaddr = ptr;

	return 0;
}

static void hisi_sec_unmap_io(struct wd_dev *dev)
{
	struct sec_dev_info *info = dev->priv;

	iounmap(info->info[0].vaddr);
	iounmap(info->info[1].vaddr);
}

static int hisi_sec_base_init(struct wd_dev *sec)
{
	int ret = 0;
	struct device *dev = HISI_SEC_DEV(sec);

	ret = hisi_sec_set_io_info(sec);
	if (ret) {
		dev_err(dev, "get res fail!\n");
		return ret;
	}

	ret = hisi_sec_map_io(sec);
	if (ret) {
		dev_err(dev, "ioremap fail!\n");
		return ret;
	}

	ret = hisi_sec_set_clk(sec, 1);
	if (ret) {
		dev_err(dev, "set sec clock fail!\n");
		goto io_op_fail;
	}

	ret = hisi_sec_reset_whole_module(sec);
	if (ret) {
		dev_err(dev, "reset sec module fail!\n");
		goto io_op_fail;
	}

	ret = hisi_sec_hw_init(sec);
	if (ret) {
		dev_err(dev, "sec hw initiates fail!\n");
		goto io_op_fail;
	}


	return ret;

io_op_fail:
	hisi_sec_unmap_io(sec);

	return ret;
}

/* This capa in sec device is used for pre-match to improve speed */
static int hisi_sec_capability_init(struct wd_dev *dev)
{
	struct sec_dev_info *dev_info = dev->priv;

	dev_info->capa[WD_AT_CY_SYM] = (struct _sec_wd_capa **)sec_sym_capa_tbl;
	dev_info->capa[WD_AT_CY_AUTH] = (struct _sec_wd_capa **)sec_dgst_capa_tbl;

	return 0;
}
static void hisi_sec_queue_free_ring_pages(struct wd_queue *queue)
{
	int i;
	unsigned int order;
	struct page *queue_page;
	unsigned long long phy;
	struct sec_queue_info *info = queue->priv;
	dma_addr_t iova_start;

	for (i = 1; i < info->info_num; i ++) {
		iova_start = (dma_addr_t)Q_IO_IOVA(queue, i);
		if (iova_start)
			dma_unmap_single(HISI_SEC_Q_DEV(queue), iova_start,
				Q_IO_SIZE(queue, i),
				DMA_TO_DEVICE);
		phy = Q_IO_PADDR(queue, i);
		if (phy) {
			queue_page = phys_to_page(phy);
			order = (unsigned int)get_order(Q_IO_SIZE(queue, i));
			if (order < MAX_ORDER && queue_page)
				__free_pages(queue_page, order);
			else
				pr_err("queue pages error!\n");
		}
	}
}

static int hisi_sec_queue_res_cfg(struct wd_queue *queue)
{
	unsigned int order;
	struct device *dev = HISI_SEC_Q_DEV(queue);
	struct page *page_list;
	unsigned long long phy_addr;
	struct sec_queue_info *info = queue->priv;
	unsigned int mem_size[HISI_SEC_HW_RING_NUM] = {
		HISI_SEC_IO1_SIZE,
		HISI_SEC_IO2_SIZE,
		HISI_SEC_IO3_SIZE,
		HISI_SEC_IO4_SIZE,
	};
	int i, node, ret, k;
	void *addr;
	struct resource *res;
	struct platform_device *pdev, *sec_pdev;
	dma_addr_t dma_addr;

	node = dev_to_node(dev);

	/* Including one IRQ resource more */
	res = kzalloc((HISI_SEC_HW_RING_NUM + 1) * sizeof(*res), GFP_KERNEL);
	if (!res) {
		dev_err(dev, "kzalloc resource memory fail!\n");
		return -ENOMEM;
	}

	/* Actually, all the resources such as IO address/Irqs should be gotten
	  * from SEC device from DTS or ACPI. Here we temparily use fixed
	  * Marco to get the resources.
	 */
	for (i = 0; i < HISI_SEC_HW_RING_NUM; i ++) {
		if (i == SEC_Q_REGS) {
			Q_IO_PADDR(queue, i) = DEV_IO_PADDR(queue->wdev, 2) +
					DEV_IO_SIZE(queue->wdev, 2) *
					info->queue_id;
			Q_IO_SIZE(queue, i) = mem_size[i];
			res[i].start = Q_IO_PADDR(queue, i);
			res[i].end = res[i].start + Q_IO_SIZE(queue, i) - 1;
			res[i].parent = NULL;
			res[i].flags = IORESOURCE_MEM;
			info->info_num++;

			continue;
		}
		if (mem_size[i] & (PAGE_SIZE - 1))
			mem_size[i] = (mem_size[i] & PAGE_MASK) + PAGE_SIZE;

		order = (unsigned int)get_order(mem_size[i]);

		page_list = alloc_pages_node(node, GFP_KERNEL | GFP_DMA, order);
		if (IS_ERR(page_list)) {
			dev_err(dev, "alloc_pages_node order=%d fail!\n", order);
			ret = PTR_ERR(page_list);
			goto alloc_pg_fail;
		}
		addr = page_address(page_list);
		memset(addr, 0, mem_size[i]);
		phy_addr = (unsigned long long)virt_to_phys(addr);
		Q_IO_ADDR(queue, info->info_num) = addr;
		dma_addr = dma_map_single(dev, addr, mem_size[i],
			DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, dma_addr)) {
			ret = -ENOMEM;
			goto alloc_pg_fail;
		}
#if defined(CONFIG_ARM_SMMU_V3)
		Q_IO_IOVA(queue, info->info_num) = (void *)dma_addr;
#else
		Q_IO_IOVA(queue, info->info_num) = dma_addr;
#endif
		Q_IO_PADDR(queue, info->info_num) = phy_addr;
		Q_IO_SIZE(queue, info->info_num) = mem_size[i];
		res[i].start = phy_addr;
		res[i].end = phy_addr + mem_size[i] - 1;
		res[i].parent = NULL;
		res[i].flags = IORESOURCE_MEM;
		info->info_num++;
	}
	sec_pdev = to_platform_device(dev);

	info->task_irq = platform_get_irq(sec_pdev, info->queue_id * 2 + 1);
	info->err_irq = platform_get_irq(sec_pdev, info->queue_id * 2 + 2);

	/* Err Irq is not used currently */
	res[HISI_SEC_HW_RING_NUM].start = info->task_irq;
	res[HISI_SEC_HW_RING_NUM].flags = IORESOURCE_IRQ;

	/* Only task irq is used now */
	info->irq_num = HISI_SEC_IRQ_EN_NUM;
	for (i = 0; i < info->irq_num; i++) {
		info->irqs[i].count = 1;
		info->irqs[i].hwirq = info->task_irq;
	}
	info->ring[SEC_CMD_RING].base = Q_IO_ADDR(queue, SEC_CMD_RING);
	info->ring[SEC_CMD_RING].depth = HISI_SEC_QUEUE_LEN;
	info->ring[SEC_CMD_RING].callback = sec_alg_callback;
	info->ring[SEC_CMD_RING].msg_size = HISI_SEC_BD_SIZE;

	info->ring[SEC_OUTORDER_RING].base = Q_IO_ADDR(queue, SEC_OUTORDER_RING);
	info->ring[SEC_OUTORDER_RING].depth = HISI_SEC_QUEUE_LEN;
	info->ring[SEC_OUTORDER_RING].callback = NULL;
	info->ring[SEC_OUTORDER_RING].msg_size = HISI_SEC_OUT_BD_SIZE;

	info->ring[SEC_DBG_RING].base = Q_IO_ADDR(queue, SEC_DBG_RING);
	info->ring[SEC_DBG_RING].depth = HISI_SEC_QUEUE_LEN;
	info->ring[SEC_DBG_RING].callback = NULL;
	info->ring[SEC_DBG_RING].msg_size = HISI_SEC_DBG_BD_SIZE;

	for (k = 0; k < HISI_SEC_HW_RING_NUM; k ++) {
		atomic_set(&info->ring[k].used, 0);
		spin_lock_init(&info->ring[k].lock);
	}

	/* Zaibo: i think queue platform device is not needed. */
	pdev = platform_device_alloc(info->name, info->queue_id);
	if (IS_ERR(pdev)) {
		dev_err(dev, "Alloc platform device fail!\n");
		ret = PTR_ERR(page_list);
		goto alloc_pg_fail;
	}
	ret = platform_device_add_resources(pdev, res, HISI_SEC_HW_RING_NUM + 1);
	if (ret) {
		dev_err(dev, "platform device add resource fail!\n");
		goto fail_platform_device;
	}

	ret = platform_device_add(pdev);
	if (ret) {
		dev_err(dev, "platform device add fail!\n");
		goto fail_platform_device;
	}
	info->qdev = &pdev->dev;
	info->wdi.regions = info->info;
	info->wdi.num_regions = info->info_num;
	info->wdi.irqs = info->irqs;
	info->wdi.num_irqs = info->irq_num;
	info->wdi.opaque = &pdev->dev;
	kfree(res);

	return 0;
fail_platform_device:
	platform_device_put(pdev);
alloc_pg_fail:
	hisi_sec_queue_free_ring_pages(queue);
	kfree(res);

	return ret;
}

/* Based on DRV, which fixs the algorithm type from algorithm name */
static int hisi_sec_get_alg_type(const char *alg_name)
{
	int value = WD_AT_CY_SYM;

	/* fix me */

	return value;
}

static int _get_alg_info(struct wd_dev *wdev, const char *alg_name,
					struct _sec_wd_capa ***info)
{
	struct sec_dev_info *dinfo = wdev->priv;
	int alg_type, i;
	const char *aname;

	if (!wdev || !info)
		return -EINVAL;
	if (!alg_name) {
		info[0] = dinfo->capa[WD_AT_CY_SYM];
		info[1] = dinfo->capa[WD_AT_CY_AUTH];

		/* 2 kinds of algorithms are supported now */
		return HISI_SEC_ALG_TYPES -2;
	}

	/* This alg_name has alg_type at the beginning */
	alg_type = hisi_sec_get_alg_type(alg_name);
	if (alg_type < 0)
		return alg_type;

	for (i = 0; i < HISI_SEC_V1_MAX_CAP; i++) {
		aname = dinfo->capa[alg_type][i]->alg_name;
		if (aname[0] == '\0')
			break;
		if (!strncmp(alg_name, aname, strlen(aname))) {
			*info = &dinfo->capa[alg_type][i];
			return 0;
		}
	}

	return -ENODEV;
}
static int _get_free_q_num(struct wd_dev *dev)
{
	int i, count = 0;
	struct sec_dev_info *dev_info = dev->priv;

	spin_lock(&dev_info->dev_lock);

	for (i = 0; i < HISI_SEC_V1_Q_NUM; i++) {
		if (dev_info->queue[i]->status == WDQ_STATE_USING)
			continue;
		count++;
	}
	spin_unlock(&dev_info->dev_lock);

	return count;
}

static int _queue_mmap(struct wd_queue *q, struct vm_area_struct *vma)
{
	struct device *dev = HISI_SEC_Q_DEV(q);
	struct sec_queue_info *qinfo = q->priv;
	struct sec_azone *z = qinfo->info;
	unsigned long req_len;
	int ret, i, sz = 0;
	pgprot_t vm_page_prot = vma->vm_page_prot;

	req_len = vma->vm_end - vma->vm_start;

	/* the io space is provided as a whole, no bargain */
	if (vma->vm_end < vma->vm_start ||
	    !(vma->vm_flags & VM_SHARED) ||
	    vma->vm_start & ~PAGE_MASK ||
	    vma->vm_end & ~PAGE_MASK ||
	    vma->vm_pgoff != 0 || req_len != HISI_SEC_IOSPACE_SIZE) {
		dev_err(dev, "sec map vm error!\n");
		return -EINVAL;
	}

	vma->vm_private_data = q;

	for (i = 0; i < HISI_SEC_HW_RING_NUM; i++) {
		if (z[i].size & ~PAGE_MASK)
			z[i].size = (z[i].size & PAGE_MASK) + PAGE_SIZE;
		if (z[i].addr & ~PAGE_MASK) {
			dev_err(dev, "sec map zone param error!\n");
			return -EINVAL;
		}
		vma->vm_pgoff = (z[i].addr >> PAGE_SHIFT);
		if (SEC_Q_REGS == i)
			vma->vm_page_prot =
			pgprot_noncached(vma->vm_page_prot);
		else
			vma->vm_page_prot = vm_page_prot;
		ret = remap_pfn_range(vma, vma->vm_start + sz, vma->vm_pgoff,
				z[i].size, vma->vm_page_prot);
		if (ret) {
			/* no unmap can be done */
			dev_err(dev, "map SEC_Q_REGS fail (%d)\n", ret);
			return ret;
		}
		sz += z[i].size;
	}

	return 0;
}

static int _reset_queue(struct wd_queue *wdev)
{
	/* Fixe me */
	return 0;
}

long _queue_ioctl(struct wd_queue *q, unsigned int cmd, unsigned long arg)
{
	struct device *dev = HISI_SEC_Q_DEV(q);

	switch (cmd) {

	default:
		dev_err(dev, "SEC ioctl cmd error!cmd=0x%x\n", cmd);
		return -EINVAL;
	}
}

static int sec_q_updated(struct wd_queue *q)
{
	u32 wr;
	struct sec_queue_info *qinfo = q->priv;
	struct sec_out_bd_info *out_bd = Q_IO_ADDR(q, SEC_OUTORDER_RING);
	struct sec_bd_info *bd = Q_IO_ADDR(q, SEC_CMD_RING);

	wr = readl_relaxed(Q_IO_ADDR(q, 0) +
			HISI_SEC_Q_OUTORDER_WR_PTR_REG);
	if (wr > 0)
		out_bd = out_bd + wr - 1;
	else
		out_bd = out_bd + HISI_SEC_QUEUE_LEN - 1;

	bd = bd + out_bd->q_id;

	if (wr != qinfo->ring[SEC_OUTORDER_RING].write && bd->done) {
		qinfo->ring[SEC_OUTORDER_RING].write = wr;
		hisi_sec_queue_irq_disable(q);
		disable_irq(qinfo->task_irq);

		return 1;
	}

	return 0;
}

static void sec_mask_notification(struct wd_queue *q, int mask)
{
	struct sec_queue_info *qinfo = q->priv;

	if (mask & _WD_EVENT_NOTIFY) {
		enable_irq(qinfo->task_irq);
		hisi_sec_queue_irq_enable(q);
	} else {
		hisi_sec_queue_irq_disable(q);
		disable_irq(qinfo->task_irq);
	}
}

static int hisi_sec_ops_init(struct wd_dev *dev)
{
	dev->ops.get_queue = _alloc_queue;
	dev->ops.put_queue = _free_queue;
	dev->ops.reset = NULL;
	dev->ops.mmap = _queue_mmap;
	dev->ops.reset_queue = _reset_queue;
	dev->ops.close = _close_queue;
	dev->ops.open = _open_queue;
	dev->ops.ioctl = _queue_ioctl;
	dev->ops.is_q_updated = sec_q_updated;
	dev->ops.mask_notification = sec_mask_notification;

	return 0;
}
static const char *get_alg_from_kobj(struct device *dev, struct kobject *kobj)
{
	const char *drv_name = dev_driver_string(dev);
	int len;

	len = strlen(drv_name);

	return kobj->name + len + 1;
}

static ssize_t iv_size_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct wd_dev *wdev = dev->driver_data;
	struct wd_calg_param *param;
	const char *alg_name;
	int ret;
	struct _sec_wd_capa **capa;

	if (!wdev)
		return sprintf(buf, "no device!\n");
	alg_name = get_alg_from_kobj(dev, kobj);
	if (!alg_name)
		return sprintf(buf, "no alg!\n");

	ret = _get_alg_info(wdev, alg_name, &capa);
	if (ret)
		return sprintf(buf, "no alg info!\n");
	param = capa[0]->priv;

	return sprintf(buf, "%d\n", param->iv_size);
}

MDEV_TYPE_ATTR_RO(iv_size);

static ssize_t key_size_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct wd_dev *wdev = dev->driver_data;
	struct wd_calg_param *param;
	const char *alg_name;
	struct _sec_wd_capa **capa;
	int ret;

	if (!wdev)
		return sprintf(buf, "no device!\n");
	alg_name = get_alg_from_kobj(dev, kobj);
	if (!alg_name)
		return sprintf(buf, "no alg!\n");
	ret = _get_alg_info(wdev, alg_name, &capa);
	if (ret)
		return sprintf(buf, "no alg info!\n");

	param = capa[0]->priv;

	/* We take this 'keysize' as cipher key size now */
	return sprintf(buf, "%d\n", param->key_size);
}

MDEV_TYPE_ATTR_RO(key_size);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	int num = -1;
	struct wd_dev *wdev = (struct wd_dev *)dev->driver_data;

	if (wdev)
		num = _get_free_q_num(wdev);
	if (num >= 0)
		return sprintf(buf, "%d\n", num);
	else
		return sprintf(buf, "error!\n");
}
MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	struct wd_dev *wdev = (struct wd_dev *)dev->driver_data;
	assert(wdev);
	return sprintf(buf, "%s\n", HISI_SEC_DRV_NAME);
}
MDEV_TYPE_ATTR_RO(device_api);

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	const char *alg_name;
	struct wd_dev *wdev = (struct wd_dev *)dev->driver_data;
	if (!wdev)
		return sprintf(buf, "Get name fali!\n");
	alg_name = get_alg_from_kobj(dev, kobj);
	if (!alg_name)
		return sprintf(buf, "no alg!\n");

	return sprintf(buf, "%s\n", alg_name);
}
MDEV_TYPE_ATTR_RO(name);

static ssize_t mac_size_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct wd_dev *wdev = dev->driver_data;
	struct wd_aalg_param *param;
	const char *alg_name;
	struct _sec_wd_capa **capa;
	int ret;

	if (!wdev)
		return sprintf(buf, "no device!\n");
	alg_name = get_alg_from_kobj(dev, kobj);
	if (!alg_name)
		return sprintf(buf, "no alg!\n");
	ret = _get_alg_info(wdev, alg_name, &capa);
	if (ret)
		return sprintf(buf, "no alg info!\n");

	param = capa[0]->priv;

	return sprintf(buf, "%d\n", param->mac_size);
}

MDEV_TYPE_ATTR_RO(mac_size);

/* Zaibo: Currently, i just figure out this attr of pid for SEC mdev */
static struct attribute *sec_mdev_attrs[] = {
	WD_DEFAULT_MDEV_DEV_ATTRS
	NULL,
};

static const struct attribute_group sec_mdev_group = {
	.name  = WD_QUEUE_PARAM_GRP_NAME,
	.attrs = sec_mdev_attrs,
};

static const  struct attribute_group *sec_mdev_groups[] = {
	&sec_mdev_group,
	NULL,
};

static struct attribute *sec_cbc_aes_128_type_attrs[] = {
	WD_DEFAULT_MDEV_TYPE_ATTRS
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,

	/* Zaibo: i don't know how to put the belows into 'flags', because
	 * different algorithm has different parameter value with different
	 * kinds of parameters, however, we just have one flags in wdev.
	 * So put here at present
	 */
	&mdev_type_attr_iv_size.attr,
	&mdev_type_attr_key_size.attr,
	NULL,
};
static struct attribute *sec_md5_type_attrs[] = {
	WD_DEFAULT_MDEV_TYPE_ATTRS
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,

	/* Zaibo: i don't know how to put the belows into 'flags', because
	 * different algorithm has different parameter value with different
	 * kinds of parameters, however, we just have one flags in wdev.
	 * So put here at present
	 */
	&mdev_type_attr_mac_size.attr,
	NULL,
};
/* one cipher and one hash algorithm is suported now */
static struct attribute_group sec_cbc_aes_128_type_group = {
	.name  = cbc_aes_128,
	.attrs = sec_cbc_aes_128_type_attrs,
};
static struct attribute_group sec_md5_type_group = {
	.name  = md5,
	.attrs = sec_md5_type_attrs,
};
static struct attribute_group *sec_mdev_type_groups[] = {
	&sec_cbc_aes_128_type_group,
	&sec_md5_type_group,
	NULL,
};
/* Zaibo: The above alorithms will be a huge number in different drivers.
* I think there will be a disaster that WD give no managment on algorithms.
*/

static int hisi_sec_queue_trigger(struct wd_queue *q)
{
	struct sec_bd_info bd;
	void *buffer;
	unsigned long long dma_buffer, key, iv, dst, src;
	int ret = 0;
	struct device *dev = HISI_SEC_Q_DEV(q);

	ret = hisi_sec_queue_irq_init(q);
	if (ret) {
		dev_err(dev, "sec queue irq init fai!\n");
		return ret;
	}
	(void)hisi_sec_queue_enable(q, 0x1);
	hisi_sec_queue_irq_enable(q);
	memset(&bd, 0, sizeof(bd));
	buffer = kzalloc(512, GFP_KERNEL | GFP_DMA);
	dma_buffer = dma_map_single(dev, buffer, 512, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma_buffer)) {
		ret = -1;
		goto dmamap_fail;
	}

	key = dma_buffer;
	iv = key + 16;
	dst = iv + 16;
	src = dst + 16;
	bd.cipher = 1;
	bd.de = 1;
	bd.c_mode = 1;
	bd.c_alg = 2;
	bd.gran_num = 1;
	bd.cipher_gran_size_low = 0x10;
	bd.cipher_key_addr = (key & 0xFFFFFFFF);
	bd.cipher_key_addr_hi = ((key >> 32) & 0xFFFFFFFF);
	bd.cipher_iv_addr = (iv & 0xFFFFFFFF);
	bd.cipher_iv_addr_hi = ((iv >> 32) & 0xFFFFFFFF);
	bd.cipher_destin_addr = (dst & 0xFFFFFFFF);
	bd.cipher_destin_addr_hi = ((dst >> 32) & 0xFFFFFFFF);
	bd.data_addr = (src & 0xFFFFFFFF);
	bd.data_addr_hi = ((src >> 32) & 0xFFFFFFFF);
	hisi_sec_queue_send(q, &bd);
	(void)hisi_sec_poll((void *)q, 0);
	udelay(10);
dmamap_fail:
	hisi_sec_queue_irq_disable(q);
	(void)hisi_sec_queue_enable(q, 0x0);
	ret = hisi_sec_queue_irq_uninit(q);
	if (ret) {
		dev_err(q->wdev->dev,"sec queue irq uninit fai!\n");
		return ret;
	}
	dma_unmap_single(dev, dma_buffer, 512, DMA_TO_DEVICE);
	kfree(buffer);

	return ret;
}

static int hisi_sec_probe(struct platform_device *pdev)
{
	struct wd_dev *sec_dev = NULL;
	struct device *dev = &pdev->dev;
	unsigned int i;
	struct wd_queue * queue;
	int ret;

	sec_dev = hisi_sec_create_wd_dev(pdev);
	if (IS_ERR(sec_dev)) {
		dev_err(dev, "sec creates wd device fail!\n");
		return PTR_ERR(sec_dev);
	}

	ret = hisi_sec_base_init(sec_dev);
	if (ret) {
		dev_err(dev, "sec basical initiation fail!\n");
		goto wd_dev_init_fail;
	}
	ret = hisi_sec_ops_init(sec_dev);
	if (ret) {
		dev_err(dev, "initiate sec operations fail!\n");
		goto wd_dev_init_fail;
	}
	ret = hisi_sec_capability_init(sec_dev);
	if (ret) {
		dev_err(dev, "hisi sec capability init fail!\n");
		goto wd_dev_init_fail;
	}
	for (i = 0; i < HISI_SEC_V1_Q_NUM; i++) {
		queue = hisi_sec_create_wd_queue(sec_dev);
		if (IS_ERR(queue)) {
			dev_err(dev, "hisi_sec_create_wd_queue fail!\n");
			ret = PTR_ERR(queue);
			goto wd_dev_init_fail;
		}
		ret = hisi_sec_queue_res_cfg(queue);
		if (ret) {
			dev_err(dev, "hisi_sec_queue_res_cfg fail!\n");
			goto wd_dev_init_fail;
		}
		ret = hisi_sec_queue_map_io(queue);
		if (ret) {
			dev_err(dev, "sec queue map fail!\n");
			goto wd_dev_init_fail;
		}
		ret = hisi_sec_queue_hw_init(queue);
		if (ret) {
			dev_err(dev, "sec queue hw init fai!\n");
			goto wd_dev_init_fail;
		}

		/* i don't know why we need this trigger currently */
		ret = hisi_sec_queue_trigger(queue);
		if (ret) {
			dev_err(dev, "sec queue trigger fai!\n");
			goto wd_dev_init_fail;
		}
	}

	sec_dev->mdev_fops.owner = THIS_MODULE;
	sec_dev->mdev_fops.supported_type_groups = sec_mdev_type_groups;
	sec_dev->mdev_fops.mdev_attr_groups = sec_mdev_groups,

	ret = wd_dev_register(sec_dev);
	if (0 != ret) {
		dev_err(dev, "sec device register to wd fail!\n");
		goto wd_dev_register_fail;
	}

	ret = hisi_sec_algs_register();
	if (0 != ret) {
		dev_err(dev, "sec register algorithms to crypto fail!\n");
		goto wd_dev_algs_register_fail;
	}

	dev_dbg(dev, "hisilicon sec probe finishing!!!\n");

	return 0;

wd_dev_algs_register_fail:
	hisi_sec_algs_unregister();

wd_dev_register_fail:
	wd_dev_unregister(sec_dev);
	//hisi_sec_capa_attr_groups_release(sec_dev);

wd_dev_init_fail:
	hisi_sec_destroy_wd_dev(sec_dev);
	dev_err(dev, "hisilicon sec probe failing!!!\n");
	return ret;
}

static int hisi_sec_remove(struct platform_device *pdev)
{
	struct wd_dev *sec_dev = NULL;
	struct device *dev = &pdev->dev;

	sec_dev = platform_get_drvdata(pdev);
	hisi_sec_algs_unregister();
	wd_dev_unregister(sec_dev);
	//hisi_sec_capa_attr_groups_release(sec_dev);
	hisi_sec_destroy_wd_dev(sec_dev);
	dev_dbg(dev, "hisilicon sec remove finishing!!!\n");

	return 0;
}

static const struct of_device_id g_sec_match[] = {
	{.compatible = "hisilicon,hip06-sec"},
	{}
};

static struct platform_driver g_sec_driver = {
	.probe = hisi_sec_probe,
	.remove = hisi_sec_remove,
	.driver = {
		.name = HISI_SEC_DRV_NAME,
		.of_match_table = g_sec_match,
	},
};
static int __init hisi_sec_init(void)
{
	platform_driver_register(&g_sec_driver);
	return 0;
}

static void __exit hisi_sec_exit(void)
{
	platform_driver_unregister(&g_sec_driver);
}
module_init(hisi_sec_init);

module_exit(hisi_sec_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Hisilicon Security Accelerators");
MODULE_VERSION(HISI_SEC_DRV_VERSION);
