/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _HISI_SEC_DRV_V1_H
#define _HISI_SEC_DRV_V1_H

#include <linux/interrupt.h>
#include <linux/list.h>

#include "hisi_sec_drv_if.h"

enum sec_wd_alg_type {
	WD_AT_CUSTOMIZED,
	WD_AT_CY_SYM,		/* symmetric cipher */
	WD_AT_CY_AUTH,		/* auth */
	WD_AT_CY_SYM_AUTH,	/* cipher/auth */
	WD_AT_CY_AUTH_SYM,	/* auth/cipher */
	WD_AT_ALG_TYPE_MAX,
};

#define HISI_SEC_NAME_SIZE				64
#define HISI_SEC_DRV_VERSION				"sec-v1.0"
#define HISI_SEC_V1_Q_NUM				16
#define HISI_SEC_V1_ADDR_REGION				3
#define HISI_ALG_SUB_BASE				(0xd0000000)
#define HISI_SEC_REG_BASE 				(0xd2000000)
#define HISI_SEC_QUEUE_BASE_ADDR 			(0xd2010000)
#define HISI_ALG_SUB_BASE_SIZE				HISI_SEC_SIZE_64K
#define HISI_SEC_REG_BASE_SIZE				HISI_SEC_SIZE_64K

/* Hi161x ALGSUB SEC register value */
#define HISI_SEC_CLK_EN 					(0x3b8)
#define HISI_SEC_CLK_DIS  				(0x3bc)
#define HISI_SEC_CLK_ST 					(0x535c)
#define HISI_SEC_RST_REQ  				(0xaa8)
#define HISI_SEC_RESET_DREQ				(0xaac)
#define HISI_SEC_RESET_ST				(0x5a54)
#define HISI_SEC_BUILD_RST_REQ 				(0xab8)
#define HISI_SEC_BUILD_RESET_DREQ			(0xabc)
#define HISI_SEC_BUILD_RESET_ST				(0x5a5c)

#define HISI_SEC_SAA_BASE				(0x00001000UL)

/* Hi161x SEC_SAA registers offset */
#define HISI_SEC_SAA_CONTROL_REG                       		(0x0)
#define HISI_SEC_ST_INTMSK1_REG                        		(0x200)
#define HISI_SEC_ST_RINT1_REG                          		(0x400)
#define HISI_SEC_ST_INTSTS1_REG                        		(0x600)
#define HISI_SEC_BD_MNG_STAT_REG                       		(0x800)
#define HISI_SEC_PARSING_STAT_REG                      		(0x804)
#define HISI_SEC_LOAD_TIME_OUT_CNT_REG                 	(0x808)
#define HISI_SEC_CORE_WORK_TIME_OUT_CNT_REG            	(0x80C)
#define HISI_SEC_BACK_TIME_OUT_CNT_REG                 	(0x810)
#define HISI_SEC_BD1_PARSING_RD_TIME_OUT_CNT_REG       (0x814)
#define HISI_SEC_BD1_PARSING_WR_TIME_OUT_CNT_REG      (0x818)
#define HISI_SEC_BD2_PARSING_RD_TIME_OUT_CNT_REG       (0x81C)
#define HISI_SEC_BD2_PARSING_WR_TIME_OUT_CNT_REG      (0x820)
#define HISI_SEC_SAA_ACC_REG                           		(0x83C)
#define HISI_SEC_BD_NUM_CNT_IN_SEC_REG                 	(0x858)
#define HISI_SEC_LOAD_WORK_TIME_CNT_REG                	(0x860)
#define HISI_SEC_CORE_WORK_WORK_TIME_CNT_REG           	(0x864)
#define HISI_SEC_BACK_WORK_TIME_CNT_REG                	(0x868)
#define HISI_SEC_SAA_IDLE_TIME_CNT_REG                 	(0x86C)
#define HISI_SEC_SAA_CLK_CNT_REG                       		(0x870)

/* Hi161x SEC_COMMON register offset */
#define HISI_SEC_CLK_EN_REG                            		(0x0)
#define HISI_SEC_CONTROL_REG                          		(0x4)
#define HISI_SEC_COMMON_CNT_CLR_CE_REG                 	(0x8)
#define HISI_SEC_SECURE_CONTROL_REG                    	(0xC)
#define HISI_SEC_AXI_CACHE_CFG_REG                     		(0x10)
#define HISI_SEC_AXI_QOS_CFG_REG                       		(0x14)
#define HISI_SEC_IPV4_MASK_TABLE_REG                   	(0x20)
#define HISI_SEC_IPV6_MASK_TABLE_0_REG                 	(0x24)
#define HISI_SEC_IPV6_MASK_TABLE_1_REG                 	(0x28)
#define HISI_SEC_IPV6_MASK_TABLE_2_REG                 	(0x2C)
#define HISI_SEC_IPV6_MASK_TABLE_3_REG                 	(0x30)
#define HISI_SEC_IPV6_MASK_TABLE_4_REG                 	(0x34)
#define HISI_SEC_IPV6_MASK_TABLE_5_REG                 	(0x38)
#define HISI_SEC_IPV6_MASK_TABLE_6_REG                 	(0x3C)
#define HISI_SEC_IPV6_MASK_TABLE_7_REG                 	(0x40)
#define HISI_SEC_IPV6_MASK_TABLE_8_REG                 	(0x44)
#define HISI_SEC_IPV6_MASK_TABLE_9_REG                 	(0x48)
#define HISI_SEC_FSM_MAX_CNT_REG                       		(0x64)
#define HISI_SEC_CONTROL_2_REG                         		(0x68)
#define HISI_SEC_CNT_PRECISION_CFG_REG                 	(0x6C)
#define HISI_SEC_DEBUG_BD_CFG_REG                      		(0x70)
#define HISI_SEC_Q_SIGHT_SEL                           		(0x74)
#define HISI_SEC_Q_SIGHT_HIS_CLR                       		(0x78)
#define HISI_SEC_Q0_VMID_CFG_REG                       		(0x100)
#define HISI_SEC_Q1_VMID_CFG_REG                       		(0x104)
#define HISI_SEC_Q2_VMID_CFG_REG                       		(0x108)
#define HISI_SEC_Q3_VMID_CFG_REG                       		(0x10C)
#define HISI_SEC_Q4_VMID_CFG_REG                       		(0x110)
#define HISI_SEC_Q5_VMID_CFG_REG                       		(0x114)
#define HISI_SEC_Q6_VMID_CFG_REG                       		(0x118)
#define HISI_SEC_Q7_VMID_CFG_REG                       		(0x11C)
#define HISI_SEC_Q8_VMID_CFG_REG                       		(0x120)
#define HISI_SEC_Q9_VMID_CFG_REG                       		(0x124)
#define HISI_SEC_Q10_VMID_CFG_REG                      		(0x128)
#define HISI_SEC_Q11_VMID_CFG_REG                      		(0x12C)
#define HISI_SEC_Q12_VMID_CFG_REG                      		(0x130)
#define HISI_SEC_Q13_VMID_CFG_REG                      		(0x134)
#define HISI_SEC_Q14_VMID_CFG_REG                      		(0x138)
#define HISI_SEC_Q15_VMID_CFG_REG                      		(0x13C)
#define HISI_SEC_Q0_WEIGHT_CFG_REG                     	(0x200)
#define HISI_SEC_Q1_WEIGHT_CFG_REG                     	(0x204)
#define HISI_SEC_Q2_WEIGHT_CFG_REG                     	(0x208)
#define HISI_SEC_Q3_WEIGHT_CFG_REG                     	(0x20C)
#define HISI_SEC_Q4_WEIGHT_CFG_REG                     	(0x210)
#define HISI_SEC_Q5_WEIGHT_CFG_REG                     	(0x214)
#define HISI_SEC_Q6_WEIGHT_CFG_REG                     	(0x218)
#define HISI_SEC_Q7_WEIGHT_CFG_REG                     	(0x21C)
#define HISI_SEC_Q8_WEIGHT_CFG_REG                     	(0x220)
#define HISI_SEC_Q9_WEIGHT_CFG_REG                     	(0x224)
#define HISI_SEC_Q10_WEIGHT_CFG_REG                    	(0x228)
#define HISI_SEC_Q11_WEIGHT_CFG_REG                    	(0x22C)
#define HISI_SEC_Q12_WEIGHT_CFG_REG                    	(0x230)
#define HISI_SEC_Q13_WEIGHT_CFG_REG                    	(0x234)
#define HISI_SEC_Q14_WEIGHT_CFG_REG                    	(0x238)
#define HISI_SEC_Q15_WEIGHT_CFG_REG                    	(0x23C)
#define HISI_SEC_STAT_CLR_REG                          		(0xA00)
#define HISI_SEC_SAA_IDLE_CNT_CLR_REG                  	(0xA04)
#define HISI_SEC_QM_CPL_Q_IDBUF_DFX_CFG_REG            	(0xB00)
#define HISI_SEC_QM_CPL_Q_IDBUF_DFX_RESULT_REG         	(0xB04)
#define HISI_SEC_QM_BD_DFX_CFG_REG                     	(0xB08)
#define HISI_SEC_QM_BD_DFX_RESULT_REG                  	(0xB0C)
#define HISI_SEC_QM_BDID_DFX_RESULT_REG                	(0xB10)
#define HISI_SEC_QM_BD_DFIFO_STATUS_REG                	(0xB14)
#define HISI_SEC_QM_BD_DFX_CFG2_REG                     	(0xB1C)
#define HISI_SEC_QM_BD_DFX_RESULT2_REG                  	(0xB20)
#define HISI_SEC_QM_BD_IDFIFO_STATUS_REG               	(0xB18)
#define HISI_SEC_QM_BD_DFIFO_STATUS2_REG               	(0xB28)
#define HISI_SEC_QM_BD_IDFIFO_STATUS2_REG              	(0xB2c)

#define HISI_SEC_Q_DEV(Q) ((Q)->wdev->dev)
#define HISI_SEC_DEV(SEC) 	((SEC)->dev)

#define SEC_RESET_ST 					(1)
#define SEC_NOT_RESET_ST 				(0)

#define HISI_SEC_V1_ALG_NUM				4
#define HISI_SEC_V1_MAX_CAP				32

#define HISI_SEC_HASH_IPV4_MASK 			(0xfff00000)
#define HISI_SEC_MAX_SAA_NUM 				(0xa)
#define HISI_SEC_SAA_ADDR_SIZE 				(0x1000)

#define SEC_MODULE_NAME 				"SEC_DEV"

/* cipher before auth */
#define SEC_SEQ_CIPHER_AUTH                   			(0x0)
/* auth before cipher */
#define SEC_SEQ_AUTH_CIPHER                   			(0x1)


#define Q_IO_PADDR(Q, INX)	\
	(((struct sec_queue_info *)Q->priv)->info[INX].addr)
#define Q_IO_ADDR(Q, INX)	\
	(((struct sec_queue_info *)Q->priv)->info[INX].vaddr)

#if defined(CONFIG_ARM_SMMU_V3)
#define Q_IO_IOVA(Q, INX)	\
	(((struct sec_queue_info *)Q->priv)->info[INX].ioaddr)
#else
#define Q_IO_IOVA(Q, INX)	\
	(((struct sec_queue_info *)Q->priv)->info[INX].addr)
#endif

#define Q_IO_SIZE(Q, INX)	\
	(((struct sec_queue_info *)Q->priv)->info[INX].size)
#define Q_IO_TYPE(Q, INX)	\
	(((struct sec_queue_info *)Q->priv)->info[INX].type)
#define Q_IO_FLAG(Q, INX)	\
	(((struct sec_queue_info *)Q->priv)->info[INX].flags)

#define DEV_IO_ADDR(DEV, INX)	\
	((struct sec_dev_info *)DEV->priv)->info[INX].vaddr
#define DEV_IO_PADDR(DEV, INX)	\
	((struct sec_dev_info *)DEV->priv)->info[INX].addr
#define DEV_IO_SIZE(DEV, INX)	\
	((struct sec_dev_info *)DEV->priv)->info[INX].size

typedef void (*sec_callback_fn)(void *resp_msg);

struct sec_queue_ring {
	u32 depth;
	u32 type;
	u32 write;
	u32 read;
	atomic_t used;
	u32 msg_size;
	spinlock_t lock;
	void *base;
	sec_callback_fn callback;
};

struct sec_azone {
	union {
		void *vaddr;
		__u64 pad0;
	};
	union {
		void *ioaddr;
		__u64 pad1;
	};
	__u64 addr;
	__u32 type;
	__u32 size;
	__u32 flags;
	__u32 id;
};

struct sec_dev_irq {
	u32		flags;
	u32		count;
	int		hwirq;
	char		*name;
	struct wd_queue	*q;
};

struct sec_comm_dev_info {
	struct sec_dev_irq 	*irqs;
	u32 			num_irqs;
	struct sec_azone 	*regions;
	u32 			num_regions;
	void 			*opaque;
};

struct sec_queue_info {
	int task_irq;
	int err_irq;
	char name[HISI_SEC_NAME_SIZE];
	struct tasklet_struct resp_handler;
	struct sec_queue_ring ring[HISI_SEC_HW_RING_NUM];
	struct sec_azone info[HISI_SEC_HW_RING_NUM];
	struct sec_dev_irq irqs[HISI_SEC_Q_IRQ_NUM];
	struct sec_comm_dev_info wdi;
	void *hwaddr[HISI_SEC_HW_RING_NUM];
	struct list_head list;
	u32 irq_num;
	u32 info_num;
	u32 queue_id;
	struct device *qdev;
};

struct sec_dev_info {
	int sec_id;
	char name[HISI_SEC_NAME_SIZE];
	struct sec_azone info[HISI_SEC_V1_ADDR_REGION];
	void *hwaddr[HISI_SEC_V1_ADDR_REGION];

	/* A list of queues on this device */
	struct wd_queue *queue[HISI_SEC_V1_Q_NUM];
	struct list_head queue_list;
	spinlock_t dev_lock;
	u32 queue_num;
	struct _sec_wd_capa **capa[WD_AT_ALG_TYPE_MAX];
};

union sec_control2_info {
	struct {
		unsigned int data_axi_rd_otsd_config : 4;
		unsigned int data_axi_wr_otsd_config : 3;
		unsigned int clk_gate_enable        	 : 1;
		unsigned int sec_endian_bd           	: 1;
		unsigned int sec_endian_bd_type      : 1;
		unsigned int reserved_5              	: 22;
	} bits;

	unsigned int u32;
};

union sec_common_cnt_info {
	struct {
		unsigned int cnt_clr_ce  : 1;
		unsigned int snap_en     : 1;
		unsigned int reserved_2  : 30;
	} bits;

	unsigned int u32;
};

union dbg_bd_cfg {
	struct {
		unsigned int back_bd_info_en     : 1;
		unsigned int back_bd_info_msk   : 1;
		unsigned int reserved_8              : 30;
	} bits;

	unsigned int u32;
};

union saa_control_info {
	struct {
		unsigned int get_qm_en           : 1;
		unsigned int back_bd_info_en    : 1;
		unsigned int pre_dat_rd_en       : 1;
		unsigned int cfb_mode_en         : 1;
		unsigned int ofb_mode_en         : 1;
		unsigned int back_bd_info_msk  : 1;
		unsigned int reserved_9          : 26;
	} bits;

	unsigned int u32;
};
int hisi_sec_queue_send(void *queue, void *msg);
int hisi_release_crypto_queue(struct wd_queue *sec_queue);
struct wd_queue *hisi_alloc_crypto_queue(struct wd_dev *sec_dev);
struct wd_dev *hisi_get_sec_device(int cpu);
#endif /* _HISI_SEC_DRV_V1_H */
