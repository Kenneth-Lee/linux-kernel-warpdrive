/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* This file is shared between user and kernel drivers of Hisilicon SEC  */

#ifndef HISI_SEC_DRV_IF_H
#define HISI_SEC_DRV_IF_H

#include <linux/types.h>

#define HISI_SEC_DRV_NAME 			"hisi_sec_platform_driver"
#define LITTLE

#define HISI_SEC_DEV_NAME  "hisi_sec"
#define HISI_SEC_V1_HW_TYPE				(1)
#define HISI_MAX_SEC_DEVICES				(4)
#define HISI_SEC_ALG_TYPES				(4)


#define HISI_SEC_Q_IRQ_NUM				(2)
#define HISI_SEC_HW_RING_NUM				(4)
#define SEC_Q_REGS					(0)
#define SEC_CMD_RING  					(1)
#define SEC_OUTORDER_RING 				(2)
#define SEC_DBG_RING  					(3)


#define U_SEC_QUEUE_AR_FROCE_ALLOC   			(0)
#define U_SEC_QUEUE_AR_FROCE_NOALLOC 			(1)
#define U_SEC_QUEUE_AR_FROCE_DIS     			(2)

#define U_SEC_QUEUE_AW_FROCE_ALLOC   			(0)
#define U_SEC_QUEUE_AW_FROCE_NOALLOC 		(1)
#define U_SEC_QUEUE_AW_FROCE_DIS     			(2)


#define HISI_SEC_Q_INIT_REG                            			(0x0)
#define HISI_SEC_Q_CFG_REG                             			(0x8)
#define HISI_SEC_Q_PROC_NUM_CFG_REG				(0x10)
#define HISI_SEC_QUEUE_ENB_REG                         			(0x18)
#define HISI_SEC_Q_DEPTH_CFG_REG				(0x50)
#define HISI_SEC_Q_BASE_HADDR_REG                      			(0x54)
#define HISI_SEC_Q_BASE_LADDR_REG                      			(0x58)
#define HISI_SEC_Q_WR_PTR_REG                          			(0x5C)
#define HISI_SEC_Q_OUTORDER_BASE_HADDR_REG             		(0x60)
#define HISI_SEC_Q_OUTORDER_BASE_ADDR_REG              		(0x64)

#define HISI_SEC_Q_OUTORDER_RD_PTR_REG                 		(0x68)
#define HISI_SEC_Q_OT_TH_REG                           			(0x6C)
#define HISI_SEC_Q_ARUSER_CFG_REG                      			(0x70)
#define HISI_SEC_Q_AWUSER_CFG_REG                      			(0x74)
#define HISI_SEC_Q_ERR_BASE_HADDR_REG                  		(0x7C)
#define HISI_SEC_Q_ERR_BASE_LADDR_REG                  		(0x80)
#define HISI_SEC_Q_CFG_VF_NUM_REG                      			(0x84)
#define HISI_SEC_Q_SOFT_PROC_PTR_REG                   		(0x88)
#define HISI_SEC_Q_FAIL_INT_MSK_REG                    			(0x300)
#define HISI_SEC_Q_FLOW_INT_MKS_REG                    		(0x304)
#define HISI_SEC_Q_FAIL_RINT_REG                       			(0x400)
#define HISI_SEC_Q_FLOW_RINT_REG                       			(0x404)
#define HISI_SEC_Q_FAIL_INT_STATUS_REG				(0x500)
#define HISI_SEC_Q_FLOW_INT_STATUS_REG                 		(0x504)
#define HISI_SEC_Q_STATUS_REG                          			(0x600)
#define HISI_SEC_Q_RD_PTR_REG                          			(0x604)
#define HISI_SEC_Q_PRO_PTR_REG                         			(0x608)
#define HISI_SEC_Q_OUTORDER_WR_PTR_REG                 		(0x60C)
#define HISI_SEC_Q_OT_CNT_STATUS_REG                   		(0x610)
#define HISI_SEC_Q_INORDER_BD_NUM_ST_REG               		(0x650)
#define HISI_SEC_Q_INORDER_GET_FLAG_ST_REG             		(0x654)
#define HISI_SEC_Q_INORDER_ADD_FLAG_ST_REG             		(0x658)
#define HISI_SEC_Q_INORDER_TASK_INT_NUM_LEFT_ST_REG    	(0x65C)
#define HISI_SEC_Q_RD_DONE_PTR_REG                     		(0x660)
#define HISI_SEC_Q_CPL_Q_BD_NUM_ST_REG                 		(0x700)
#define HISI_SEC_Q_CPL_Q_PTR_ST_REG                    		(0x704)
#define HISI_SEC_Q_CPL_Q_H_ADDR_ST_REG                 		(0x708)
#define HISI_SEC_Q_CPL_Q_L_ADDR_ST_REG                 		(0x70C)
#define HISI_SEC_Q_CPL_TASK_INT_NUM_LEFT_ST_REG        		(0x710)
#define HISI_SEC_Q_WRR_ID_CHECK_REG                    		(0x714)
#define HISI_SEC_Q_CPLQ_FULL_CHECK_REG                 		(0x718)
#define HISI_SEC_Q_SUCCESS_BD_CNT_REG                  		(0x800)
#define HISI_SEC_Q_FAIL_BD_CNT_REG                     			(0x804)
#define HISI_SEC_Q_GET_BD_CNT_REG                      			(0x808)
#define HISI_SEC_Q_IVLD_CNT_REG                        			(0x80C)
#define HISI_SEC_Q_BD_PROC_GET_CNT_REG                 		(0x810)
#define HISI_SEC_Q_BD_PROC_DONE_CNT_REG                		(0x814)
#define HISI_SEC_Q_LAT_CLR_REG                         			(0x850)
#define HISI_SEC_Q_PKT_LAT_MAX_REG                     			(0x854)
#define HISI_SEC_Q_PKT_LAT_AVG_REG                     			(0x858)
#define HISI_SEC_Q_PKT_LAT_MIN_REG                     			(0x85C)
#define HISI_SEC_Q_ID_CLR_CFG_REG                      			(0x900)
#define HISI_SEC_Q_1ST_BD_ERR_ID_REG                   		(0x904)
#define HISI_SEC_Q_1ST_AUTH_FAIL_ID_REG               		(0x908)
#define HISI_SEC_Q_1ST_RD_ERR_ID_REG                   		(0x90C)
#define HISI_SEC_Q_1ST_ECC2_ERR_ID_REG                 		(0x910)
#define HISI_SEC_Q_1ST_IVLD_ID_REG                     			(0x914)
#define HISI_SEC_Q_1ST_BD_WR_ERR_ID_REG                		(0x918)
#define HISI_SEC_Q_1ST_ERR_BD_WR_ERR_ID_REG            		(0x91C)
#define HISI_SEC_Q_1ST_BD_MAC_WR_ERR_ID_REG            		(0x920)


#define HISI_SEC_QUEUE_LEN   					(2048/4)

typedef union {
	struct {
		unsigned int ar_fa	 : 1;
		unsigned int ar_fna	 : 1;
		unsigned int ar_rinvld : 1;
		unsigned int ar_pkg	 : 1;
		unsigned int reserved_11 : 28;
	} bits;
	unsigned int u32;
} U_SEC_Q_ARUSER_CFG;

typedef union {
	struct {
		unsigned int aw_fa	 : 1;
		unsigned int aw_fna	 : 1;
		unsigned int aw_pkg	 : 1;
		unsigned int reserved_12 : 29;
	} bits;
	unsigned int u32;
} U_SEC_Q_AWUSER_CFG;

union sec_q_info {
	struct {
		unsigned int sec_q_reorder : 1;
		unsigned int reserved_21   : 31;
	} bits;
	unsigned int u32;
};
union sec_depth_info {
	struct {
		unsigned int sec_q_depth : 12;
		unsigned int reserved_24 : 20;
	} bits;
	unsigned int u32;
};
union authaddr_lo {
	unsigned int authkey_addr_lo;
	unsigned int authiv_addr_lo;
};
union authaddr_hi {
	unsigned int authkey_addr_hi;
	unsigned int authiv_addr_hi;
};
struct  sec_bd_info {
#ifndef  LITTLE
	/* W0 */
	volatile unsigned int done	:  1;
	unsigned int flag_or_cipher_gran_size_hi :2;
	unsigned int icv_or_s_key_en	:   2;
	unsigned int hm	:                2;
	unsigned int no_hpad	:1;
	unsigned int ci_gen	:	1;
	unsigned int ai_gen	:	1;
	unsigned int auth	:              2;
	unsigned int cipher	:            2;
	unsigned int cipher_gran_size_mid:4;
	unsigned int dat_skip	:2;
	unsigned int de	:	1;
	unsigned int seq	:	1;
	unsigned int c_mode	:             3;
	unsigned int c_width	:	2;
	unsigned int t_len	:	5;


	/* W1 */
	unsigned int c_alg	    :              3;
	unsigned int a_alg	    :              4;
	unsigned int addr_type    :          1;
	unsigned int bd_invalid   :         1;
	unsigned int m_key_en:           1;
	unsigned int auth_gran_sz :       22;

	/* W2 */
	unsigned int gran_num	:16;
	unsigned int cipher_gran_size_low:16;

	/* W3 */
	unsigned int c_key_len	 :2;
	unsigned int a_key_len	 :5;
	unsigned int mac_len	: 5;
	unsigned int cipher_len_offset :  10;
	unsigned int auth_len_offset	 :  10;

#else

	/* W0 */
	unsigned int t_len	:	5;
	unsigned int c_width	:	2;
	unsigned int c_mode	:             3;
	unsigned int seq	:	1;
	unsigned int de	:	1;
	unsigned int dat_skip:	2;
	unsigned int cipher_gran_size_mid:4;
	unsigned int cipher	:            2;
	unsigned int auth	:              2;
	unsigned int ai_gen	:	1;
	unsigned int ci_gen	:	1;
	unsigned int no_hpad:	1;
	unsigned int hm	:                2;
	unsigned int icv_or_s_key_en	:    2;
	unsigned int flag_or_cipher_gran_size_hi:2;
	volatile unsigned int done	:     1;

	/* W1 */
	unsigned int auth_gran_sz :       22;
	unsigned int m_key_en:           1;
	unsigned int bd_invalid   :         1;
	unsigned int addr_type    :          1;
	unsigned int a_alg	    :              4;
	unsigned int c_alg	    :              3;

	/* W2 */
	unsigned int cipher_gran_size_low:16;
	unsigned int gran_num	:16;

	/* W3 */
	unsigned int auth_len_offset	 :  10;
	unsigned int cipher_len_offset :  10;
	unsigned int mac_len:            5;
	unsigned int a_key_len	 :   5;
	unsigned int c_key_len	 :    2;

#endif

	/* W4,5 */
	union authaddr_lo auth_addr_lo;
	union authaddr_hi auth_addr_hi;

	/* W6,7 */
	unsigned int cipher_key_addr;
	unsigned int cipher_key_addr_hi;

	/* W8,9 */
	unsigned int cipher_iv_addr;
	unsigned int cipher_iv_addr_hi;

	/* W10,11 */
	unsigned int data_addr;
	unsigned int data_addr_hi;

	/* W12,13 */
	unsigned int mac_addr;
	unsigned int mac_addr_hi;

	/* W14,15 */
	unsigned int cipher_destin_addr;
	unsigned int cipher_destin_addr_hi;
};

struct sec_debug_bd_info {
#ifndef  LITTLE

	/* W0 */
	unsigned int reserv0	    :    9;
	unsigned int soft_err_check :         23;

	/* W1 */
	unsigned int reserv1	      :    22;
	unsigned int hard_err_check :        10;

	/* W2 */
	unsigned int icv_mac1st_word :     32;

	/* W3 */
	unsigned int reserv2	  :       12;
	unsigned int sec_get_id :                20;

#else

	/* W0 */
	unsigned int soft_err_check :          23;
	unsigned int reserv0	      :      9;

	/* W1 */
	unsigned int hard_err_check :          10;
	unsigned int reserv1	      :      22;

	/* W2 */
	unsigned int icv_mac1st_word :      32;

	/* W3 */
	unsigned int sec_get_id :                   20;
	unsigned int reserv2	  :           12;
#endif

	/* W4---W15 */
	unsigned int reserv_left[12];

};

struct sec_out_bd_info	{
#ifndef  LITTLE
	unsigned short reserve1 : 1;
	unsigned short ecc_2bit_err:1;
	unsigned short reserve0 : 2;
	unsigned short q_id :12;
#else
	unsigned short q_id :12;
	unsigned short reserve0 : 2;
	unsigned short ecc_2bit_err:1;
	unsigned short reserve1 : 1;
#endif
};
#define HISI_SEC_IRQ_EN_NUM				(1)
#define HISI_SEC_SIZE_64K 				(0x10000)

#ifndef PAGE_SIZE
#define PAGE_SIZE	getpagesize()
#endif


#define WPG_ALIGN(size)	((size + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)))

#define HISI_SEC_IO1_SIZE WPG_ALIGN(HISI_SEC_SIZE_64K)
#define HISI_SEC_IO2_SIZE WPG_ALIGN(HISI_SEC_QUEUE_LEN * HISI_SEC_BD_SIZE)
#define HISI_SEC_IO3_SIZE WPG_ALIGN(HISI_SEC_QUEUE_LEN * HISI_SEC_OUT_BD_SIZE)
#define HISI_SEC_IO4_SIZE WPG_ALIGN(HISI_SEC_QUEUE_LEN * HISI_SEC_DBG_BD_SIZE)

/* sizeof SEC_Q_REGS + SEC_CMD_RING + SEC_OUTORDER_RING + SEC_DBG_RING */
#define HISI_SEC_IOSPACE_SIZE	(HISI_SEC_IO1_SIZE + \
				 HISI_SEC_IO2_SIZE + \
				 HISI_SEC_IO3_SIZE + \
				 HISI_SEC_IO4_SIZE)

#define HISI_SEC_BD_SIZE   	(sizeof(struct sec_bd_info))
#define HISI_SEC_OUT_BD_SIZE    (sizeof(struct sec_out_bd_info))
#define HISI_SEC_DBG_BD_SIZE    (sizeof(struct sec_debug_bd_info))

#define HISI_MAX_SGE_NUM   64
#ifndef dma_addr_t
#define dma_addr_t __u64
#endif
struct sec_hw_sge {
	dma_addr_t buf;
	unsigned int len;
	unsigned int pad;
} ;

struct sec_hw_sgl {
	dma_addr_t next_sgl;
	__u16 entry_sum_in_chain;
	__u16 entry_sum_in_sgl;
	__u32 flag;
	__u64 serial_num;
	__u32 cpuid;
	__u32 data_bytes_in_sgl;
	struct sec_hw_sgl *next;
	__u8  reserved[8];
	struct sec_hw_sge  sge_entrys[HISI_MAX_SGE_NUM];
	__u8 node[16];
} ;

enum hisi_sec_cipher_type{
	SEC_CIPHER_NULL,
	SEC_CIPHER_ENCRYPT,
	SEC_CIPHER_DECRYPT,
	SEC_CIPHER_PASS,
	SEC_CIPHER_INVALID,
};

enum hisi_sec_auth_type {
	SEC_AUTH_NULL,
	SEC_AUTH_HASH,
	SEC_AUTH_AUTH,
	SEC_AUTH_INVALID,
};

enum hisi_sec_cipher_alg {
	SEC_DES_ECB_64             	=  0x004 ,
	SEC_DES_CBC_64             	=  0x014 ,

	SEC_3DES_ECB_192_3KEY   =  0x084 ,
	SEC_3DES_ECB_192_2KEY   =  0x08C ,

	SEC_3DES_CBC_192_3KEY   =  0x094 ,
	SEC_3DES_CBC_192_2KEY   =  0x09C ,

	SEC_AES_ECB_128            =  0x100 ,
	SEC_AES_ECB_192            =  0x104 ,
	SEC_AES_ECB_256            =  0x108 ,

	SEC_AES_CBC_128            =  0x110 ,
	SEC_AES_CBC_192            =  0x114 ,
	SEC_AES_CBC_256            =  0x118 ,

	SEC_AES_CTR_128            =  0x140 ,
	SEC_AES_CTR_192            =  0x144 ,
	SEC_AES_CTR_256            =  0x148 ,

	SEC_AES_CCM_128            =  0x150 ,
	SEC_AES_CCM_192            =  0x154 ,
	SEC_AES_CCM_256            =  0x158 ,

	SEC_AES_GCM_128            =  0x160 ,
	SEC_AES_GCM_192            =  0x164 ,
	SEC_AES_GCM_256            =  0x168 ,

	SEC_AES_XTS_128            =  0x170,
	SEC_AES_XTS_256            =  0x178,
	SEC_CIPHER_ALG_INVALID = 0xffff,
};

enum hisi_sec_auth_alg {
	SEC_SHA_160                         = 0x0000,
	SEC_SHA_256                         = 0x0400,
	SEC_MD5                                 = 0x0800,
	SEC_SHA_224                         = 0x0C00,
	SEC_AES_XCBC_MAC_96        = 0x3483,
	SEC_AES_XCBC_PRF_128       = 0x3484,
	SEC_AES_CMAC                       = 0x3884,

	SEC_HMAC_SHA160_96         = 0x2003,
	SEC_HMAC_SHA160                = 0x2005,
	SEC_HMAC_SHA224_96         = 0x2803,
	SEC_HMAC_SHA224                = 0x2807,
	SEC_HMAC_SHA256_96         = 0x2c03,
	SEC_HMAC_SHA256                = 0x2c08,
	SEC_HMAC_MD5_96                = 0x3003,
	SEC_HMAC_MD5                      = 0x3004,

	SEC_AUTH_ALG_INVALID       = 0xffff,
};

/* This queue information is shared between user and kernel sec drivers */
struct hisi_sec_queue_info {
	char mdev_name[32];
	char uuid[16];

	/* The following two units are for debug. Once wd_get_start_paddr
	* is ok, the two can be removed.
	*/
	unsigned long long cmd_buf;
	unsigned long long mid_buf;
};


#define HISI_SEC_V1_MAX_KEY		32
#define HISI_SEC_V1_MAX_IV		16

/* This area is used for storing key or iv, which can be DMA */
#define HISI_SEC_V1_EXEREA_SIZE	(2*(HISI_SEC_V1_MAX_KEY + HISI_SEC_V1_MAX_IV))

#endif /* HISI_SEC_DRV_IF_H */
