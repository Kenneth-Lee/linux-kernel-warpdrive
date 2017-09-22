/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _HISI_SEC_ALGS_H
#define _HISI_SEC_ALGS_H

#include "hisi_sec_drv_if.h"

#define HISI_SEC_MAX_CIPHER_KEY   	64
#define HISI_SEC_MAX_CIPHER_IV		32
enum hisi_sec_cipher_mode {
	HISI_SEC_UNKNOW_MODE = 0,
	HISI_SEC_HW_CIPHER_ECB_MODE,
	HISI_SEC_HW_CIPHER_CBC_MODE,
	HISI_SEC_HW_CIPHER_CTR_MODE,
	HISI_SEC_HW_CIPHER_XTS_MODE,
};

struct sec_alg_key {
	union {
		struct sec_enc_key { /* Encrypt content desc */
			u8 cipher[64];
			u8 hash[64];
		} enc_key;
		struct sec_dec_key { /* Decrytp content desc */
			u8 hash[64];
			u8 cipher[64];
		} dec_key;
	};
};

struct sec_alg_aead_ctx {
	struct sec_alg_key *enc_cd;
	struct sec_alg_key *dec_cd;
	dma_addr_t enc_cd_paddr;
	dma_addr_t dec_cd_paddr;
	struct sec_bd_info enc_fw_req;
	struct sec_bd_info dec_fw_req;
	struct crypto_shash *hash_tfm;
	enum hisi_sec_auth_alg hash_alg;
	struct wd_queue *queue;
};

struct sec_alg_ablkcipher_ctx {
	enum hisi_sec_cipher_alg cipher_alg;
	u8 *enc_key;
	u8 *dec_key;
	dma_addr_t enc_pkey;
	dma_addr_t dec_pkey;
	struct sec_bd_info enc_req;
	struct sec_bd_info dec_req;
	struct wd_queue *queue;
	struct crypto_tfm *tfm;
	spinlock_t lock;
};
struct sec_crypto_buf_list {
	struct sec_hw_sgl *in;
	dma_addr_t dma_in;
	struct sec_hw_sgl *out;
	dma_addr_t dma_out;
	u8 *iv;
	dma_addr_t dma_iv;
};
struct sec_crypto_request {
	struct sec_bd_info req;
	union {
		struct sec_alg_aead_ctx *aead_ctx;
		struct sec_alg_ablkcipher_ctx *ablkcipher_ctx;
	};
	union {
		struct aead_request *aead_req;
		struct ablkcipher_request *ablkcipher_req;
	};
	struct sec_crypto_buf_list sec_udata;
	void (*cb)(struct sec_bd_info *resp,
		   struct sec_crypto_request *req);
};
struct  sec_ablkcipher_param {
	void *session;
	void *cipher_iv;
	uint32_t cipher_offset;
	uint32_t cipher_length;
	dma_addr_t pcipher_iv;
};

void sec_alg_callback(void *resp);
int hisi_sec_algs_register(void);
void hisi_sec_algs_unregister(void);
#endif /* _HISI_SEC_ALGS_H */
