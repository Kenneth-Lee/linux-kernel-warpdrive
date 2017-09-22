/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/internal/aead.h>
#include <crypto/des.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <linux/dma-mapping.h>

#include "../wd/wd.h"
#include "hisi_sec_drv_v1.h"
#include "hisi_sec_algs.h"


static void sec_free_opdata(struct wd_queue *queue,
			struct sec_crypto_request *sec_req);
static DEFINE_MUTEX(algs_lock);
static unsigned int active_devs;
static inline unsigned int ADDR_L(dma_addr_t addr){return addr&0xffffffff;}
static inline unsigned int ADDR_H(dma_addr_t addr){return addr>>32;}
#ifdef HISI_SEC_DEBUG
void Test_sec_print_bd(void* bd_ptr)
{
	struct sec_bd_info * bd = (struct sec_bd_info *)bd_ptr;

	printk(KERN_ERR "******* word 0 *******\r\n");
	printk(KERN_ERR "done:0x%x\r\n", bd->done);
	printk(KERN_ERR "flag_or_cipher_gran_size_hi:0x%x\r\n", bd->flag_or_cipher_gran_size_hi);
	printk(KERN_ERR "icv_or_s_key_en:0x%x\r\n", bd->icv_or_s_key_en);
	printk(KERN_ERR "hm:0x%x\r\n", bd->hm);
	printk(KERN_ERR "no_hpad:0x%x\r\n", bd->no_hpad);
	printk(KERN_ERR "ci_gen:0x%x\r\n", bd->ci_gen);
	printk(KERN_ERR "ai_gen:0x%x\r\n", bd->ai_gen);
	printk(KERN_ERR "auth:0x%x\r\n", bd->auth);
	printk(KERN_ERR "cipher:0x%x\r\n", bd->cipher);
	printk(KERN_ERR "cipher_gran_size_mid:0x%x\r\n", bd->cipher_gran_size_mid);
	printk(KERN_ERR "dat_skip:0x%x\r\n", bd->dat_skip);
	printk(KERN_ERR "de:0x%x\r\n", bd->de);
	printk(KERN_ERR "seq:0x%x\r\n", bd->seq);
	printk(KERN_ERR "c_mode:0x%x\r\n", bd->c_mode);
	printk(KERN_ERR "c_width:0x%x\r\n", bd->c_width);
	printk(KERN_ERR "t_len:0x%x\r\n", bd->t_len);

	printk(KERN_ERR "******* word 1 *******\r\n");
	printk(KERN_ERR "c_alg:0x%x\r\n", bd->c_alg);
	printk(KERN_ERR "a_alg:0x%x\r\n", bd->a_alg);
	printk(KERN_ERR "addr_type:0x%x\r\n", bd->addr_type);
	printk(KERN_ERR "bd_invalid:0x%x\r\n", bd->bd_invalid);
	printk(KERN_ERR "m_key_en:0x%x\r\n", bd->m_key_en);
	printk(KERN_ERR "auth_gran_sz:0x%x\r\n", bd->auth_gran_sz);

	printk(KERN_ERR "******* word 2 *******\r\n");
	printk(KERN_ERR "gran_num:0x%x\r\n", bd->gran_num);
	printk(KERN_ERR "cipher_gran_size_low:0x%x\r\n", bd->cipher_gran_size_low);

	printk(KERN_ERR "******* word 3 *******\r\n");
	printk(KERN_ERR "c_key_len:0x%x\r\n", bd->c_key_len);
	printk(KERN_ERR "a_key_len:0x%x\r\n", bd->a_key_len);
	printk(KERN_ERR "mac_len:0x%x\r\n", bd->mac_len);
	printk(KERN_ERR "cipher_len_offset:0x%x\r\n", bd->cipher_len_offset);
	printk(KERN_ERR "auth_len_offset:0x%x\r\n", bd->auth_len_offset);

	printk(KERN_ERR "******* word 4 5 6 7 *******\r\n");
	printk(KERN_ERR "AuthKeyAddr:0x%x\r\n", bd->auth_addr_lo.authkey_addr_lo);
	printk(KERN_ERR "AuthKeyAddrHi:0x%x\r\n", bd->auth_addr_hi.authkey_addr_hi);
	printk(KERN_ERR "CipherKeyAddr:0x%x\r\n", bd->cipher_key_addr);
	printk(KERN_ERR "CipherKeyAddrHi:0x%x\r\n", bd->cipher_destin_addr_hi);

	printk(KERN_ERR "******* word 8 9 10 11 *******\r\n");
	printk(KERN_ERR "IVINAddr:0x%x\r\n", bd->cipher_iv_addr);
	printk(KERN_ERR "IVINAddrHi:0x%x\r\n", bd->cipher_iv_addr_hi);
	printk(KERN_ERR "DataAddr:0x%x\r\n", bd->data_addr);
	printk(KERN_ERR "DataAddrHi:0x%x\r\n", bd->data_addr_hi);

	printk(KERN_ERR "******* word 12 13 14 15 *******\r\n");
	printk(KERN_ERR "MacAddr:0x%x\r\n", bd->mac_addr);
	printk(KERN_ERR "MacAddrHi:0x%x\r\n", bd->mac_addr_hi);
	printk(KERN_ERR "CipherDestinAddr:0x%x\r\n", bd->cipher_destin_addr);
	printk(KERN_ERR "CipherDestinAddrHi:0x%x\r\n", bd->cipher_destin_addr_hi);
}

void Test_sec_print_dbg_bd(void* bd_ptr)
{
	struct sec_debug_bd_info * bd = (struct sec_debug_bd_info *)bd_ptr;

	printk(KERN_ERR "******* word 0 *******\n");
	printk(KERN_ERR "soft_err_check:0x%x\n", bd->soft_err_check);
	printk(KERN_ERR "******* word 1 *******\n");
	printk(KERN_ERR "hard_err_check:0x%x\n", bd->hard_err_check);
	printk(KERN_ERR "******* word 2 *******\n");
	printk(KERN_ERR "icv_mac1st_word:0x%x\n", bd->icv_mac1st_word);
	printk(KERN_ERR "******* word 3 *******\n");
	printk(KERN_ERR "sec_get_id:0x%x\n", bd->sec_get_id);
}

static void _sec_show_sgl(struct sec_hw_sgl *sgl)
{
	int i  = 0;
	printk(KERN_ERR "sgl->next_sgl = %llx \r\n", sgl->next_sgl);
	printk(KERN_ERR "sgl->entry_sum_in_chain = %d \r\n", sgl->entry_sum_in_chain);
	printk(KERN_ERR "sgl->entry_sum_in_sgl = %d \r\n", sgl->entry_sum_in_sgl);
	printk(KERN_ERR "sgl->flag = %d \r\n", sgl->flag);
	printk(KERN_ERR "sgl->serial_num = %lld \r\n", sgl->serial_num);
	printk(KERN_ERR "sgl->cpuid = %d \r\n", sgl->cpuid);
	printk(KERN_ERR "sgl->data_bytes_in_sgl = %d \r\n", sgl->data_bytes_in_sgl);
	while (i < sgl->entry_sum_in_sgl) {
		printk(KERN_ERR "sgl->sge_entrys[%d].buf=%llx \r\n", i, sgl->sge_entrys[i].buf);
		printk(KERN_ERR "sgl->sge_entrys[%d].len=%d \r\n", i, sgl->sge_entrys[i].len);
		printk(KERN_ERR "sgl->sge_entrys[%d].pad=%d \r\n", i, sgl->sge_entrys[i].pad);
		//dump_buf((uint8_t*)hatk_mem_p2v((unsigned long long)sgl->sge_entrys[i].buf),
			//sgl->sge_entrys[i].len);
		i++;
	}
}
#endif

static void sec_ablkcipher_alg_callback(struct sec_bd_info *sec_resp,
				  struct sec_crypto_request *sec_req)
{
	struct sec_alg_ablkcipher_ctx *ctx = sec_req->ablkcipher_ctx;
	struct wd_queue *queue = ctx->queue;
	struct device *dev = queue->wdev->dev;
	struct ablkcipher_request *areq = sec_req->ablkcipher_req;
	int ret = 0;

	if (unlikely(1 == sec_resp->bd_invalid ||
		3 == sec_resp->icv_or_s_key_en))
			ret = -EINVAL;
	sec_free_opdata(queue, sec_req);
	dma_unmap_single(dev, ctx->enc_pkey, HISI_SEC_MAX_CIPHER_KEY,
		DMA_TO_DEVICE);
	ctx->enc_pkey = 0;
	dma_unmap_single(dev, ctx->dec_pkey, HISI_SEC_MAX_CIPHER_KEY,
		DMA_TO_DEVICE);
	ctx->dec_pkey = 0;
	areq->base.complete(&areq->base, ret);
}
void sec_alg_callback(void *resp)
{
	struct sec_bd_info *sec_resp = resp;
	struct sec_crypto_request *sec_req =
			*(struct sec_crypto_request **)&sec_resp->mac_addr;
	if (sec_req)
		sec_req->cb(sec_resp, sec_req);
}

static int sec_alg_info_trans(int key_len, int *sec_alg, const char *alg)
{
	if (!strncmp(alg, "cbc", 3)) {
		if (!strncmp(alg + 4, "aes", 3)) {
			if (key_len == AES_KEYSIZE_128)
				*sec_alg = SEC_AES_CBC_128;
			else if (key_len == AES_KEYSIZE_192)
				*sec_alg = SEC_AES_CBC_192;
			else if (key_len == AES_KEYSIZE_256)
				*sec_alg = SEC_AES_CBC_256;
			else
				return -EINVAL;
			return 0;
		}
		if (!strncmp(alg + 4, "des3_ede", 8)) {
			if (key_len == DES3_EDE_KEY_SIZE)
				*sec_alg = SEC_3DES_CBC_192_3KEY;
			else
				return -EINVAL;
			return 0;
		}
		if (!strncmp(alg + 4, "des", 3)) {
			if (key_len == DES_KEY_SIZE)
				*sec_alg = SEC_DES_CBC_64;
			else
				return -EINVAL;
			return 0;
		}
	} else if (!strncmp(alg, "ecb", 3)) {
		if (!strncmp(alg + 4, "aes", 3)) {
			if (key_len == AES_KEYSIZE_128)
				*sec_alg = SEC_AES_ECB_128;
			else if (key_len == AES_KEYSIZE_192)
				*sec_alg = SEC_AES_ECB_192;
			else if (key_len == AES_KEYSIZE_256)
				*sec_alg = SEC_AES_ECB_256;
			else
				return -EINVAL;
			return 0;
		}
		if (!strncmp(alg + 4, "des3_ede", 8)) {
			if (key_len == DES3_EDE_KEY_SIZE)
				*sec_alg = SEC_3DES_ECB_192_3KEY;
			else
				return -EINVAL;
			return 0;
		}
		if (!strncmp(alg + 4, "des", 3)) {
			if (key_len == DES_KEY_SIZE)
				*sec_alg = SEC_DES_ECB_64;
			else
				return -EINVAL;
			return 0;
		}
	}
	else if (!strncmp(alg, "ctr", 3)) {
		if (!strncmp(alg + 4, "aes", 3)) {
			if (key_len == AES_KEYSIZE_128)
				*sec_alg = SEC_AES_CTR_128;
			else if (key_len == AES_KEYSIZE_192)
				*sec_alg = SEC_AES_CTR_192;
			else if (key_len == AES_KEYSIZE_256)
				*sec_alg = SEC_AES_CTR_256;
			else
				return -EINVAL;
			return 0;
		}
	} else if (!strncmp(alg, "xts", 3)) {
		if (!strncmp(alg + 4, "aes", 3)) {
			if (key_len == AES_KEYSIZE_128)
				*sec_alg = SEC_AES_XTS_128;
			else if (key_len == AES_KEYSIZE_256)
				*sec_alg = SEC_AES_XTS_256;
			else
				return -EINVAL;
			return 0;
		}
	} else
		/* other cipher algs are not supported by this version */
		return -EINVAL;
	return -EINVAL;
}

static void sec_alg_ablkcipher_com_init(struct sec_alg_ablkcipher_ctx *ctx,
					struct sec_bd_info *req, int alg)
{
	req->bd_invalid = 0;
	req->done = 0;
	req->c_alg    = (alg >> 7) & 0x7;
	req->c_mode   = (alg >> 4)  & 0x7;
	req->c_key_len = (alg >> 2)  & 0x3;
	req->c_width  = (alg >> 0)  & 0x3;
	req->seq = SEC_SEQ_CIPHER_AUTH;
	req->cipher_key_addr = ADDR_L(ctx->enc_pkey);
	req->cipher_destin_addr_hi = ADDR_H(ctx->enc_pkey);
}

static void sec_alg_ablkcipher_init_enc(struct sec_alg_ablkcipher_ctx *ctx,
					int alg, const uint8_t *key,
					unsigned int keylen)
{
	struct sec_bd_info *req = &ctx->enc_req;

	req->cipher = SEC_CIPHER_ENCRYPT;
	memcpy(ctx->enc_key, key, keylen);
	sec_alg_ablkcipher_com_init(ctx, req, alg);
}

static void sec_alg_ablkcipher_init_dec(struct sec_alg_ablkcipher_ctx *ctx,
					int alg, const uint8_t *key,
					unsigned int keylen)
{
	struct sec_bd_info *req = &ctx->dec_req;

	req->cipher = SEC_CIPHER_DECRYPT;
	memcpy(ctx->dec_key, key, keylen);
	sec_alg_ablkcipher_com_init(ctx, req, alg);
}


static int sec_alg_ablkcipher_init_context(struct sec_alg_ablkcipher_ctx *ctx,
					    const uint8_t *key,
					    unsigned int keylen,
					    const char *alg)
{
	int sec_alg;

	if (sec_alg_info_trans(keylen, &sec_alg, alg))
		goto bad_info;

	sec_alg_ablkcipher_init_enc(ctx, sec_alg, key, keylen);
	sec_alg_ablkcipher_init_dec(ctx, sec_alg, key, keylen);
	return 0;
bad_info:
	crypto_tfm_set_flags(ctx->tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}
static void sec_destroy_sec_sgl(struct sec_hw_sgl *sgl,
			dma_addr_t psec_sgl, struct device *dev)
{
	size_t sz = sizeof(struct sec_hw_sgl);
	int n = sgl->entry_sum_in_chain, sg_nctr = 0, total = 0;
	struct sec_hw_sgl *temp, *temp1;

	temp = sgl;
	for (; total < n;) {
		if (sg_nctr < HISI_MAX_SGE_NUM) {
			if (!dma_mapping_error(dev,
				temp->sge_entrys[sg_nctr].buf)) {
				dma_unmap_single(dev,
					temp->sge_entrys[sg_nctr].buf,
					temp->sge_entrys[sg_nctr].len,
					DMA_BIDIRECTIONAL);
				sg_nctr++;
				total++;
			} else
				break;
		} else {
			temp1 = temp->next;
			if (!dma_mapping_error(dev, temp->next_sgl)) {
				dma_unmap_single(dev, temp->next_sgl,
					sz, DMA_BIDIRECTIONAL);
				kfree(temp);
			} else {
				kfree(temp);
				kfree(temp1);
				break;
			}
			temp = temp1;
			sg_nctr = 0;
		}
	}
	if (dma_mapping_error(dev, psec_sgl)) {
		kfree(sgl);
		return;
	} else
		dma_unmap_single(dev, psec_sgl, sz, DMA_BIDIRECTIONAL);
}

static struct sec_hw_sgl *sec_setup_sec_sgl(dma_addr_t *psecsgl,
				struct scatterlist *sgl, struct device *dev)
{
	struct sec_hw_sgl *sec_sgl, *temp, *temp1;
	dma_addr_t psec_sgl, ptemp;
	struct scatterlist *sg;
	int n = sg_nents(sgl), i, sg_nctr = 0, total = 0, ret;
	size_t sz = sizeof(struct sec_hw_sgl);

	if (unlikely(!n))
		return ERR_PTR(-EINVAL);
	sec_sgl = kzalloc_node(sz, GFP_ATOMIC | GFP_DMA, dev_to_node(dev));
	if (unlikely(!sec_sgl))
		return ERR_PTR(-ENOMEM);

	psec_sgl = dma_map_single(dev, sec_sgl, sz, DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(dev, psec_sgl))) {
		ret = -ENOMEM;
		goto err;
	}
	temp = sec_sgl;
	for_each_sg(sgl, sg, n, i) {
		if (!sg->length)
			continue;

		temp->sge_entrys[sg_nctr].buf = dma_map_single(dev,
						sg_virt(sg), sg->length,
						DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(dev,
			temp->sge_entrys[sg_nctr].buf))) {
			ret = -ENOMEM;
			goto err;
		}
		temp->sge_entrys[sg_nctr].len = sg->length;

		sg_nctr++;
		total++;
		temp->data_bytes_in_sgl += sg->length;
		sec_sgl->entry_sum_in_chain = total;
		temp->entry_sum_in_sgl = sg_nctr;
		if (sg_nctr == HISI_MAX_SGE_NUM) {
			temp1 = kzalloc_node(sz, GFP_ATOMIC | GFP_DMA, dev_to_node(dev));
			if (unlikely(!temp1)) {
				ret = -ENOMEM;
				goto err;
			}
			temp->next = temp1;
			ptemp = dma_map_single(dev, temp1, sz, DMA_BIDIRECTIONAL);
			temp->next_sgl = ptemp;
			if (unlikely(dma_mapping_error(dev, ptemp))) {
				ret = -ENOMEM;
				goto err;
			}
			temp = temp1;
			sg_nctr = 0;
		}
	}
	temp->next_sgl = 0;
	*psecsgl = psec_sgl;

	return sec_sgl;
err:
	sec_destroy_sec_sgl(sec_sgl, psec_sgl, dev);
	*psecsgl = 0;
	return ERR_PTR(ret);
}
static void sec_free_opdata(struct wd_queue *queue,
			struct sec_crypto_request *sec_req)
{
	struct device *dev = queue->wdev->dev;

	sec_destroy_sec_sgl(sec_req->sec_udata.in,
			sec_req->sec_udata.dma_in, dev);
	if (sec_req->ablkcipher_req->src != sec_req->ablkcipher_req->dst)
		sec_destroy_sec_sgl(sec_req->sec_udata.out,
			sec_req->sec_udata.dma_out, dev);
	if (sec_req->sec_udata.iv) {
		dma_unmap_single(dev, sec_req->sec_udata.dma_iv,
			   HISI_SEC_MAX_CIPHER_IV, DMA_TO_DEVICE);
		sec_req->sec_udata.dma_iv = 0;
		kfree(sec_req->sec_udata.iv);
		sec_req->sec_udata.iv = NULL;
	}
}
static int sec_create_opdata(struct wd_queue *queue,
			       struct scatterlist *sgl,
			       struct scatterlist *sglout,
			       struct sec_crypto_request *sec_req)
{
	struct device *dev = queue->wdev->dev;
	struct sec_hw_sgl *inbufs;
	struct sec_hw_sgl *outbufs;
	dma_addr_t pinbufs;
	dma_addr_t poutbufs = 0;
	int ret;
	void *iv;

	iv = kzalloc_node(HISI_SEC_MAX_CIPHER_IV,
		GFP_ATOMIC|GFP_DMA, dev_to_node(dev));
	if (unlikely(!iv))
		return -ENOMEM;

	inbufs = sec_setup_sec_sgl(&pinbufs, sgl, dev);
	if (IS_ERR(inbufs)) {
		dev_err(dev, "sec_setup_sec_sgl for in sgl fail!\n");
		return PTR_ERR(inbufs);
	}
	sec_req->sec_udata.in = inbufs;
	sec_req->sec_udata.dma_in = pinbufs;
	if (sgl != sglout) {
		outbufs = sec_setup_sec_sgl(&poutbufs, sglout, dev);
		if (IS_ERR(outbufs)) {
			sec_destroy_sec_sgl(inbufs, pinbufs, dev);
			dev_err(dev, "sec_setup_sec_sgl for out sgl fail!\n");
			ret = PTR_ERR(outbufs);
			goto err;
		}
		sec_req->sec_udata.out = outbufs;
		sec_req->sec_udata.dma_out = poutbufs;
		sec_req->req.de = 1;
	} else
		sec_req->req.de = 0;

	sec_req->sec_udata.dma_iv = dma_map_single(dev, iv,
		HISI_SEC_MAX_CIPHER_IV, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, sec_req->sec_udata.dma_iv))) {
		sec_free_opdata(queue, sec_req);
		ret = -ENOMEM;
		goto err;
	}
	sec_req->sec_udata.iv = iv;

	return 0;
err:
	dev_err(dev, "Failed to create operatinal data for sec queue\n");

	return ret;
}

static int sec_alg_ablkcipher_setkey(struct crypto_ablkcipher *tfm,
				     const u8 *key, unsigned int keylen)
{
	struct sec_alg_ablkcipher_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct device *dev = NULL;
	const char *alg = crypto_tfm_alg_name(&tfm->base);

	spin_lock(&ctx->lock);
	if (ctx->queue) {
		/* rekeying */
		dev = ctx->queue->wdev->dev;
		memset(ctx->enc_key, 0, HISI_SEC_MAX_CIPHER_KEY);
		memset(ctx->dec_key, 0, HISI_SEC_MAX_CIPHER_KEY);
	} else {
		/* new key */
		int id = smp_processor_id();
		struct wd_dev *sec;
		struct wd_queue *queue;

		/* Zaibo: 0 is used, i don't know why this id is not right now */
		id = 0;
		sec = hisi_get_sec_device(id);
		if (!sec) {
			spin_unlock(&ctx->lock);
			return -ENODEV;
		}
		queue = hisi_alloc_crypto_queue(sec);
		if (!queue) {
			spin_unlock(&ctx->lock);
			return -ENODEV;
		}
		ctx->queue = queue;
		dev = ctx->queue->wdev->dev;
	}
	spin_unlock(&ctx->lock);
	ctx->enc_pkey = dma_map_single(dev, ctx->enc_key,
		HISI_SEC_MAX_CIPHER_KEY, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, ctx->enc_pkey)))
		return -ENOMEM;
	ctx->dec_pkey = dma_map_single(dev, ctx->dec_key,
		HISI_SEC_MAX_CIPHER_KEY, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, ctx->dec_pkey)))
		goto out_free_enc;
	if (sec_alg_ablkcipher_init_context(ctx, key, keylen, alg))
		goto out_free_all;

	return 0;

out_free_all:
	dma_unmap_single(dev, ctx->dec_pkey,
		HISI_SEC_MAX_CIPHER_KEY, DMA_TO_DEVICE);
	ctx->dec_pkey = 0;
out_free_enc:
	dma_unmap_single(dev, ctx->enc_pkey,
		HISI_SEC_MAX_CIPHER_KEY, DMA_TO_DEVICE);
	ctx->enc_pkey = 0;
	return -ENOMEM;
}

static int sec_alg_ablkcipher_crypto(struct ablkcipher_request *req, int direct)
{
	struct crypto_ablkcipher *atfm = crypto_ablkcipher_reqtfm(req);
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(atfm);
	struct sec_alg_ablkcipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct sec_crypto_request *sec_req = ablkcipher_request_ctx(req);
	struct sec_bd_info *msg;
	int ret, ctr = 0;

	memset(sec_req, 0, sizeof(*sec_req));
	msg = &sec_req->req;
	if (direct)
		memcpy(msg, &(ctx->enc_req), sizeof(*msg));
	else
		memcpy(msg, &(ctx->dec_req), sizeof(*msg));

	ret = sec_create_opdata(ctx->queue, req->src, req->dst, sec_req);
	if (unlikely(ret))
		return ret;

	sec_req->ablkcipher_ctx = ctx;
	sec_req->ablkcipher_req = req;
	sec_req->cb = sec_ablkcipher_alg_callback;
	*(uint64_t *)(&sec_req->req.mac_addr) = (uint64_t)sec_req;
	sec_req->req.cipher_gran_size_mid = req->nbytes >> 16;
	sec_req->req.flag_or_cipher_gran_size_hi = req->nbytes >> 20;
	sec_req->req.cipher_gran_size_low = req->nbytes;
	sec_req->req.gran_num = 1;
	sec_req->req.cipher_len_offset = 0;
	sec_req->req.addr_type = 1;

	/* sec_req->req.data_addr_hi is filled by the this setting */
	sec_req->req.data_addr = ADDR_L(sec_req->sec_udata.dma_in);
	sec_req->req.data_addr_hi = ADDR_H(sec_req->sec_udata.dma_in);
	if (sec_req->req.de){
	    sec_req->req.cipher_destin_addr =
		    ADDR_L(sec_req->sec_udata.dma_out);
	    sec_req->req.cipher_destin_addr_hi =
		    ADDR_H(sec_req->sec_udata.dma_out);
	} else {
	    sec_req->req.cipher_destin_addr = ADDR_L(sec_req->sec_udata.dma_in);
	    sec_req->req.cipher_destin_addr_hi =
		    ADDR_H(sec_req->sec_udata.dma_in);
	}
	memcpy(sec_req->sec_udata.iv, req->info, tfm->crt_ablkcipher.ivsize);
	sec_req->req.cipher_iv_addr = ADDR_L(sec_req->sec_udata.dma_iv);
	sec_req->req.cipher_iv_addr_hi= ADDR_H(sec_req->sec_udata.dma_iv);
	do {
		ret = hisi_sec_queue_send((void *)ctx->queue, (void *)msg);
	} while (ret == -EAGAIN && ctr++ < 10);

	if (unlikely(ret == -EAGAIN)) {
		sec_free_opdata(ctx->queue, sec_req);
		return -EBUSY;
	}
	return -EINPROGRESS;
}

static int sec_alg_ablkcipher_encrypt(struct ablkcipher_request *req)
{
	return sec_alg_ablkcipher_crypto(req, 1);
}

static int sec_alg_ablkcipher_decrypt(struct ablkcipher_request *req)
{
	return sec_alg_ablkcipher_crypto(req, 0);
}

static int sec_alg_ablkcipher_init(struct crypto_tfm *tfm)
{
	struct sec_alg_ablkcipher_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(struct sec_alg_ablkcipher_ctx));
	spin_lock_init(&ctx->lock);
	tfm->crt_ablkcipher.reqsize = sizeof(struct sec_crypto_request);
	ctx->tfm = tfm;

	ctx->enc_key = kzalloc(HISI_SEC_MAX_CIPHER_KEY, GFP_KERNEL | GFP_DMA);
	if (!ctx->enc_key)
		return -ENOMEM;

	ctx->dec_key = kzalloc(HISI_SEC_MAX_CIPHER_KEY, GFP_KERNEL | GFP_DMA);
	if (!ctx->dec_key)
		return -ENOMEM;

	return 0;
}

static void sec_alg_ablkcipher_exit(struct crypto_tfm *tfm)
{
	struct sec_alg_ablkcipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct wd_queue *queue = ctx->queue;
	struct device *dev;

	if (!queue)
		return;

	dev = HISI_SEC_Q_DEV(queue);
	if (ctx->enc_key) {
		kfree(ctx->enc_key);
		ctx->enc_key = NULL;
	}
	if (ctx->dec_key) {
		kfree(ctx->dec_key);
		ctx->dec_key = NULL;
	}
	hisi_release_crypto_queue(queue);
	ctx->queue = NULL;
}

static struct crypto_alg sec_algs[] = { {
	.cra_name = "cbc(aes)",
	.cra_driver_name = "hisi_sec_aes_cbc",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
		},
	},
}, {
	.cra_name = "ctr(aes)",
	.cra_driver_name = "hisi_sec_aes_ctr",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
		},
	},
}, {
	.cra_name = "xts(aes)",
	.cra_driver_name = "hisi_sec_aes_xts",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = 2 * AES_MIN_KEY_SIZE,
			.max_keysize = 2 * AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
		},
	},
}, {
	.cra_name = "cbc(des)",
	.cra_driver_name = "hisi_sec_des_cbc",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = DES_KEY_SIZE,
			.max_keysize = DES_KEY_SIZE,
			.ivsize = DES_BLOCK_SIZE,
		},
	},
}, {
	.cra_name = "cbc(des3_ede)",
	.cra_driver_name = "hisi_sec_3des_cbc",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES3_EDE_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = DES3_EDE_KEY_SIZE,
			.max_keysize = DES3_EDE_KEY_SIZE,
			.ivsize = DES3_EDE_BLOCK_SIZE,
		},
	},
} , {
	.cra_name = "ecb(aes)",
	.cra_driver_name = "hisi_sec_aes_ecb",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
		},
	},
}, {
	.cra_name = "ecb(des)",
	.cra_driver_name = "hisi_sec_des_ecb",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = DES_KEY_SIZE,
			.max_keysize = DES_KEY_SIZE,
			.ivsize = DES_BLOCK_SIZE,
		},
	},
}, {
	.cra_name = "ecb(des3_ede)",
	.cra_driver_name = "hisi_sec_3des_ecb",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES3_EDE_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct sec_alg_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_type = &crypto_ablkcipher_type,
	.cra_module = THIS_MODULE,
	.cra_init = sec_alg_ablkcipher_init,
	.cra_exit = sec_alg_ablkcipher_exit,
	.cra_u = {
		.ablkcipher = {
			.setkey = sec_alg_ablkcipher_setkey,
			.decrypt = sec_alg_ablkcipher_decrypt,
			.encrypt = sec_alg_ablkcipher_encrypt,
			.min_keysize = DES3_EDE_KEY_SIZE,
			.max_keysize = DES3_EDE_KEY_SIZE,
			.ivsize = DES3_EDE_BLOCK_SIZE,
		},
	},
} };

int hisi_sec_algs_register(void)
{
	int ret = 0, i;

	mutex_lock(&algs_lock);
	if (++active_devs != 1)
		goto unlock;

	for (i = 0; i < ARRAY_SIZE(sec_algs); i++)
		sec_algs[i].cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER |
			CRYPTO_ALG_ASYNC;

	ret = crypto_register_algs(sec_algs, ARRAY_SIZE(sec_algs));

unlock:
	mutex_unlock(&algs_lock);
	return ret;
}

void hisi_sec_algs_unregister(void)
{
	mutex_lock(&algs_lock);
	if (--active_devs != 0)
		goto unlock;

	crypto_unregister_algs(sec_algs, ARRAY_SIZE(sec_algs));

unlock:
	mutex_unlock(&algs_lock);
}
