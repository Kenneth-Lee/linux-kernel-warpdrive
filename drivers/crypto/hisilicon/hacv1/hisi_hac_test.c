/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/rng.h>
#include <crypto/drbg.h>
#include <crypto/akcipher.h>
#include <crypto/kpp.h>
#include <crypto/acompress.h>

#include "hisi_hac_test.h"

#define CRYPTO_HISI_HAC_TEST_VERSION "1.0"
#define HAC_XBUFSIZE			8
#define HAC_MAX_IVLEN			32
#define HAC_DECRYPT			0
#define HAC_ENCRYPT			1


static int diff_dst = 1;
static int enc = HAC_ENCRYPT;


static void hac_hexdump(unsigned char *buf, unsigned int len)
{
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
			16, 1,
			buf, len, false);
}

static void hac_tcrypt_complete(struct crypto_async_request *req, int err)
{
	struct hac_tcrypt_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}
static int hac_tcrypt_alloc_buf(char *buf[HAC_XBUFSIZE])
{
	int i;

	for (i = 0; i < HAC_XBUFSIZE; i++) {
		buf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!buf[i])
			goto err_free_buf;
	}

	return 0;

err_free_buf:
	while (i-- > 0)
		free_page((unsigned long)buf[i]);

	return -ENOMEM;
}

static void hac_tcrypt_free_buf(char *buf[HAC_XBUFSIZE])
{
	int i;

	for (i = 0; i < HAC_XBUFSIZE; i++)
		free_page((unsigned long)buf[i]);
}

static int __init hac_tcrypt_test_init(void)
{
	struct crypto_skcipher *tfm;
	int type = 0, mask = 0;
	const char *driver = "hisi_sec_aes_cbc", *algo;
	unsigned int ivsize;
	struct hac_tcrypt_result result;
	struct skcipher_request *req;
	int i, j, ret = 0;
	char iv[HAC_MAX_IVLEN];
	int align_offset = 0;
	void *data;
	char *xbuf[HAC_XBUFSIZE];
	char *xoutbuf[HAC_XBUFSIZE];
	char *d, *e;
	char *q;
	struct scatterlist sg[8];
	struct scatterlist sgout[8];

	if (hac_tcrypt_alloc_buf(xbuf))
		goto out_nobuf;
	if (diff_dst && hac_tcrypt_alloc_buf(xoutbuf))
		goto out_nooutbuf;
	if (diff_dst)
		d = "-ddst";
	else
		d = "";
	if (enc == HAC_ENCRYPT)
	        e = "encryption";
	else
		e = "decryption";
	tfm = crypto_alloc_skcipher(driver, type, mask);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "alg: skcipher: Failed to load transform for "
		       "%s: %ld\n", driver, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	algo = crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));
	ivsize = crypto_skcipher_ivsize(tfm);
	init_completion(&result.completion);
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("alg: skcipher%s: Failed to allocate request for %s\n",
						       d, algo);
		goto out;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
		hac_tcrypt_complete, &result);
	j = 0;
	for (i = 0; i < ARRAY_SIZE(aes_cbc_enc_tv_template); i++) {
		struct hac_cipher_testvec *template = aes_cbc_enc_tv_template;
		if (template[i].np && !template[i].also_non_np)
			continue;
		if (fips_enabled && template[i].fips_skip)
			continue;
		if (template[i].iv)
			memcpy(iv, template[i].iv, ivsize);
		else
			memset(iv, 0, HAC_MAX_IVLEN);
		j++;
		ret = -EINVAL;
		if (WARN_ON(align_offset + template[i].ilen > PAGE_SIZE))
			goto out;
		data = xbuf[0];
		data += align_offset;
		memcpy(data, template[i].input, template[i].ilen);
		crypto_skcipher_clear_flags(tfm, ~0);
		if (template[i].wk)
			crypto_skcipher_set_flags(tfm,
						  CRYPTO_TFM_REQ_WEAK_KEY);
		ret = crypto_skcipher_setkey(tfm, template[i].key,
					     template[i].klen);
		if (template[i].fail == !ret) {
			pr_err("alg: skcipher%s: setkey failed on test %d for %s: flags=%x\n",
			       d, j, algo, crypto_skcipher_get_flags(tfm));
			goto out;
		} else if (ret)
			continue;
		sg_init_one(&sg[0], data, template[i].ilen);
		if (diff_dst) {
			data = xoutbuf[0];
			data += align_offset;
			sg_init_one(&sgout[0], data, template[i].ilen);
		}
		skcipher_request_set_crypt(req, sg, (diff_dst) ? sgout : sg,
					   template[i].ilen, iv);
		ret = enc ? crypto_skcipher_encrypt(req) :
			    crypto_skcipher_decrypt(req);
		switch (ret) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			wait_for_completion_timeout(&result.completion, 1000);
			reinit_completion(&result.completion);
			ret = result.err;
			if (!ret)
				break;
			/* fall through */
		default:
			pr_err("alg: skcipher%s: %s failed on test %d for %s: ret=%d\n",
			       d, e, j, algo, -ret);
			goto out;
		}
		q = data;
		if (memcmp(q, template[i].result, template[i].rlen)) {
			pr_err("alg: skcipher%s: Test %d failed (invalid result) on %s for %s\n",
			       d, j, e, algo);
			hac_hexdump(q, template[i].rlen);
			ret = -EINVAL;
			goto out;
		}
		if (template[i].iv_out &&
		    memcmp(iv, template[i].iv_out,
			   crypto_skcipher_ivsize(tfm))) {
			pr_err("alg: skcipher%s: Test %d failed (invalid output IV) on %s for %s\n",
			       d, j, e, algo);
			hac_hexdump(iv, crypto_skcipher_ivsize(tfm));
			ret = -EINVAL;
			goto out;
		}
	}
	printk(KERN_ERR "%s is tested pass!\n", algo);
	ret = 0;
out:
	skcipher_request_free(req);
	if (diff_dst)
		hac_tcrypt_free_buf(xoutbuf);
	crypto_free_skcipher(tfm);
out_nooutbuf:
	hac_tcrypt_free_buf(xbuf);
out_nobuf:
	return ret;
}

static void __exit hac_tcrypt_test_exit(void)
{
}

module_init(hac_tcrypt_test_init);
module_exit(hac_tcrypt_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Hisilicon Security Accelerators Testing based on Crypto");
MODULE_VERSION(CRYPTO_HISI_HAC_TEST_VERSION);
