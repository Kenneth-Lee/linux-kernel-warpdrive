/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


/* This file is shared bewteen WD user and kernel space, which is
* including attibutions of user caring for
*/

#ifndef __HISI_SEC_USR_IF_H
#define __HISI_SEC_USR_IF_H

#include <linux/types.h>
#include "../wd/wd_usr_if.h"

#define WD_PKT_CPY_THRESHOLD 1984

/* General symmetric cipher core algorithms */
enum wd_cipher_alg {
	WD_CA_NO_CIPHER,
	WD_CA_AES,
	WD_CA_DES,
	WD_CA_3DES,
	WD_CA_ZUC,
	WD_CA_KASUMI,
	WD_CA_SNOW3G,
	WD_CA_TWOFISH,
	WD_CA_BLOWFISH,
	WD_CA_RC4,
	WD_CA_RC2,
	WD_CA_CAMELLIA,
	WD_CA_IDEA,
	WD_CA_CAST5,
};

/* General symmetric block cipher mode */
enum wd_cipher_mode {
	WD_CM_NO_MODE,
	WD_CM_CBC,
	WD_CM_ECB,
	WD_CM_CTR,
	WD_CM_GCM,
	WD_CM_CCM,
	WD_CM_XTS,
	WD_CM_OFB,
	WD_CM_CFB,
	WD_CM_WRAP,
};

/* Auth/digest algorithms are defined as the following */
enum wd_auth_alg {
	WD_AA_MD2,
	WD_AA_MD4,
	WD_AA_MD5,
	WD_AA_SHA1,
	WD_AA_SHA160,
	WD_AA_SHA224,
	WD_AA_SHA256,
	WD_AA_SHA384,
	WD_AA_SHA512,
	WD_AA_HMAC_SHA160_96,
	WD_AA_HMAC_SHA160,
	WD_AA_HMAC_SHA224_96,
	WD_AA_HMAC_SHA224,
	WD_AA_HMAC_SHA256_96,
	WD_AA_HMAC_SHA256,
	WD_AA_HMAC_MD5_96,
	WD_AA_HMAC_MD5,
	WD_AA_AES_XCBC_MAC_96,
	WD_AA_AES_XCBC_PRF_128,
	WD_AA_AES_CMAC,
};

/* Common asymmetric algorithms for cipher/auth/key generate */
enum wd_asym_alg {
	WD_ASA_RSA_KEY_GEN,
	WD_ASA_RSA_ENCRYPTO,
	WD_ASA_RSA_DECRYPTO,
	WD_ASA_DSA_VERIFY,
	WD_ASA_DSA_DIGEST,
	WD_ASA_ECC_ENCRYPTO,
	WD_ASA_ECC_DECRYPTO,
	WD_ASA_ECDSA_VERIFY,
	WD_ASA_ECDSA_DIGEST,
};

/* Common key exchange algorithms for calculating public/private keys */
enum wd_kex_alg {
	WD_KA_DH_GEN_PUB_KEY,
	WD_KA_DH_GEN_PRI_KEY,
	WD_KA_ECDH_GEN_PUB_KEY,
	WD_KA_ECDH_GEN_PRI_KEY,
};

/* Common de-compression algorithms */
enum wd_dc_alg {
	WD_DA_DEFLATE,
	WD_DA_INFLATE,
	WD_DA_LZS_DECOMP,
	WD_DA_LZ4_DECOMP,
	WD_DA_LZW_DECOMP,
	WD_DA_LZ77_DECOMP,
	WD_DA_LZS_COMP,
	WD_DA_LZ4_COMP,
	WD_DA_LZW_COMP,
	WD_DA_LZ77_COMP,
};
/* to extend more algorithms */

/* Cipher algorithms' parameters */
struct wd_calg_param {
	__u8 key_size;
	__u8 iv_size;
	__u8 pad[2];
};

/* Auth algorithms' parameters */
struct wd_aalg_param {
	__u8 key_size;
	__u8 mac_size;
	struct  {
		__u8 min_size;
		__u8 max_ssize;
		__u8 inc_ssize;
	} aad_ssize;
	__u8 pad[3];
};

/* Cipher-auth chaining algorithms' parameters */
struct wd_aalg_calg_param {
	struct wd_calg_param cparam;
	struct wd_aalg_param aparam;
};

/* Data de-compression algorithms' parameters */
struct wd_zalg_param {
	__u32 win_size;
	__u8 comp_lv	:4;
	__u8 mode	:4;

	/* main algorithm type such as lz77 in deflate */
	__u8 malg_type;

	/* sub algorithm type such as d-huffman in deflate */
	__u8 salg_type;
	__u8 crc_type;
};

/* RSA algorithm relative parameters */
struct wd_rsa_param {
	__u16 mod_n; /* bits of modulus */
	__u16 q_bits; /* bits of Q */
	__u16 p_bits; /* bits of P */
	__u16 is_crt;
};
/* to extend more algorithm parameters*/

//todo: a a prefix for the name
/* WD defines all the algorithm names here */
#define cbc_aes_128		"cbc_aes_128"
#define cbc_aes_192		"cbc_aes_192"
#define cbc_aes_256		"cbc_aes_256"
#define ctr_aes_128		"ctr_aes_128"
#define ctr_aes_192		"ctr_aes_192"
#define ctr_aes_256		"ctr_aes_256"
#define ecb_aes_128		"ecb_aes_128"
#define ecb_aes_192		"ecb_aes_192"
#define ecb_aes_256		"ecb_aes_256"

#define md5			"md5"
#define sha160			"sha160"
#define sha224			"sha224"
#define sha256			"sha256"

#define SECALG_AT_CY_SYM	"at_cy_sym"
#define SECALG_AT_CY_AUTH	"at_cy_auth"
#define	SECALG_AT_CY_SYM_AUTH	"at_cy_sym_auth"
#define SECALG_AT_CY_AUTH_SYM	"at_cy_auth_sym"

#define HISI_SEC_V1_API		"hisi_sec_v1"


#endif
