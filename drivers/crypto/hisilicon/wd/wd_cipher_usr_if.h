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

#ifndef __WD_CIPHER_IF_H
#define __WD_CIPHER_IF_H


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


#endif
