/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef __WD_CIPHER_H
#define __WD_CIPHER_H
#include <stdlib.h>
#include <errno.h>

#include "../../drivers/crypto/hisilicon/wd/wd_usr_if.h"
#include "../../drivers/crypto/hisilicon/wd/wd_cipher_usr_if.h"

enum wd_cipher_op {
	WD_CIPHER_INVALID,
	WD_CIPHER_ENCRYPT,
	WD_CIPHER_DECRYPT,
	WD_CIPHER_PSSTHRH,
};

struct wd_cipher_msg {
	/* First 8 bytes of the message must indicate algorithm */
	union {
		char  *alg;
		__u64 pading;
	};
	
	__u32 keylen	: 16;
	__u32 status	: 16;
	__u32 mode 	: 16;
	__u32 optype	: 16;

	/* Address flags (aflags) indicate memory attributions of user
	  * which should be re-formated to match the capa of queue.
	  * For example, we can use memcpy/re-scatter.
	  */
	__u32 aflags;
	__u32 dsize;
	__u64 udata;
	__u64 key;
	__u64 src;
	__u64 dst;
	__u64 iv;
};
void *wd_create_cipher_ctx(struct wd_queue *q, __u8 *key, __u32 keylen,
					enum wd_cipher_op op);
int wd_do_cipher(void *ctx, char *in, char *out, char *iv, int size);
void wd_del_cipher_ctx(void *ctx);
void wd_set_cipher_key(void *ctx, __u64 key);
#endif
