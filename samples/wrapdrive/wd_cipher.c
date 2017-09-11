/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "wd.h"
#include "wd_cipher.h"
#include "wd_util.h"

struct wd_cipher_ctx {
	struct wd_cipher_msg msg;
	struct wd_queue *q;
	char *iv[32];
};

/* Before initiate this context, we should get a queue from WD */
void *wd_create_cipher_ctx(struct wd_queue *q, __u8 *key, __u32 keylen,
					enum wd_cipher_op op)
{
	struct wd_cipher_ctx *context;
	struct wd_aalg_calg_param *ci_para;
	struct wd_capa *capa;

	if (!q || !key || !keylen) {
		WD_ERR("param err!\n");
		return NULL;
	}
	context = (struct wd_cipher_ctx *)malloc(sizeof(*context));
	if (!context) {
		WD_ERR("malloc err!\n");
		return NULL;
	}
	memset(context, 0, sizeof(*context));
	capa = &q->capa;
	ci_para = (struct wd_aalg_calg_param *)capa->priv;
	if (ci_para->cparam.key_size != keylen) {
		WD_ERR("key size mismatch %d=!%d!\n",
			ci_para->cparam.key_size, keylen);
		goto release_ctx;
	}
	context->msg.key = (__u64)key;

	/* For this ctx, only user virtual memory is supported */
	/* Use IOVA at first */
	context->msg.optype = op;

	 /* Get them from 'capa' of queue */
	context->msg.keylen = ci_para->cparam.key_size;
	context->msg.alg = capa->alg;

	context->q = q;

	return context;
release_ctx:
	free(context);

	return NULL;
}

int wd_do_cipher(void *ctx, char *in, char *out, char *iv, int size)
{
	struct wd_cipher_ctx *context = (struct wd_cipher_ctx *)ctx;
	struct wd_cipher_msg *msg = &context->msg;
	int ret;
	void *resp;

	msg->iv = (__u64)iv;
	msg->src = (__u64)in;
	msg->dst = (__u64)out;
	msg->dsize = (__u32)size;
	msg->status = 0;

	ret = wd_send(context->q, (void *)msg);
	if (ret < 0) {
		WD_ERR ("wd send request fail!\n");
		return -1;
	}
	ret = wd_recv_sync(context->q, (void **)&resp, 0);
	if (ret < 0) {
		WD_ERR ("wd recv fail!\n");
		return -1;
	} else if (ret == 0) {
		WD_ERR ("wd recv nothing!\n");
		return -1;
	} else if (ret == 1)
		return 0;
	else
		return -1;

	return -1;
}

void wd_del_cipher_ctx(void *ctx)
{
	free(ctx);
}

void wd_set_cipher_key(void *ctx, __u64 key)
{
	struct wd_cipher_ctx *context = (struct wd_cipher_ctx *)ctx;
	context->msg.key = (__u64)key;
}
