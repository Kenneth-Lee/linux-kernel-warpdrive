/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "test_cipher_common.h"

int main(int argc, char *argv[])
{
	int ret, size;
	unsigned char *src, *dst;
	struct wd_capa capa;
	struct wd_queue q;
	struct wd_cipher_msg msg, *resp;

	init_capa(&capa, cbc_aes_128);

	ret = wd_request_queue(&q, &capa);
	SYS_ERR_COND(ret, "wd_request_queue");

	size = sizeof(aucDataIn_aes_cbc_128);
	src = malloc(size);
	SYS_ERR_COND(!src, "malloc src");
	memcpy(src, aucDataIn_aes_cbc_128, size);
	dst = malloc(size);
	SYS_ERR_COND(!dst, "malloc dst");

	init_msg(&msg, &capa);
	msg.iv = (__u64)aucIvIn_aes_cbc_128;
	msg.src = (__u64)src;
	msg.dst = (__u64)dst;
	msg.key = (__u64)aucKey_aes_cbc_128;

	ret = wd_mem_share(&q, src, size, 0);
	SYS_ERR_COND(ret, "wd_mem_share(src)");

	ret = wd_mem_share(&q, dst, size, 0);
	SYS_ERR_COND(ret, "wd_mem_share(src)");

	ret = wd_send(&q, (void *)&msg);
	SYS_ERR_COND(ret, "wd_send(wd_release_queue should be done automatically)");

	ret = wd_recv_sync(&q, (void **)&resp, 0);
	SYS_ERR_COND(ret, "wd_send(wd_release_queue should be done automatically)");

	check_result((void *)resp->dst);

	wd_mem_unshare(&q, src, size);
	wd_mem_unshare(&q, dst, size);
	wd_release_queue(&q);

	return EXIT_SUCCESS;
}
