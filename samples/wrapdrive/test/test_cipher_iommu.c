/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "wd.h"
#include "test_cipher_common.h"
int main(int argc, char *argv[])
{
	int ret, size;
	unsigned char *src, *dst, *iv, *key;
	struct wd_capa capa;
	struct wd_queue q;
	struct wd_cipher_msg msg, *resp;
	void *a;

	init_capa(&capa, cbc_aes_128);

	ret = wd_request_queue(&q, &capa);
	SYS_ERR_COND(ret, "wd_request_queue");

#define ASIZE (1024 * 1024)
	/* Allocate some space and setup a DMA mapping */
	a = mmap(0, ASIZE,
	  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	ret = wd_mem_share(&q, a, ASIZE, 0);
	SYS_ERR_COND(ret, "wd_mem_share a");
	printf("dma map successfully!\n");

	size = sizeof(aucDataIn_aes_cbc_128);
	src = a;
	memcpy(src, aucDataIn_aes_cbc_128, size);
	dst = a + size;
	key = dst + size;
	memcpy(key, aucKey_aes_cbc_128, sizeof(aucKey_aes_cbc_128));
	iv = key + sizeof(aucKey_aes_cbc_128);
	memcpy(iv, aucIvIn_aes_cbc_128, sizeof(aucIvIn_aes_cbc_128));

	init_msg(&msg, &capa);
	msg.iv = (__u64)iv;
	msg.src = (__u64)src;
	msg.dst = (__u64)dst;
	msg.key = (__u64)key;

	ret = wd_send(&q, (void *)&msg);
	SYS_ERR_COND(ret, "wd_send(wd_release_queue should be done automatically)");

	ret = wd_recv_sync(&q, (void **)&resp, 0);
	SYS_ERR_COND(ret != 1, "wd_recv(release_queue should be done automatically)");
	check_result((void *)resp->dst);

	wd_mem_unshare(&q, a, ASIZE);

	printf("unshare uccessfully!\n");

	munmap(a, ASIZE);
	wd_release_queue(&q);

	return EXIT_SUCCESS;
}
