/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "test_cipher_common.h"
#include "../wd_dummy.h"

int main(int argc, char *argv[])
{
	int ret, size;
	unsigned char *src, *dst;
	void *ctx;
	char *alg;
	int pkt_len;
#ifdef WD_SHARE_ALL_USED
	struct timeval start_tval, end_tval;
	float time, speed;
	void *temp_src, *temp_dst;
	int i, loops, bloop, count;
#endif
	struct wd_capa capa;
	struct wd_queue q, q1;

#ifdef WD_SHARE_ALL_USED
	if (argv[1]) {
		bloop = loops = strtoul(argv[1], NULL, 10);
		if (loops == 0)
			bloop = loops = 1;
		if (loops > 0x10000) {
			loops = 0x10000;
			bloop = strtoul(argv[1], NULL, 10);
		}
	} else
		bloop = loops = 1;
#endif

	if (argv[2]) {
		pkt_len = strtoul(argv[2], NULL, 10);
		if (pkt_len == 0 || pkt_len > 1984) {
			printf("pkt_len error!\n");
			return -1;
		}
	} else
		pkt_len = 16;

	alg = cbc_aes_128;
	init_capa(&capa, alg);
	ret = wd_request_queue(&q, &capa);
	if (ret) {
		printf("wd_request_queue fail!\n");
		return -1;
	}
	ret = wd_dummy_request_memcpy_queue(&q1, 0x400);
	if (ret) {
		printf("wd_request_queue q1 fail!\n");
		return -1;
	}

	ctx = wd_create_cipher_ctx(&q, (__u8 *)aucKey_aes_cbc_128,
			sizeof(aucKey_aes_cbc_128),
			WD_CIPHER_ENCRYPT);
	SYS_ERR_COND(!ctx, "wd_create_cipher_ctx");

#ifdef WD_SHARE_ALL_USED /* use user's vritual address */
	size = pkt_len;
	src = malloc(size * loops);
	SYS_ERR_COND(!src, "malloc src");
	memcpy(src, aucDataIn_aes_cbc_128, size);
	dst = malloc(size * loops);
	SYS_ERR_COND(!dst, "malloc dst");
	memset(dst, 0, size * loops);

	gettimeofday(&start_tval, NULL);
again:
	temp_src = src, temp_dst = dst;
	i = loops;

	while (i--) {
		count++;
		if (count > bloop)
			break;
		ret = wd_do_cipher(ctx, (char *)temp_src, (char *)temp_dst,
			(char *)aucIvIn_aes_cbc_128, size);
		SYS_ERR_COND(ret, "wd_do_cipher(wd_del_cipher_ctx should be done automatically)");
		temp_src += size;
		temp_dst += size;
		if (i == 0)
			goto again;
	}
	gettimeofday(&end_tval, NULL);

	time = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 + end_tval.tv_usec -start_tval.tv_usec);
	speed = 1 / (time /count);
	printf("\r\n%s cipher time %0.0f us, pkt len = %d bytes, %0.3f Mpps", "aes_cbc_128",
		time, pkt_len, speed);
#else /* Use IOVA  */
	void *key, *iv;
	void *a;
#define ASIZE (1024*1024)

	/* Allocate some space and setup a DMA mapping */
	a = mmap(NULL, ASIZE,
	  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	SYS_ERR_COND(ret, "mmap a\n");
	ret = wd_mem_share(&q, a, ASIZE, 0);
	SYS_ERR_COND(ret, "mem share fail!\n");
	size = sizeof(aucDataIn_aes_cbc_128);
	src = a;
	memcpy(src, aucDataIn_aes_cbc_128, size);
	dst = a + size;
	memset(dst, 0, size);
	key = dst + size;
	memcpy(key, aucKey_aes_cbc_128, sizeof(aucKey_aes_cbc_128));
	iv = key + sizeof(aucKey_aes_cbc_128);
	memcpy(iv, aucIvIn_aes_cbc_128, sizeof(aucIvIn_aes_cbc_128));
	wd_set_cipher_key(ctx, (__u64) key);
	ret = wd_do_cipher(ctx, (char *)src, (char *)dst,
		(char *)iv, size);
	SYS_ERR_COND(ret, "wd_do_cipher FAIL!");
#endif	
	wd_del_cipher_ctx(ctx);
	check_result(dst);
#ifdef WD_SHARE_ALL_USED
	free(src);
	free(dst);
#else
	wd_mem_unshare(&q, a, ASIZE);
	munmap(a, ASIZE);
#endif
	wd_release_queue(&q);
	wd_release_queue(&q1);

	return EXIT_SUCCESS;
}

