/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../wd_dummy.h"

#define CPSZ 4096

#define SYS_ERR_COND(cond, msg) if(cond) { \
	perror(msg); \
	exit(EXIT_FAILURE); }


static void _do_test(struct wd_queue *q)
{
	int ret, i;
	char *s, *t;

	//init user data (to be copied)
	s = malloc(CPSZ);
	SYS_ERR_COND(!s, "malloc saddr");
	memset(s, 'x', CPSZ);

	ret = wd_mem_share(q, s, CPSZ, 0);
	SYS_ERR_COND(!s, "mem_share src");

	t = malloc(CPSZ);
	SYS_ERR_COND(!t, "malloc taddr");
	memset(t, 'y', CPSZ);

	ret = wd_mem_share(q, t, CPSZ, 0);
	SYS_ERR_COND(!t, "mem_share tgt");

	ret = wd_dummy_memcpy(q, t, s, CPSZ);
	SYS_ERR_COND(ret, "acce cpy");

	//verify result
	for (i = 0; i < CPSZ; i++) {
		if(t[i] != 'x') {
			printf("verify result fail on %d\n", i);
			break;
		}

	}

	if (i == CPSZ)
		printf("test success\n");

	wd_mem_unshare(q, s, CPSZ);
	wd_mem_unshare(q, t, CPSZ);
	free(s);
	free(t);
}

#define REP_TEST 10
int main(int argc, char *argv[])
{
	struct wd_queue q;
	int ret, i;

	ret = wd_dummy_request_memcpy_queue(&q, 4096);
	SYS_ERR_COND(ret, "wd_request_queue");

	for (i = 0; i < REP_TEST; i++)
		_do_test(&q);

	wd_release_queue(&q);

	return EXIT_SUCCESS;
}
