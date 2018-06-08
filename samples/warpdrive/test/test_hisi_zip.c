/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include "../wd.h"
#include "comp_hw.h"
#include "../drv/hisi_zip_udrv.h"

#define ASIZE (512*4096)

#define SYS_ERR_COND(cond, msg)		\
do {					\
	if (cond) {			\
		perror(msg);		\
		exit(EXIT_FAILURE);	\
	}				\
} while (0)

#define SAMPLE_SIZE	244
#define COMP_FILE	"/root/compress_data"
#define OP_NUMBER	10240000
#define MAX_PKT		0x8192

char zlib_sample[SAMPLE_SIZE] = {
0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d,
0x20, 0x69, 0x73, 0x20, 0x66, 0x72, 0x65, 0x65, 0x20, 0x73, 0x6f, 0x66, 0x74,
0x77, 0x61, 0x72, 0x65, 0x3b, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e,
0x20, 0x72, 0x65, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65,
0x20, 0x69, 0x74, 0x20, 0x61, 0x6e, 0x64, 0x2f, 0x6f, 0x72, 0x20, 0x6d, 0x6f,
0x64, 0x69, 0x66, 0x79, 0x0a, 0x20, 0x69, 0x74, 0x20, 0x75, 0x6e, 0x64, 0x65,
0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x65, 0x72, 0x6d, 0x73, 0x20, 0x6f,
0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x47, 0x4e, 0x55, 0x20, 0x47, 0x65, 0x6e,
0x65, 0x72, 0x61, 0x6c, 0x20, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x4c,
0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x20, 0x61, 0x73, 0x20, 0x70, 0x75, 0x62,
0x6c, 0x69, 0x73, 0x68, 0x65, 0x64, 0x20, 0x62, 0x79, 0x0a, 0x20, 0x74, 0x68,
0x65, 0x20, 0x46, 0x72, 0x65, 0x65, 0x20, 0x53, 0x6f, 0x66, 0x74, 0x77, 0x61,
0x72, 0x65, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e,
0x3b, 0x20, 0x65, 0x69, 0x74, 0x68, 0x65, 0x72, 0x20, 0x76, 0x65, 0x72, 0x73,
0x69, 0x6f, 0x6e, 0x20, 0x32, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x2c, 0x20, 0x6f, 0x72, 0x0a, 0x20,
0x28, 0x61, 0x74, 0x20, 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6f, 0x70, 0x74, 0x69,
0x6f, 0x6e, 0x29, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6c, 0x61, 0x74, 0x65, 0x72,
0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x0a};


int main(int argc, char *argv[])
{
	struct wd_capa capa;
	struct wd_queue q;
	struct hisi_zip_msg *msg, *recv_msg;
	void *a, *src, *dst, *test_sample;
	__u64 in, out;
	int ret, i;
	int output_num;
	FILE *fp;
	int proc_tag;
	char file[64];
	struct timeval start_tval, end_tval;
	float time, speed;
	int mode;
	unsigned int pkt_len, asyn_count = 0;

	if (argv[1])
		proc_tag = strtoul(argv[1], NULL, 10);
	else
		proc_tag = 0;
	if (proc_tag)
		sprintf(file, COMP_FILE"%d", proc_tag);
	else
		sprintf(file, COMP_FILE);
	if (argv[2])
		mode = strtoul(argv[2], NULL, 10);
	else
		mode = 0;
	if (argv[3])
		pkt_len = strtoul(argv[3], NULL, 10);
	else
		pkt_len = 244;

	if (pkt_len > MAX_PKT) {
		printf("\npkt length is too large, now set at default!");
		pkt_len = MAX_PKT;
	}
	test_sample = malloc(pkt_len);
	if (!test_sample) {
		printf("\nmalloc test sample fail!");
		return -1;
	}
	for (i = 0; i < pkt_len/SAMPLE_SIZE; i++)
		memcpy(test_sample + i * SAMPLE_SIZE, zlib_sample, SAMPLE_SIZE);
	memcpy(test_sample + i * SAMPLE_SIZE, zlib_sample,
	       pkt_len % SAMPLE_SIZE);
	memset(&q, 0, sizeof(q));
	memset(&capa, 0, sizeof(capa));
	capa.alg = VFIO_WDEV_ZLIB;
	capa.throughput = 10;
	capa.latency = 10;

	ret = wd_request_queue(0, &q, &capa);
	SYS_ERR_COND(ret, "wd_request_queue");
	printf("\npasid=%d, dma_flag=%d", q.pasid, q.dma_flag);

	/* Allocate some space and setup a DMA mapping */
	a = mmap((void *)0x0, ASIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!a) {
		printf("\nmmap fail!");
		goto release_q;
	}
	memset(a, 0, ASIZE);
	ret = wd_mem_share(&q, a, ASIZE, 0);
	SYS_ERR_COND(ret, "wd_mem_share err\n");
	printf("WD dma map VA=IOVA=%p successfully!\n", a);

	src = a;
	dst = (char *)a + (ASIZE / 2);

	for (i = 0; i < 128; i++)
		memcpy(src + i * pkt_len, test_sample, pkt_len);

	msg = malloc(sizeof(*msg));
	if (!msg) {
		printf("\nalloc msg fail!");
		goto alloc_msg_fail;
	}
	memset((void *)msg, 0, sizeof(*msg));
	gettimeofday(&start_tval, NULL);
	msg->input_date_length = pkt_len;
	msg->dw9 = 2;
	msg->dest_avail_out = 0x800;

	for (i = 0; i < OP_NUMBER; i++) {
		in = (__u64)src + (i % 128) * pkt_len;
		out = (__u64)dst + (i % 128) * pkt_len;
		msg->source_addr_l = in & 0xffffffff;
		msg->source_addr_h = in >> 32;
		msg->dest_addr_l = out & 0xffffffff;
		msg->dest_addr_h = out >> 32;

		ret = wd_send(&q, msg);
		if (ret == -EBUSY) {
			usleep(1);
			goto recv_again;
		}
		SYS_ERR_COND(ret, "send fail!\n");
recv_again:
		ret = wd_recv(&q, (void **)&recv_msg);
		if (ret < 0) {
			printf("\n wd_recv fail!");
			goto alloc_msg_fail;
		/* synchronous mode, if get none, then get again */
		} else if (ret == 0 && mode)
			goto recv_again;
		/* asynchronous mode, if get one then get again */
		else if (ret == 1 && !mode) {
			asyn_count++;
			goto recv_again;
		}
	}

	output_num = recv_msg->produced;
	gettimeofday(&end_tval, NULL);
	time = (float)((end_tval.tv_sec-start_tval.tv_sec) * 1000000 +
		end_tval.tv_usec - start_tval.tv_usec);

	if (mode)
		speed = 1 / (time / OP_NUMBER);
	else
		speed = 1 / (time / asyn_count);
	printf("\r\n%s compressing time %0.0f us, pkt len = %d bytes, %0.3f Mpps",
	       "zlib", time, pkt_len, speed);

	/* add zlib compress head and write head + compressed date to a file */
	char zip_head[2] = {0x78, 0x9c};

	fp = fopen(file, "wb");

	fwrite(zip_head, 1, 2, fp);
	fwrite((char *)out, 1, output_num, fp);

	fclose(fp);

	free(msg);
alloc_msg_fail:
	wd_mem_unshare(&q, a, ASIZE);
	munmap(a, ASIZE);
release_q:
	wd_release_queue(&q);
	free(test_sample);

	return EXIT_SUCCESS;
}
