// SPDX-License-Identifier: GPL-2.0+
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include "../wd.h"
#include "comp_hw.h"
#include "../drv/hisi_qm_udrv.h"

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)

#define ASIZE (8*512*4096)	/*16MB*/

#define SYS_ERR_COND(cond, msg)		\
do {					\
	if (cond) {			\
		perror(msg);		\
		exit(EXIT_FAILURE);	\
	}				\
} while (0)

#define ZLIB 0
#define GZIP 1

#define CHUNK 65535


int hizip_deflate(FILE *source, FILE *dest,  int type)
{
	__u64 in, out;
	struct wd_queue q;
	struct hisi_qm_msg *msg, *recv_msg;
	void *a, *b;
	char *src, *dst;
	int ret, total_len;
	int output_num;
	int fd, file_msize;

	q.container = -1;
	q.dev_path = "/dev/ua1";
	ret = wd_request_queue(&q);
	SYS_ERR_COND(ret, "wd_request_queue");

	fprintf(stderr, "pasid=%d, dma_flag=%d\n", q.pasid, q.dma_flag);
	fd = fileno(source);
	struct stat s;

	if (fstat(fd, &s) < 0) {
		close(fd);
		perror("fd error\n");
		return -1;
	}
	total_len = s.st_size;

	if (!total_len) {
		ret = -EINVAL;
		SYS_ERR_COND(ret, "input file length zero");
	}
	if (total_len > 16*1024*1024) {
		fputs("error, input file size too large(<16MB)!\n", stderr);
		goto release_q;
	}
	file_msize = !(total_len%PAGE_SIZE) ? total_len :
			(total_len/PAGE_SIZE+1)*PAGE_SIZE;
	/* mmap file and  DMA mapping */
	a = mmap((void *)0x0, file_msize, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE, fd, 0);
	if (!a) {
		fputs("mmap file fail!\n", stderr);
		goto release_q;
	}
	ret = wd_mem_share(&q, a, file_msize, 0);
	if (ret) {
		fprintf(stderr, "wd_mem_share dma a buf fail!err=%d\n", -errno);
		goto unmap_file;
	}
	/* Allocate some space and setup a DMA mapping */
	b = mmap((void *)0x0, ASIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (!b) {
		fputs("mmap b fail!\n", stderr);
		goto unshare_file;
	}
	memset(b, 0, ASIZE);
	ret = wd_mem_share(&q, b, ASIZE, 0);
	if (ret) {
		fputs("wd_mem_share dma b buf fail!\n", stderr);
		goto unmap_mem;
	}
	src = (char *)a;
	dst = (char *)b;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		fputs("alloc msg fail!\n", stderr);
		goto alloc_msg_fail;
	}
	memset((void *)msg, 0, sizeof(*msg));
	msg->input_date_length = total_len;
	if (type == ZLIB)
		msg->dw9 = 2;
	else
		msg->dw9 = 3;
	msg->dest_avail_out = 0x800000;

	in = (__u64)src;
	out = (__u64)dst;

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
	if (ret == -EIO) {
		fputs(" wd_recv fail!\n", stderr);
		goto alloc_msg_fail;
	/* synchronous mode, if get none, then get again */
	} else if (ret == -EAGAIN)
		goto recv_again;

	output_num = recv_msg->produced;
	/* add zlib compress head and write head + compressed date to a file */
	char zip_head[2] = {0x78, 0x9c};

	fwrite(zip_head, 1, 2, dest);
	fwrite((char *)out, 1, output_num, dest);
	fclose(dest);

	free(msg);
alloc_msg_fail:
	wd_mem_unshare(&q, b, ASIZE);
unmap_mem:
	munmap(b, ASIZE);
unshare_file:
	wd_mem_unshare(&q, a, file_msize);
unmap_file:
	munmap(a, file_msize);
release_q:
	wd_release_queue(&q);

	return ret;
}

int main(int argc, char *argv[])
{
	int alg_type = 0;

	/* avoid end-of-line conversions */
	SET_BINARY_MODE(stdin);
	SET_BINARY_MODE(stdout);

	if (!argv[1]) {
		fputs("<<use ./test_hisi_zip -h get more details>>\n", stderr);
		goto EXIT;
	}

	if (!strcmp(argv[1], "-z"))
		alg_type = ZLIB;
	else if (!strcmp(argv[1], "-g")) {
		alg_type = GZIP;
	} else if (!strcmp(argv[1], "-h")) {
		fputs("[version]:1.0.2\n", stderr);
		fputs("[usage]: ./test_hisi_zip [type] <src_file> dest_file\n",
			stderr);
		fputs("     [type]:\n", stderr);
		fputs("            -z  = zlib\n", stderr);
		fputs("            -g  = gzip\n", stderr);
		fputs("            -h  = usage\n", stderr);
		fputs("Example:\n", stderr);
		fputs("./test_hisi_zip -z < test.data > out.data\n", stderr);
		goto EXIT;
	} else {
		fputs("Unknow option\n", stderr);
		fputs("<<use ./test_comp_iommu -h get more details>>\n",
			stderr);
		goto EXIT;
	}

	hizip_deflate(stdin, stdout, alg_type);
EXIT:
	return EXIT_SUCCESS;
}
