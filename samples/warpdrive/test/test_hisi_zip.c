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

/*
 * We have a problem here as va in user space and iova in kernel space are in
 * different domain. Let's hack it to one page, so the possibility of conflict
 * will be small, and let code run firtly :(
 */
#define ASIZE (4 * 1024)

#define SYS_ERR_COND(cond, msg)		\
do {					\
	if (cond) {			\
		perror(msg);		\
		exit(EXIT_FAILURE);	\
	}				\
} while (0)

#define ZLIB 0
#define GZIP 1

int hizip_deflate(FILE *source, FILE *dest,  int type)
{
	struct hisi_qm_msg *msg, *recv_msg;
	struct wd_queue q;
	__u64 in, out;
	void *a;
	char *src, *dst;
	int ret, total_len, output_num, fd;

	q.dev_path = "/dev/ua1";
	strncpy(q.hw_type, "hisi_qm_v1", PATH_STR_SIZE);
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
	if (total_len > 16 * 1024 * 1024) {
		fputs("error, input file size too large(<16MB)!\n", stderr);
		goto release_q;
	}

	a = wd_preserve_share_memory(&q, ASIZE * 2);
	if (!a) {
		fputs("mmap a fail!\n", stderr);
		goto release_q;
	}
	memset(a, 0, ASIZE * 2);

	src = (char *)a;
	dst = (char *)a + ASIZE;

	fread(src, 1, total_len, source);
	if (ferror(source)) {
		fputs("read fails!\n", stderr);
		goto release_q;
	}
	fclose(source);

	msg = malloc(sizeof(*msg));
	if (!msg) {
		fputs("alloc msg fail!\n", stderr);
		goto release_q;
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
		fputs("wd_recv fail!\n", stderr);
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

	return 0;

alloc_msg_fail:
	free(msg);
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
		fputs("Unknown option\n", stderr);
		fputs("<<use ./test_comp_iommu -h get more details>>\n",
			stderr);
		goto EXIT;
	}

	hizip_deflate(stdin, stdout, alg_type);
EXIT:
	return EXIT_SUCCESS;
}
