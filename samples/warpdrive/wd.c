// SPDX-License-Identifier: GPL-2.0
#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/poll.h>
#include "wd.h"
#include "wd_adapter.h"

int wd_request_queue(struct wd_queue *q)
{
	int ret;

	q->fd = open(q->dev_path, O_RDWR | O_CLOEXEC);
	if (q->fd == -1)
		return -ENODEV;

	ret = drv_open(q);
	if (ret)
		goto err_with_fd;

	return 0;

err_with_fd:
	close(q->fd);
	return ret;
}

void wd_release_queue(struct wd_queue *q)
{
	drv_close(q);
	close(q->fd);
}

int wd_send(struct wd_queue *q, void *req)
{
	return drv_send(q, req);
}

int wd_recv(struct wd_queue *q, void **resp)
{
	return drv_recv(q, resp);
}

static int wd_flush_and_wait(struct wd_queue *q, __u16 ms)
{
	struct pollfd fds[1];
	int ret;

	wd_flush(q);
	fds[0].fd = q->fd;
	fds[0].events = POLLIN;
	ret = poll(fds, 1, ms);
	if (ret == -1)
		return -errno;

	return 0;
}

int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms)
{
	int ret;

	while (1) {
		ret = wd_recv(q, resp);
		if (ret == -EBUSY) {
			ret = wd_flush_and_wait(q, ms);
			if (ret)
				return ret;
		} else
			return ret;
	}
}

void wd_flush(struct wd_queue *q)
{
	drv_flush(q);
}

int wd_mem_share(struct wd_queue *q, const void *addr, size_t size, int flags)
{
	struct uacce_mem_share_arg si;

	si.vaddr = (__u64)addr;
	si.size = (__u64)size;
	return ioctl(q->fd, UACCE_CMD_SHARE_MEM, &si);
}

void wd_mem_unshare(struct wd_queue *q, const void *addr, size_t size)
{
	struct uacce_mem_share_arg si;

	si.vaddr = (__u64)addr;
	si.size = (__u64)size;
	ioctl(q->fd, UACCE_CMD_UNSHARE_MEM, &si);
}

