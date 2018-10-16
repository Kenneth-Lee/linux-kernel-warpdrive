// SPDX-License-Identifier: GPL-2.0
/* This file is shared bewteen WD user space and kernel */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <linux/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "dummy_drv.h"

#define PAGE_SIZE 4096

struct dummy_q_priv {
	/* local mirror of the register space */
	int head;		/* queue head */
	int resp_tail;		/* resp tail in the queue */
	/* so in the user side: when add to queue, head++ but don't exceed resp_tail.
	 * when get back from the queue, resp_tail++ but don't exceed tail.
	 * in the kernel side: when get from queue, tail++ but don't exceed head-1 */

	struct dummy_hw_queue_reg *reg;
};

int dummy_set_queue_dio(struct wd_queue *q)
{
	int ret = 0;
	struct dummy_q_priv *priv;

	printf("dummy_set_queue_dio\n");
	alloc_obj(priv);
	if (!priv) {
		DUMMY_ERR("No memory for dummy queue!\n");
		ret = -ENOMEM;
		goto out;
	}

	q->priv = priv;
	priv->head = 0;
	priv->resp_tail = 0;
	/* priv->reg = mmap(0, sizeof(struct dummy_hw_queue_reg)
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
		*/
	/* try to test a bigger mmap region which contains more than a page */
	priv->reg = mmap(0, DUMMY_REGMEM_NR_PAGE*PAGE_SIZE,
		PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (priv->reg == MAP_FAILED) {
		DUMMY_ERR("dummy_dev: mmap fail (%d)\n", errno);
		if (errno)
			ret = errno;
		else
			ret = -EIO;
		goto out_with_priv;
	}

	if (memcmp(priv->reg->hw_tag, DUMMY_HW_TAG, DUMMY_HW_TAG_SZ)) {
		DUMMY_ERR("dummy_dev: hw detection fail\n");
		ret = -EIO;
		goto out_with_priv_map;
	}

	return 0;

out_with_priv_map:
	munmap(priv->reg, sizeof(struct dummy_hw_queue_reg));
out_with_priv:
	free_obj(priv);
	q->priv = NULL;
out:
	return ret;
}

void dummy_unset_queue_dio(struct wd_queue *q)
{
	struct dummy_q_priv *priv = (struct dummy_q_priv *)q->priv;

	assert(priv);

	munmap(priv->reg, sizeof(struct dummy_hw_queue_reg));
	free(priv);
	q->priv = NULL;
}

int dummy_add_to_dio_q(struct wd_queue *q, void *req) {
	struct dummy_q_priv *priv = (struct dummy_q_priv *)q->priv;
	int bd_num;

	assert(priv);

	bd_num = priv->reg->ring_bd_num;

	if ((priv->head + 1) % bd_num == priv->resp_tail)
		return -EBUSY; /* the queue is full */
	else {
		priv->reg->ring[priv->head] = *((struct ring_bd *)req);
		priv->reg->ring[priv->head].ptr = req;
		priv->head = (priv->head + 1) % bd_num;
		wd_reg_write(&priv->reg->head, priv->head);
		printf("add to queue, new head=%d, %d\n", priv->head, priv->reg->head);
	}

	return 0;
}

int dummy_get_from_dio_q(struct wd_queue *q, void **resp)
{
	struct dummy_q_priv *priv = (struct dummy_q_priv *)q->priv;
	int bd_num = priv->reg->ring_bd_num;
	int ret;
	int tail;

	assert(priv);

	tail = wd_reg_read(&priv->reg->tail);
	printf("get queue tail=%d,%d\n", tail, priv->resp_tail);
	if (priv->resp_tail == tail) {
		return -EBUSY;
	} else {
		ret = priv->reg->ring[priv->resp_tail].ret;
		*resp = priv->reg->ring[priv->resp_tail].ptr;
		priv->resp_tail = (priv->resp_tail + 1) % bd_num;
		printf("get resp %d, %d\n", ret, priv->resp_tail);
		return ret;
	}
}

void dummy_flush(struct wd_queue *q)
{
	/* use ioctl to flush, this is just for dummy driver, in pratical, this
	 * should be a read or write to hardware, avoiding syscall */
	ioctl(q->fd, DUMMY_CMD_FLUSH);
}

void *dummy_preserve_mem(struct wd_queue *q, size_t size) {
	void *mem = mmap(0, size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, q->fd, size);
	if (mem == MAP_FAILED)
		return NULL;
	else
		return mem;
}
