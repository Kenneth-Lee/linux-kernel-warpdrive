/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* This file is shared bewteen WD user space and kernel */

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "../wd_util.h"
#include "dummy_drv.h"


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
	struct wd_dummy_cpy_param *prv_capa =
		(struct wd_dummy_cpy_param *)&q->capa.priv;
	char value[WD_NAME_SIZE];

	alloc_obj(priv);
	if (!priv) {
		DUMMY_ERR("No memory for dummy queue!\n");
		ret = -ENOMEM;
		goto out;
	}

	q->priv = priv;
	priv->head = 0;
	priv->resp_tail = 0;
	priv->reg = mmap(0, sizeof(struct dummy_hw_queue_reg),
		PROT_READ | PROT_WRITE, MAP_SHARED, q->device, 0);
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

	snprintf(value, WD_NAME_SIZE, "%d", prv_capa->flags);
	ret = wd_set_queue_attr(q, AAN_AFLAGS, value);
	if (ret) {
		ret = -EINVAL;
		goto out_with_priv_map;
	}

	snprintf(value, WD_NAME_SIZE, "%d", prv_capa->max_copy_size);
	ret = wd_set_queue_attr(q, AAN_MAX_COPY_SIZE, value);
	if (ret) {
		ret = -EINVAL;
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

int dummy_unset_queue_dio(struct wd_queue *q)
{
	struct dummy_q_priv *priv = (struct dummy_q_priv *)q->priv;

	assert(priv);

	munmap(priv->reg, sizeof(struct dummy_hw_queue_reg));
	free(priv);
	q->priv = NULL;

	return 0;
}

#if 0
/* for test only */
static void _dummy_dump_hw_queue(struct wd_queue *q, char *prefix)
{
	struct dummy_q_priv *priv = (struct dummy_q_priv *)q->priv;
	printf("%s", prefix);
	printf("tag=%s ", priv->reg->hw_tag);
	printf("ring_bd_num=%d ", priv->reg->ring_bd_num);
	printf("head=%d ", priv->reg->head);
	printf("tail=%d ", priv->reg->tail);
	printf("\n");
}
#endif

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
