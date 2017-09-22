/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "../wd_util.h"
#include "hisi_sec_udrv_v1.h"

#define MODE_COMMON 0
#define MODE_LEGACY 1

#ifdef HISI_SEC_DEBUG
void Test_sec_print_bd(void* bd_ptr)
{
	struct sec_bd_info * bd = (struct sec_bd_info *)bd_ptr;

	printf( "******* word 0 *******\r\n");
	printf( "bd addr:%p\r\n", bd);
	printf( "done:0x%x\r\n", bd->done);
	printf( "flag_or_cipher_gran_size_hi:0x%x\r\n", bd->flag_or_cipher_gran_size_hi);
	printf( "icv_or_s_key_en:0x%x\r\n", bd->icv_or_s_key_en);
	printf( "hm:0x%x\r\n", bd->hm);
	printf( "no_hpad:0x%x\r\n", bd->no_hpad);
	printf( "ci_gen:0x%x\r\n", bd->ci_gen);
	printf( "ai_gen:0x%x\r\n", bd->ai_gen);
	printf( "auth:0x%x\r\n", bd->auth);
	printf( "cipher:0x%x\r\n", bd->cipher);
	printf( "cipher_gran_size_mid:0x%x\r\n", bd->cipher_gran_size_mid);
	printf( "dat_skip:0x%x\r\n", bd->dat_skip);
	printf( "de:0x%x\r\n", bd->de);
	printf( "seq:0x%x\r\n", bd->seq);
	printf( "c_mode:0x%x\r\n", bd->c_mode);
	printf( "c_width:0x%x\r\n", bd->c_width);
	printf( "t_len:0x%x\r\n", bd->t_len);

	printf( "******* word 1 *******\r\n");
	printf( "c_alg:0x%x\r\n", bd->c_alg);
	printf( "a_alg:0x%x\r\n", bd->a_alg);
	printf( "addr_type:0x%x\r\n", bd->addr_type);
	printf( "bd_invalid:0x%x\r\n", bd->bd_invalid);
	printf( "m_key_en:0x%x\r\n", bd->m_key_en);
	printf( "auth_gran_sz:0x%x\r\n", bd->auth_gran_sz);

	printf( "******* word 2 *******\r\n");
	printf( "gran_num:0x%x\r\n", bd->gran_num);
	printf( "cipher_gran_size_low:0x%x\r\n", bd->cipher_gran_size_low);

	printf( "******* word 3 *******\r\n");
	printf( "c_key_len:0x%x\r\n", bd->c_key_len);
	printf( "a_key_len:0x%x\r\n", bd->a_key_len);
	printf( "mac_len:0x%x\r\n", bd->mac_len);
	printf( "cipher_len_offset:0x%x\r\n", bd->cipher_len_offset);
	printf( "auth_len_offset:0x%x\r\n", bd->auth_len_offset);

	printf( "******* word 4 5 6 7 *******\r\n");
	printf( "AuthKeyAddr:0x%x\r\n", bd->auth_addr_lo.authkey_addr_lo);
	printf( "AuthKeyAddrHi:0x%x\r\n", bd->auth_addr_hi.authkey_addr_hi);
	printf( "CipherKeyAddr:0x%x\r\n", bd->cipher_key_addr);
	printf( "CipherKeyAddrHi:0x%x\r\n", bd->cipher_destin_addr_hi);

	printf( "******* word 8 9 10 11 *******\r\n");
	printf( "IVINAddr:0x%x\r\n", bd->cipher_iv_addr);
	printf( "IVINAddrHi:0x%x\r\n", bd->cipher_iv_addr_hi);
	printf( "DataAddr:0x%x\r\n", bd->data_addr);
	printf( "DataAddrHi:0x%x\r\n", bd->data_addr_hi);

	printf( "******* word 12 13 14 15 *******\r\n");
	printf( "MacAddr:0x%x\r\n", bd->mac_addr);
	printf( "MacAddrHi:0x%x\r\n", bd->mac_addr_hi);
	printf( "CipherDestinAddr:0x%x\r\n", bd->cipher_destin_addr);
	printf( "CipherDestinAddrHi:0x%x\r\n", bd->cipher_destin_addr_hi);
}
#endif

static void hisi_sec_cipher_alg_set(struct sec_bd_info * bd, struct sec_wd_msg *wd_msg)
{
	uint32_t sec_alg;
	char *cipher_alg = wd_msg->cmsg.alg;

	if (!strcmp(cbc_aes_128, cipher_alg))
		sec_alg = SEC_AES_CBC_128;
	else if (!strcmp(cbc_aes_192, cipher_alg))
		sec_alg = SEC_AES_CBC_192;
	/* to be fixed */
	else {
		SEC_ERROR("ERR: ALG is not supported now!\n");
		return; //need to be reviewed again
	}

	/* c_alg,c_mode,c_key_len,c_width,t_length */
	bd->c_alg    = (sec_alg >> 7) & 0x7;
	bd->c_mode   = (sec_alg >> 4)  & 0x7;
	bd->c_key_len = (sec_alg >> 2)  & 0x3;
	bd->c_width  = (sec_alg >> 0)  & 0x3;

	return;
}

/* If the message format of accelerator is the same as WD's, the following
* two transfering functions will do nothing
*/
static int hisi_sec_v1_msg_2_wd_msg(struct wd_queue *q,
	struct sec_bd_info *sec_msg, struct sec_wd_msg *wd_msg, __u32 index)
{
	int status = 1;

	if (1 == sec_msg->done) {
		if (1 == sec_msg->bd_invalid)
			status = -2;
		if (3 == sec_msg->icv_or_s_key_en)
			status = -2;
		if (0 == sec_msg->cipher && 0 == sec_msg->auth)
			status = -2;
	} else
		return -EBUSY;
	if (status == -2)
		return -1;
#ifdef HISI_SEC_DEBUG
	Test_sec_print_bd(sec_msg);
#endif
	wd_msg->cmsg.status = status;
	wd_msg->cmsg.dst = ((__u64)sec_msg->cipher_destin_addr_hi << 32) |
		(__u64)sec_msg->cipher_destin_addr;
	if (sec_msg->addr_type == 1)
		wd_msg->cmsg.aflags |= WD_AATTR_SGL;
	sec_msg->done = 0;

	return 0;
}

static inline int hisi_sec_get_op_type(struct sec_wd_msg *wd_msg)
{
	return wd_msg->cmsg.optype;
}

static int wd_msg_2_hisi_sec_v1_msg(struct wd_queue *q,
	struct sec_wd_msg *wd_msg, struct sec_bd_info *sec_msg,  __u32 index)
{
	int size;

	size = wd_msg->cmsg.dsize;
	sec_msg->data_addr = (uint32_t)wd_msg->cmsg.src;
	sec_msg->data_addr_hi = wd_msg->cmsg.src >> 32;
	sec_msg->cipher_destin_addr = (uint32_t)wd_msg->cmsg.dst;
	sec_msg->cipher_destin_addr_hi = wd_msg->cmsg.dst >> 32;
	sec_msg->cipher_key_addr_hi = wd_msg->cmsg.key >> 32;
	sec_msg->cipher_key_addr = (uint32_t)wd_msg->cmsg.key;
	sec_msg->cipher_iv_addr = (uint32_t)wd_msg->cmsg.iv;
	sec_msg->cipher_iv_addr_hi = wd_msg->cmsg.iv >> 32;
    	sec_msg->cipher_gran_size_mid = size >> 16;
	sec_msg->flag_or_cipher_gran_size_hi = size >> 20;
	sec_msg->cipher_gran_size_low = size;
	sec_msg->gran_num = 1;
	sec_msg->cipher_len_offset = 0;
	if (wd_msg->cmsg.src != wd_msg->cmsg.dst)
		sec_msg->de = 1;
	else
		sec_msg->de = 0;
	if (wd_msg->cmsg.aflags & WD_AATTR_SGL)
       		sec_msg->addr_type = 1;
	else
		sec_msg->addr_type = 0;

	/* This algorithm setting need to be fixed!!! */
	hisi_sec_cipher_alg_set(sec_msg, wd_msg);

	/* cipher*/
	sec_msg->seq = 0;

	sec_msg->bd_invalid = 0;
	sec_msg->done = 0;
	sec_msg->cipher = hisi_sec_get_op_type(wd_msg);

#ifdef HISI_SEC_DEBUG
	Test_sec_print_bd(sec_msg);
#endif
	return 0;
}

static inline __u32 hisi_sec_get_free_index(struct wd_queue *q)
{
	struct sec_eng_info *info = q->priv;
	struct sec_eng_ring *msg_ring = &info->ring[SEC_CMD_RING];

	return msg_ring->write;	
}

static inline __u32 hisi_sec_get_req_index(struct wd_queue *q, void *req)
{
	struct sec_eng_info *info = q->priv;

	return ((__u64)(req - (void *)info->out_q)) /sizeof(struct sec_wd_msg);	
}

static int hisi_sec_get_ring_info(struct wd_queue *q)
{
	struct sec_eng_info *info = q->priv;
	void *vaddr;

	vaddr = mmap(NULL, HISI_SEC_IOSPACE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_SHARED, q->device, 0);
	if (vaddr == MAP_FAILED || vaddr == NULL)
		return -EIO;

	info->rbase[SEC_Q_REGS] 		= vaddr;
	info->rbase[SEC_CMD_RING] 	= vaddr + HISI_SEC_IO1_SIZE;
	info->rbase[SEC_OUTORDER_RING] 	= info->rbase[SEC_CMD_RING] +
				   HISI_SEC_IO2_SIZE;
	info->rbase[SEC_DBG_RING] 	= info->rbase[SEC_OUTORDER_RING] +
					   HISI_SEC_IO3_SIZE;

	return 0;
}

static int hisi_sec_vfio_ring_init(struct wd_queue *q)
{
	struct sec_eng_info *info = q->priv;
	int i;
	void *base;

	for (i = 0; i < HISI_SEC_HW_RING_NUM; i++) {
		info->ring[i].depth = HISI_SEC_QUEUE_LEN -1;
		info->ring[i].base = info->rbase[i];
		info->ring[i].read = 0;
		info->ring[i].write = 0;
		info->ring[i].used = 0;
	}
	info->ring[SEC_CMD_RING].msg_size = HISI_SEC_BD_SIZE;
	info->out_ring.base = info->out_q;
	info->out_ring.depth = HISI_SEC_QUEUE_LEN -1;

	/* Reset all the hardware pointers to starting position */
	base = info->rbase[SEC_Q_REGS];
	wd_reg_write(base + HISI_SEC_Q_INIT_REG, 3);

	return 0;
}

static int hisi_sec_v1_qinfo_init(struct wd_queue *q)
{
	int ret;

	ret = hisi_sec_get_ring_info(q);
	if (ret) {
		SEC_ERROR("get mdevice of queue information fail!\n");
		return ret;
	}

	ret = hisi_sec_vfio_ring_init(q);
	if (ret) {
		SEC_ERROR("SEC vfio ring initiates fail!\n");
		return ret;
	}
	return ret;
}

int hisi_sec_v1_dio_enable(struct wd_queue *q)
{
	struct sec_eng_info *info;

	info = malloc(sizeof(struct sec_eng_info) +
		     sizeof(struct hisi_sec_queue_info));
	if (!info) {
		SEC_ERROR("malloc sec private information mem fail!\n");
		return -1;
	}
	memset(info, 0, sizeof(struct sec_eng_info));
	q->priv = info;
	info->q = q;

	return hisi_sec_v1_qinfo_init(q);
}

int hisi_sec_v1_dio_disable(struct wd_queue *q)
{
	struct sec_eng_info *info = q->priv;

	munmap(info->rbase[SEC_Q_REGS], HISI_SEC_IOSPACE_SIZE);
	free(info);

	return 0;
}

int hisi_sec_v1_batch_send(struct wd_queue *q, void **req, int num)
{
	struct sec_eng_info *info = q->priv;
	struct sec_eng_ring *msg_ring = &info->ring[SEC_CMD_RING];
	void *base = info->ring[SEC_Q_REGS].base;
	struct sec_bd_info *sec_msg;

	msg_ring->read = wd_reg_read(base + HISI_SEC_Q_RD_PTR_REG);
	while (num--) {
		msg_ring->write = wd_reg_read(base + HISI_SEC_Q_WR_PTR_REG);
		if (msg_ring->write == msg_ring->read &&
			msg_ring->used >= msg_ring->depth) {
			SEC_ERROR("SEC queue is full!\n");
			return -EAGAIN;
		}
		sec_msg = (struct sec_bd_info *)msg_ring->base + msg_ring->write;
		memset(sec_msg, 0, 64);
		wd_msg_2_hisi_sec_v1_msg(q, (struct sec_wd_msg *)*req,
						sec_msg, msg_ring->write);
		msg_ring->write = (msg_ring->write + 1) % msg_ring->depth;
		wd_reg_write(base + HISI_SEC_Q_WR_PTR_REG, msg_ring->write);
		msg_ring->used++;
		req++;
	}

	return 0;
}

int hisi_sec_v1_batch_recv(struct wd_queue *q, void **resp, int num)
{
	struct sec_eng_info *info = q->priv;
	struct sec_eng_ring *event_ring = &info->ring[SEC_OUTORDER_RING];
	struct sec_eng_ring *msg_ring = &info->ring[SEC_CMD_RING];
	struct sec_out_bd_info *outorder_msg;
	void *base = info->ring[SEC_Q_REGS].base;
	int msg_index, i = 0, ret;
	while (num--) {
		event_ring->write = wd_reg_read(base +
				HISI_SEC_Q_OUTORDER_WR_PTR_REG);
		event_ring->read = wd_reg_read(base +
				HISI_SEC_Q_OUTORDER_RD_PTR_REG);
		if (event_ring->write == event_ring->read &&
			msg_ring->used == 0)
			continue;
		//todo: wait for the queue to be ready
		outorder_msg = (struct sec_out_bd_info *)(event_ring->base) +
			event_ring->read;
		msg_index = outorder_msg->q_id;
		ret = hisi_sec_v1_msg_2_wd_msg(q, (struct  sec_bd_info*)msg_ring->base +
					msg_index,
					&info->out_q[msg_index], msg_index);
		if (ret == -EBUSY)
			continue;
		else if (ret == -1)
			return ret;
		event_ring->read = (event_ring->read + 1) % event_ring->depth;
		wd_reg_write(base +
			HISI_SEC_Q_OUTORDER_RD_PTR_REG, event_ring->read);
		*resp = &info->out_q[msg_index];
		resp++;
		msg_ring->used--;
		i ++;
	}
	wd_reg_write(base + HISI_SEC_Q_FLOW_INT_MKS_REG, 0);

	return i;
}

int hisi_sec_v1_send(struct wd_queue *q, void *req)
{
	return hisi_sec_v1_batch_send(q, &req, 1);
}

int hisi_sec_v1_recv(struct wd_queue *q, void **resp)
{
	int ret;

	ret = hisi_sec_v1_batch_recv(q, resp, 1);
	if (ret == 0)
		return -EBUSY;
	else
		return ret;
}
