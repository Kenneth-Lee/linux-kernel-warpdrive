/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __DUMMY_DRV_H__
#define __DUMMY_DRV_H__

#include "../wd_dummy.h"
#include "../../../drivers/crypto/hisilicon/dummy_drv/dummy_hw_usr_if.h"

#ifndef  DUMMY_ERR
#define DUMMY_ERR(format, args...) printf(format, ##args)
#endif
int dummy_set_queue_dio(struct wd_queue *q);
int dummy_unset_queue_dio(struct wd_queue *q);
int dummy_add_to_dio_q(struct wd_queue *q, void *req);
int dummy_get_from_dio_q(struct wd_queue *q, void **req);
void dummy_flush(struct wd_queue *q);

#endif
