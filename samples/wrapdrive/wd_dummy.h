/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef __WD_DUMMY_H
#define __WD_DUMMY_H

#include <stdlib.h>
#include <errno.h>

#include "wd.h"
#include "../../drivers/crypto/hisilicon/wd/wd_usr_if.h"
#include "../../drivers/crypto/hisilicon/wd/wd_dummy_usr_if.h"

extern int wd_dummy_memcpy(struct wd_queue *q, void *dst, void *src, size_t size);
extern int wd_dummy_request_memcpy_queue(struct wd_queue *q, int max_copy_size);

#endif
