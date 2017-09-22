/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


/* This file is shared bewteen WD user and kernel space, which is
* including attibutions of user caring for
*/

#ifndef __WD_USR_IF_H
#define __WD_USR_IF_H

#include <linux/types.h>


#define WD_VER 			1
#define WD_CLASS_NAME		"wrapdrive"

#define WD_QUEUE_PARAM_GRP_NAME	"params"	/* params attrs in mdev sysfs */

#define WD_PDEV_ATTRS_GRP_NAME	"wdev"	/* dev attris in parent dev sysfs */

/* the names of the parent dev attributes */
#define WDPAN_PRIORITY		"priority"
#define WDPAN_NODE_ID		"node_id"
#define WDPAN_IOMMU_TYPE	"iommu_type"


/* Notes: The throughput and delay of queue as it doing the corresponding algorithm.
 * The standard value is based on mainstream X86 CPU throughput, which is '10'.
 * The driver guys should know the value of his engine while compared with
 * mainstream X86 CPU core. Of cource, this real value will change as X86 CPU is
 * developing. So, the mainstream X86 CPU version is based on the WD version
 * releasing time.(fixme: this text should be removed finally)
 */

/* The throughput requirement is a value from 1 to 100, default to 10
 * bigger is higher
 */
typedef __u8 wd_throughput_level_t;

/* The latency requirement is a value from 1 to 100, default to 10
 * and the smaller value is, the delay is shorter.
 */
typedef __u8 wd_latency_level_t;

/* Flat memory, user cares for */
#define WD_CAPA_SGL		1 /* the input data can be a scatter list */
#define WD_CAPA_SHARE_ALL	2 /* share whole process space to the device */

#define WD_CMD_WAIT	_IOW('W', 1, unsigned long)

#endif
