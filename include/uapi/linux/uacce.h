/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _UAPIUUACCE_H
#define _UAPIUUACCE_H

#include <linux/ioctl.h>

#define UACCE_CLASS_NAME		"uacce"

struct uacce_mem_share_arg {
	__u64 vaddr;
	__u64 size;
};

#define UACCE_CMD_SHARE_MEM	_IOR('A', 1, struct uacce_mem_share_arg)
#define UACCE_CMD_UNSHARE_MEM	_IOR('A', 2, struct uacce_mem_share_arg)

#endif
