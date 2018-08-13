/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _UAPIUACCE4U_H
#define _UAPIUACCE4U_H

#include <linux/ioctl.h>

#define ACCE4U_CLASS_NAME		"acce4u"

struct acce4u_mem_share_arg {
	__u64 vaddr;
	__u64 size;
};

#define ACCE4U_CMD_SHARE_MEM	_IOR('A', 1, struct acce4u_mem_share_arg)
#define ACCE4U_CMD_UNSHARE_MEM	_IOR('A', 2, struct acce4u_mem_share_arg)

#endif
