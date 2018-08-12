/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _UAPIUACCE4U_H
#define _UAPIUACCE4U_H

#include <linux/ioctl.h>

#define ACCE4U_CLASS_NAME		"acce4u"

#define ACCE4U_CMD_SHARE_MEM	_IO('A', 1)
#define ACCE4U_CMD_UNSHARE_MEM	_IO('A', 2)
#endif
