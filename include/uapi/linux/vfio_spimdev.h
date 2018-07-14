// SPDX-License-Identifier: GPL-2.0+
/* This file is shared bewteen WD user and kernel space, which is
 * including attibutions of user and drivers caring for
 */

#ifndef _UAPIVFIO_SPIMDEV_H
#define _UAPIVFIO_SPIMDEV_H

#include <linux/types.h>

#define VFIO_SPIMDEV_CLASS_NAME		"spimdev"

/* Device ATTRs in parent dev SYSFS DIR */
#define VFIO_SPIMDEV_PDEV_ATTRS_GRP_NAME	"params"

#define VFIO_SPIMDEV_CMD_WAIT	_IOW('W', 1, unsigned long)
#define VFIO_SPIMDEV_CMD_GET_Q	_IOW('W', 2, unsigned long)
#endif
