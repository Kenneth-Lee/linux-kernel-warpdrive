/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


/**
 * This file is shared bewteen user and kernel space Wrapdrive which is
 * including algorithm attibutions that both user and driver are caring for
 */

#ifndef __VFIO_WDEV_COMP_H
#define __VFIO_WDEV_COMP_H


/* De-compressing algorithms' parameters */
struct vfio_wdev_comp_param {
	__u32 window_size;
	__u32 comp_level;
	__u32 mode;
	__u32 alg;
};


/* WD defines all the De-compressing algorithm names here */
#define VFIO_WDEV_ZLIB			"zlib"
#define VFIO_WDEV_GZIP			"gzip"
#define VFIO_WDEV_LZ4			"lz4"

#endif
