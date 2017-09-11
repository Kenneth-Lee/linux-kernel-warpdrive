/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sysfs/libsysfs.h>
#include "wd_util.h"

#define DRV_BUS "mdev"
#define DRV "vfio_mdev"

int main(void)
{
	struct dlist *devs;
	struct sysfs_device *dev;
	struct sysfs_driver *drv;
	struct sysfs_attribute *attr;
	int ret;
	char buf[SYSFS_PATH_MAX];

	drv = sysfs_open_driver(DRV_BUS, DRV);
	if(!drv) {
		printf("no driver %s\n", DRV_BUS"-"DRV);
		return EXIT_FAILURE;
	}

	if(access("/proc/1", 0)) {
		printf("error: mount /proc fs first\n");
		return EXIT_FAILURE;
	}

	printf("clean all unused wd queue...\n");
	devs = sysfs_get_driver_devices(drv);
	if(devs) {
		dlist_for_each_data(devs, dev, struct sysfs_device) {
			printf("find dev %s, pid=", dev->name);
			//todo: check if it is a wrapdrive device
			attr = sysfs_get_device_attr(dev, WD_QUEUE_PARAM_GRP_NAME "/pid");
			if(attr) {
				printf("%s", attr->value);
				sprintf(buf, "/proc/%s", attr->value);
				if(!access("/proc/%s", 0)) {
					printf("(no user, kill device!)\n");
					wd_kill_mdev(dev->path);
				}else {
					printf("(user exist, kept)\n");
				}
			}else
				printf("unknown\n");
		}
	}

	sysfs_close_list(devs);

	printf("done\n");
	ret = EXIT_SUCCESS;

	return ret;
}
