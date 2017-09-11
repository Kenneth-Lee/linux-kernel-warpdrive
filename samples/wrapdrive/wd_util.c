/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include "wd_util.h"


int wd_write_sysfs_file(const char *path, char *buf, int size)
{
	int ret, count;
	FILE *fd;

	if (!path || !buf || !size) {
		WD_ERR("Write param error!\n");
		return -1;
	}
	ret = chmod(path, S_IRGRP|S_IWGRP|S_IWOTH|S_IROTH);
	if (ret < 0) {
		WD_ERR("chmod (%s) fail!\n", path);
		return ret;
	}
	fd = fopen(path, "wr");
	if (!fd) {
		WD_ERR("Open (%s) fail!err=%d\n",
			path, errno);
		return -1;
	}
	count = fwrite(buf, 1, size, fd);
	if (count != size) {
		fclose(fd);
		WD_ERR("fwrite %s into %s fail!\n", buf, path);
		return -1;
	}
	fflush(fd);
	fclose(fd);

	return 0;
}
