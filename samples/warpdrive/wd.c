/*
 * Copyright (c) 2017-2018. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include "wd.h"
#include "wd_adapter.h"

int wd_request_queue(struct wd_queue *q)
{
	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status) };
	int iommu_ext;
	int ret;

	if (!q->vfio_group_path ||
		!q->device_api_path ||
		!q->iommu_ext_path) {
		WD_ERR("please set vfio_group_path,"
		"device_api_path,and iommu_ext_path before call %s", __func__);
		return -EINVAL;
	}

	q->hw_type_id = 0; /* this can be set according to the device api_version in the future */

	q->group = open(q->vfio_group_path, O_RDWR);
	if (q->group < 0) {
		WD_ERR("open vfio group(%s) fail, errno=%d\n",
			q->vfio_group_path, errno);
		return -errno;
	}

	if (q->container <= 0) {
		q->container = open("/dev/vfio/vfio", O_RDWR);
		if (q->container < 0) {
			WD_ERR("Create VFIO container fail!\n");
			ret = -ENODEV;
			goto err_with_group;
		}
	}

	if (ioctl(q->container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
		WD_ERR("VFIO version check fail!\n");
		ret = -EINVAL;
		goto err_with_container;
	}

	q->dma_flag = _get_attr_int(q->dmaflag_ext_path);
	if (q->dma_flag < 0) {
		ret = q->dma_flag;
		goto err_with_container;
	}

	iommu_ext = _get_attr_int(q->iommu_ext_path);
	if (iommu_ext < 0) {
		ret = iommu_ext;
		goto err_with_container;
	}
	ret = ioctl(q->container, VFIO_CHECK_EXTENSION, iommu_ext);
	if (!ret) {
		WD_ERR("VFIO iommu check (%d) fail (%d)!\n", iommu_ext, ret);
		goto err_with_container;
	}

	ret = _get_attr_str(q->device_api_path, q->hw_type);
	if (ret)
		goto err_with_container;

	ret = ioctl(q->group, VFIO_GROUP_GET_STATUS, &group_status);
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		WD_ERR("VFIO group is not viable\n");
		goto err_with_container;
	}

	ret = ioctl(q->group, VFIO_GROUP_SET_CONTAINER, &q->container);
	if (ret) {
		WD_ERR("VFIO group fail on VFIO_GROUP_SET_CONTAINER\n");
		goto err_with_container;
	}

	ret = ioctl(q->container, VFIO_SET_IOMMU, iommu_ext);
	if (ret) {
		WD_ERR("VFIO fail on VFIO_SET_IOMMU(%d)\n", iommu_ext);
		goto err_with_container;
	}

	q->mdev = ioctl(q->group, VFIO_GROUP_GET_DEVICE_FD, q->mdev_name);
	if (q->mdev < 0) {
		WD_ERR("VFIO fail on VFIO_GROUP_GET_DEVICE_FD (%d)\n", q->mdev);
		ret = q->mdev;
		goto err_with_container;
	}

	ret = q->fd = ioctl(q->mdev, VFIO_SPIMDEV_CMD_GET_Q);
	if (ret < 0) {
		WD_ERR("get queue fail\n");
		goto err_with_mdev;
	}

	ret = drv_open(q);
	if (ret)
		goto err_with_queue;

	return 0;

err_with_queue:
	close(q->fd);
err_with_mdev:
	close(q->mdev);
err_with_container:
	close(q->container);
err_with_group:
	close(q->group);
	return ret;
}

void wd_release_queue(struct wd_queue *q)
{
	drv_close(q);
	close(q->fd);
	close(q->mdev);
	close(q->container);
	close(q->group);
}

int wd_send(struct wd_queue *q, void *req)
{
	return drv_send(q, req);
}

int wd_recv(struct wd_queue *q, void **resp)
{
	return drv_recv(q, resp);
}

int wd_send_sync(struct wd_queue *q, void *req, __u16 ms)
{
	int ret;

	while (1) {
		ret = wd_send(q, req);
		if (ret == -EBUSY) {
			wd_flush(q);
			ret = ioctl(q->fd, VFIO_SPIMDEV_CMD_WAIT,
				(unsigned long)ms & 0xffff);
			if (ret)
				return ret;
		} else
			return ret;
	}
}

int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms)
{
	int ret;

	while (1) {
		ret = wd_recv(q, resp);
		if (ret == -EBUSY) {
			wd_flush(q);
			ret = ioctl(q->fd, VFIO_SPIMDEV_CMD_WAIT,
					(unsigned long)ms & 0xffff);
			if (ret) {
				WD_ERR("ioctl q->device wait fail!\n");
				return ret;
			}
		} else
			return ret;
	}
}

void wd_flush(struct wd_queue *q)
{
	drv_flush(q);
}

static int _wd_mem_share_type1(struct wd_queue *q, const void *addr,
			       size_t size, int flags)
{
	struct vfio_iommu_type1_dma_map dma_map;

	if (q->dma_flag & VFIO_SPIMDEV_DMA_SVM_NO_FAULT)
		return mlock(addr, size);
#ifdef WITH_SVA_SUPPORT
	else if ((q->dma_flag & VFIO_SPIMDEV_DMA_MULTI_PROC_MAP) &&
		 (q->pasid > 0))
		dma_map.pasid = q->pasid;
#endif
	else if ((q->dma_flag & VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP))
		;
	else
		return -1;
	dma_map.vaddr = (__u64)addr;
	dma_map.size = size;
	dma_map.iova = (__u64)addr;
	dma_map.flags =
		VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE | flags;
	dma_map.argsz = sizeof(dma_map);

	return ioctl(q->container, VFIO_IOMMU_MAP_DMA, &dma_map);
}

static void _wd_mem_unshare_type1(struct wd_queue *q, const void *addr,
				  size_t size)
{
#ifdef WITH_SVA_SUPPORT
	struct vfio_iommu_type1_dma_unmap dma_unmap;
#endif

	if (q->dma_flag & VFIO_SPIMDEV_DMA_SVM_NO_FAULT) {
		(void)munlock(addr, size);
		return;
	}
#ifdef WITH_SVA_SUPPORT
	dma_unmap.iova = (__u64)addr;
	if ((q->dma_flag & VFIO_SPIMDEV_DMA_MULTI_PROC_MAP) && (q->pasid > 0))
		dma_unmap.pasid = q->pasid;
		dma_unmap.flags = 0;
		dma_unmap.size = size;
		dma_unmap.argsz = sizeof(dma_unmap);
		ioctl(q->container, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
#endif
}

int wd_mem_share(struct wd_queue *q, const void *addr, size_t size, int flags)
{
	if (drv_can_do_mem_share(q))
		return drv_share(q, addr, size, flags);
	else
		return _wd_mem_share_type1(q, addr, size, flags);
}

void wd_mem_unshare(struct wd_queue *q, const void *addr, size_t size)
{
	if (drv_can_do_mem_share(q))
		drv_unshare(q, addr, size);
	else
		_wd_mem_unshare_type1(q, addr, size);
}

