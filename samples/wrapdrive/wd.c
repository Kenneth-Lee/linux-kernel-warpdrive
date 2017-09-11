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
#include <uuid/uuid.h>

#include "wd.h"
#include "wd_util.h"
#include "wd_adapter.h"

struct wd_dev_info {
	int node_id;
	int priority;
	int iommu_type;
	char dev_root[PATH_STR_SIZE];
	char name[WD_NAME_SIZE];
};

struct wd_algo_info {
	__u32 flags;
	__u32 available_instances;
	char name[WD_NAME_SIZE];
	char api[WD_NAME_SIZE];
	char algo_path[PATH_STR_SIZE];
	struct wd_dev_info *dinfo;
};

static int _get_wd_dev_info(struct sysfs_device *dev, struct wd_dev_info *wd_info)
{
	struct sysfs_class_device *cd;
	struct sysfs_attribute *attr;
	int value;
	char dev_path[PATH_STR_SIZE];

	strcpy(wd_info->name, dev->name);
	strcpy(wd_info->dev_root, dev->path);
	strcat(wd_info->dev_root, "/device");

	strcpy(dev_path, wd_info->dev_root);
	strcat(dev_path, "/" WD_PDEV_ATTRS_GRP_NAME);

	cd = sysfs_open_class_device_path(dev_path);
	if (!cd) {
		WD_ERR("no wrapdrive_dev found for the dev (%s)\n", dev_path);
		return -ENODEV;
	}
	attr = sysfs_get_classdev_attr(cd, WDPAN_PRIORITY);
	if (!attr) {
		WD_ERR("no priority for the dev (%s)\n", dev_path);
		return -EINVAL;
	}

	value = atoi(attr->value);
	if (value < 100 && value >= 0)
		wd_info->priority = value;
	else {
		WD_ERR("priority is not in range (%d) in dev (%s)\n", value, dev_path);
		return -EINVAL;
	}
	attr = sysfs_get_classdev_attr(cd, WDPAN_NODE_ID);
	if (!attr) {
		WD_ERR("no node id for the dev (%s)\n", dev_path);
		return -ENODEV;
	}
	value = atoi(attr->value);
	wd_info->node_id = value;

	attr = sysfs_get_classdev_attr(cd, WDPAN_IOMMU_TYPE);
	if (!attr) {
		WD_ERR("no iommu type for the dev (%s)\n", dev_path);
		return -ENODEV;
	}
	value = atoi(attr->value);
	wd_info->iommu_type = value;


	return 0;
}

static int _get_wd_algo_info(struct wd_dev_info *wd_info, struct wd_algo_info *wa_info, char *algo)
{
	struct sysfs_class_device *cd;
	struct sysfs_attribute *attr;
	int value;
	char *sect;

	strcpy(wa_info->algo_path, wd_info->dev_root);
	strcat(wa_info->algo_path, "/mdev_supported_types/");
	strcat(wa_info->algo_path, algo);

	cd = sysfs_open_class_device_path(wa_info->algo_path);
	if (!cd) {
		WD_ERR("cannot open algo path (%s)\n", wa_info->algo_path);
		return -ENODEV;
	}
	sect = strstr(algo, "-");
	if (!sect) {
		WD_ERR("alg (%s) error!\n", algo);
		return -ENODEV;
	}
	memcpy(wa_info->api, algo, (unsigned long)(sect - algo));
	strncpy(wa_info->name, sect + 1, WD_NAME_SIZE);
	attr = sysfs_get_classdev_attr(cd, "available_instances");
	if (!attr) {
		WD_ERR("no available_instances for the algo (%s)\n", wa_info->algo_path);
		return -ENODEV;
	}
	value = atoi(attr->value);
	wa_info->available_instances = value;
	attr = sysfs_get_classdev_attr(cd, "flags");
	if (!attr) {
		WD_ERR("no available_instances for the algo (%s)\n", wa_info->algo_path);
		return -ENODEV;
	}
	value = atoi(attr->value);
	wa_info->flags = value;

	return 0;
}
int __iommu_type(struct wd_queue *q)
{
	return ((struct wd_algo_info *)q->alg_info)->dinfo->iommu_type;
}
int wd_set_queue_attr(struct wd_queue *q, const char *name, const char *value)
{
	struct sysfs_attribute *attr;
	char path[PATH_STR_SIZE];

	strcpy(path, q->mdev_path);
	strcat(path, "/" WD_QUEUE_PARAM_GRP_NAME "/");
	strcat(path, name);

	attr = sysfs_open_attribute(path);
	if (!attr) {
		WD_ERR("cannot find attr (%s)\n", path);
		return -ENODEV;
	}

	if (sysfs_write_attribute(attr, value, strlen(value))) {
		WD_ERR("write attr fail (%s), value = %s\n", path, value);
		goto out_with_attr;
	}

	return 0;

out_with_attr:
	sysfs_close_attribute(attr);

	return -1;
}

int wd_dump_all_algos(void)
{
	struct sysfs_class *cls = sysfs_open_class(WD_CLASS_NAME);
	struct dlist *dl;
	struct dlist *al = NULL;
	struct sysfs_device *cur;
	struct wd_dev_info wd_info;
	struct wd_algo_info wa_info;
	char algo_path[PATH_STR_SIZE];
	int ret = 0;
	char *a;

	if (!cls) {
		WD_ERR("wrapdrive framework is not enabled in this platform\n");
		return -ENODEV;
	}

	dl = sysfs_get_class_devices(cls);
	if (!cls) {
		WD_ERR("no device avaialbe");
		return -ENODEV;
	}

	dlist_for_each_data(dl, cur, struct sysfs_device) {
		ret = _get_wd_dev_info(cur, &wd_info);
		if(ret)
			goto end_with_cls;

		printf("wd_dev: %s (node_id=%d, pri=%d)\n", wd_info.name, wd_info.node_id, wd_info.priority);

		strncpy(algo_path, wd_info.dev_root, PATH_STR_SIZE);
		strcat(algo_path, "/mdev_supported_types");
		al = sysfs_open_directory_list(algo_path);
		if (al) {
			dlist_for_each_data(al, a, char) {
				ret = _get_wd_algo_info(&wd_info, &wa_info, a);
				if (ret) {
					printf("\talgo: %s is in wrong format\n", a);
					sysfs_close_list(al);
					goto end_with_cls;
				} else {
					printf("\talgo: %s (ins=%d, api=%s, flags=%x)\n",
							wa_info.name,
							wa_info.available_instances,
							wa_info.api,
							wa_info.flags);
				}
			}
			sysfs_close_list(al);
		} else {
			printf("\tno algo for %s\n", algo_path);
			goto end_with_cls;
		}
	}

end_with_cls:
	sysfs_close_class(cls);
	return ret;
}

static void _obj_delete(void *wa)
{
	free(wa);
}

static int _find_available_algo(struct wd_capa *capa, struct dlist **list_out)
{
	struct sysfs_class *wd_class;
	struct dlist *dl;
	struct dlist *al;
	struct sysfs_device *cur;
	struct wd_dev_info *wd_info = NULL;
	struct wd_algo_info *wa_info = NULL;
	char algo_path[PATH_STR_SIZE];
	char *a, *temp;
	struct dlist *wa_pool = NULL;
	char *algo = capa->alg;
	int wa_num = 0;

	wd_class = sysfs_open_class(WD_CLASS_NAME);
	if (!wd_class) {
		WD_ERR("WD framework is not enabled on this system!\n");
		return -ENODEV;
	}
	wa_pool = dlist_new_with_delete(sizeof(*wa_info), _obj_delete);
	if (!wa_pool) {
		WD_ERR("alloc dlist fail!\n");
		return -ENODEV;;
	}
	dl = sysfs_get_class_devices(wd_class);
	if (!wd_class) {
		dlist_destroy(wa_pool);
		WD_ERR("no devices available!\n");
		return -ENODEV;
	}
	dlist_for_each_data(dl, cur, struct sysfs_device) {
		if (!wd_info) {
			alloc_obj(wd_info);
			if (!wd_info) {
				WD_ERR("alloc wd fail\n!");
				dlist_destroy(wa_pool);
				return -ENODEV;
			}
		}
		memset(wd_info, 0, sizeof(*wd_info));
		if (_get_wd_dev_info(cur, wd_info))
			continue;

		strncpy(algo_path, wd_info->dev_root, PATH_STR_SIZE);
		strcat(algo_path, "/mdev_supported_types");
		al = sysfs_open_directory_list(algo_path);
		if (al) {
			dlist_for_each_data(al, a, char) {
				if (!strstr(a, algo))
					continue;
				if (!wa_info) {
					alloc_obj(wa_info);
					if (!wa_info) {
						WD_ERR("alloc wa fail\n!");
						dlist_destroy(wa_pool);
						return -ENODEV;
					}
				}
				memset(wa_info, 0, sizeof(*wa_info));
				strncpy(wa_info->algo_path, algo_path,
					PATH_STR_SIZE);
				strcat(wa_info->algo_path, "/");
				strcat(wa_info->algo_path, a);
				wa_info->dinfo = wd_info;
				temp = strstr(a, "-");
				memcpy(wa_info->api, a, temp - a);
				strcpy(wa_info->name, temp + 1);
				dlist_push(wa_pool, wa_info);
				wa_num++;

				/* malloc wd_info again */
				wd_info = NULL;
				wa_info = NULL;
			}
			sysfs_close_list(al);
		} else
			printf("\tno algo for %s\n", algo_path);
	}
	sysfs_close_class(wd_class);
	if (wa_num == 0) {
		WD_ERR("cannot find a match for the algoright `%s\'\n", algo);
		dlist_destroy(wa_pool);
		*list_out = NULL;
		return -ENODEV;
	}
	*list_out = wa_pool;

	return wa_num;
}

static int _wa_compare_priority(void *a, void *b)
{
	struct wd_algo_info *wa1 = (struct wd_algo_info *)a;
	struct wd_algo_info *wa2 = (struct wd_algo_info *)b;

	return wa2->dinfo->priority - wa1->dinfo->priority;
}

static void _destroy_algo_mdev(struct wd_queue *q)
{
	char rpath[PATH_STR_SIZE];
	int ret;

	strncpy(rpath, q->mdev_path, PATH_STR_SIZE);
	strcat(rpath, "/remove");
	ret = wd_write_sysfs_file(rpath, "1", 1);
	if (ret)
		WD_ERR("write %s fail\n", rpath);
	if (q->dev_name)
		free(q->dev_name);
}

static int _create_algo_mdev(struct wd_queue *q, struct wd_algo_info *ainfo)
{

	int ret;
	char cpath[PATH_STR_SIZE];
	uuid_t uuid;

	uuid_generate(uuid);
	uuid_unparse(uuid, q->dev_name);

	strncpy(cpath, ainfo->algo_path, PATH_STR_SIZE);
	strcat(cpath, "/create");

	ret = wd_write_sysfs_file(cpath, q->dev_name, strlen(q->dev_name));
	if (ret) {
		free(q->dev_name);
		WD_ERR("write %s fail\n", cpath);
		goto out_with_uuid;
	}
	strncpy(q->mdev_path, ainfo->algo_path, PATH_STR_SIZE);
	strcat(q->mdev_path, "/devices/");
	strcat(q->mdev_path, q->dev_name);

	strncpy(q->iommu_lpath, q->mdev_path, PATH_STR_SIZE);
	strcat(q->iommu_lpath, "/iommu_group");
	ret = sysfs_get_link(q->iommu_lpath, q->iommu_fpath, PATH_STR_SIZE);
	if (ret) {
		free(q->dev_name);
		WD_ERR("read iommu lpath fail\n");
		goto out_with_uuid;
	}

	ret = sysfs_get_name_from_path(q->iommu_fpath, q->iommu_name, PATH_STR_SIZE);
	if (ret) {
		free(q->dev_name);
		WD_ERR("get iommu real path fail\n");
		goto out_with_uuid;
	}
	q->hw_type = ainfo->api;
	q->alg_info = ainfo;

	strncpy(q->vfio_group_path, "/dev/vfio/", PATH_STR_SIZE);

	if (ainfo->dinfo->iommu_type == VFIO_NOIOMMU_IOMMU)
		strcat(q->vfio_group_path, "noiommu-");
	strcat(q->vfio_group_path, q->iommu_name);
out_with_uuid:
#if HAVE_OSSP_UUID_H
	uuid_destroy(uuid);
#endif

	return ret;
}

static int _get_vfio_facility(struct wd_queue *q)
{
	struct vfio_group_status group_status =
		{ .argsz = sizeof(group_status) };
	int ret;
	int iommu_ext;

	/* Create a new container */
	q->container = open("/dev/vfio/vfio", O_RDWR);
	if (q->container < 0) {
		WD_ERR("Create VFIO container fail!\n");
		return -ENODEV;
	}

	/* Unknown API version */
	if (ioctl(q->container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
		WD_ERR("VFIO version check fail!\n");
		ret = -EINVAL;
		goto out_with_container;
	}

	/* Support the IOMMU driver we want. */
	iommu_ext = ((struct wd_algo_info *)q->alg_info)->dinfo->iommu_type;
	if (ioctl(q->container, VFIO_CHECK_EXTENSION, iommu_ext) < 0) {
		WD_ERR("VFIO iommu check fail!\n");
		ret = -EINVAL;
		goto out_with_container;
	}

	/* open group */
	q->group = open(q->vfio_group_path, O_RDWR);
	if (q->group < 0) {
		WD_ERR("open vfio group fail(%s)\n", q->vfio_group_path);
		ret = -ENODEV;
		goto out_with_container;
	}

	ioctl(q->group, VFIO_GROUP_GET_STATUS, &group_status);
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		WD_ERR("VFIO group is not viable\n");
		ret = -ENODEV;
		goto out_with_group;
	}

	if ((ret = ioctl(q->group, VFIO_GROUP_SET_CONTAINER, &q->container))) {
		WD_ERR("VFIO group fail on VFIO_GROUP_SET_CONTAINER\n");
		goto out_with_group;
	}

	if (ioctl(q->container, VFIO_SET_IOMMU, iommu_ext)) {
		WD_ERR("VFIO fail on VFIO_SET_IOMMU(%d)\n", iommu_ext);
		ret = -ENODEV;
		goto out_with_group;
	}
	q->device = ioctl(q->group, VFIO_GROUP_GET_DEVICE_FD, q->dev_name);
	if (q->device < 0) {
		WD_ERR("VFIO fail on VFIO_GROUP_GET_DEVICE_FD\n");
		ret = q->device;
		goto out_with_group;
	}

	return 0;

out_with_group:
	close(q->group);
out_with_container:
	close(q->container);
	return ret;
}

static void _put_vfio_facility(struct wd_queue *q)
{
	assert(q->device > 0);
	close(q->device);

	assert(q->group > 0);
	close(q->group);

	assert(q->container > 0);
	close(q->container);
}

int wd_request_queue(struct wd_queue *q, struct wd_capa *capa)
{
	struct dlist *al;
	struct wd_algo_info *wa;
	int ret = 0;

	ret = _find_available_algo(capa, &al);
	if (ret < 0) {
		WD_ERR("Fail to find available algorithms!\n");
		return -ENODEV;
	}
	dlist_sort_custom(al, _wa_compare_priority);
get_alg_again:
	wa = (struct wd_algo_info *)dlist_shift(al);
	if (!wa) {
		WD_ERR("Fail to get a WD algo from list!\n");
		ret = -ENODEV;
		goto out_with_wa;
	}

	ret = _create_algo_mdev(q, wa);
	if (ret) {
		WD_ERR("Fail to create mdev!\n");
		free_obj(wa->dinfo);

		goto get_alg_again;
	}

	memcpy(&q->capa, capa, sizeof(*capa));

	ret = _get_vfio_facility(q);
	if (ret) {
		WD_ERR("Fail to get VFIO facility!\n");
		goto out_with_mdev;
	}
	ret = drv_open(q);
	if (ret) {
		WD_ERR("Driver queue init fail!\n");
		goto out_with_vfio;
	}

	goto out_with_al;

out_with_vfio:
	_put_vfio_facility(q);
out_with_mdev:
	_destroy_algo_mdev(q);
out_with_wa:
	free(wa);
out_with_al:
	dlist_destroy(al);
	errno = ret;
	return ret;
}

int wd_send(struct wd_queue *q, void *req)
{
	return drv_send(q, req);
}

int wd_recv(struct wd_queue *q, void **resp)
{
	return drv_recv(q, resp);
}

int wd_send_sync(struct wd_queue *q, void *req, int ms)
{
	int ret;

	while (1) {
		ret = wd_send(q, req);
		if (ret == -EBUSY) {
			wd_flush(q);
			ret = ioctl(q->device, WD_CMD_WAIT, ms);
			if (ret)
				return ret;
		} else
			return ret;
	}
}

int wd_recv_sync(struct wd_queue *q, void **resp, int ms)
{
	int ret;

	while (1) {
		ret = wd_recv(q, resp);
		if (ret == -EBUSY) {
			wd_flush(q);
			ret = ioctl(q->device, WD_CMD_WAIT, ms);
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

void wd_release_queue(struct wd_queue *q)
{
	drv_close(q);
	_put_vfio_facility(q);
	_destroy_algo_mdev(q);
}

static int _wd_mem_share_type1(int container, const void *addr, size_t size, int flags)
{
	struct vfio_iommu_type1_dma_map dma_map;

	dma_map.vaddr = (__u64)addr;
	dma_map.size = size;
	dma_map.iova = (__u64)addr;
	dma_map.flags =
		VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE | flags;
	dma_map.argsz = sizeof(dma_map);

	return ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);
}

static void _wd_mem_unshare_type1(int container, const void *addr, size_t size)
{
	struct vfio_iommu_type1_dma_unmap dma_unmap;

	dma_unmap.iova = (__u64)addr;
	dma_unmap.flags = 0;
	dma_unmap.size = size;
	dma_unmap.argsz = sizeof(dma_unmap);
	ioctl(container, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
}

int wd_mem_share(struct wd_queue *q, const void *addr, size_t size, int flags)
{
	if (drv_can_do_mem_share(q))
		return drv_share(q, addr, size, flags);
	else
		return _wd_mem_share_type1(q->container, addr, size, flags);
}

void wd_mem_unshare(struct wd_queue *q, const void *addr, size_t size)
{
	if (drv_can_do_mem_share(q))
		drv_unshare(q, addr, size);
	else
		_wd_mem_unshare_type1(q->container, addr, size);
}
