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
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include "wd.h"
#include "wd_util.h"
#include "wd_adapter.h"

#define SYS_CLASS_DIR	"/sys/class"
#define WD_LATENCY	"latency"
#define WD_THROUGHPUT	"throughput"

struct wd_algo_info;
struct wd_dev_info {
	int node_id;
	int priority;
	int iommu_type;
	int dma_flag;
	int group_fd;
	int mdev_fd;
	int container_fd;
	int resv;
	char dev_root[PATH_STR_SIZE];
	char name[WD_NAME_SIZE];
	char mdev_name[WD_NAME_SIZE];
	struct wd_algo_info *alg_list;
	TAILQ_ENTRY(wd_dev_info) next;
};

struct wd_algo_info {
	__u32 flags;
	__u32 available_instances;
	struct wd_capa capa;
	char name[WD_NAME_SIZE];
	char api[WD_NAME_SIZE];
	char algo_path[PATH_STR_SIZE];
	struct wd_dev_info *dinfo;
	struct wd_algo_info *next;
};

TAILQ_HEAD(wd_dev_list, wd_dev_info);
static struct wd_dev_list wd_dev_cache_list =
	TAILQ_HEAD_INITIALIZER(wd_dev_cache_list);
static struct wd_dev_list wd_resource_dump_list =
	TAILQ_HEAD_INITIALIZER(wd_resource_dump_list);

#ifdef WITH_SVA_SUPPORT
static int _wd_bind_process(struct wd_queue *q)
{
	struct bind_data {
		struct vfio_iommu_type1_bind bind;
		struct vfio_iommu_type1_bind_process data;
	} wd_bind;
	int ret;
	__u32 flags = 0;

	if (q->dma_flag & VFIO_WDEV_DMA_MULTI_PROC_MAP)
		flags = VFIO_IOMMU_BIND_PRIV;
	else if (q->dma_flag & VFIO_WDEV_DMA_SVM_NO_FAULT)
		flags = VFIO_IOMMU_BIND_NOPF;

	wd_bind.bind.flags = VFIO_IOMMU_BIND_PROCESS;
	wd_bind.bind.argsz = sizeof(wd_bind);
	wd_bind.data.flags = flags;
	ret = ioctl(q->container, VFIO_IOMMU_BIND, &wd_bind);
	if (ret)
		return ret;
	q->pasid = wd_bind.data.pasid;
	return ret;
}

static int _wd_unbind_process(struct wd_queue *q)
{
	struct bind_data {
		struct vfio_iommu_type1_bind bind;
		struct vfio_iommu_type1_bind_process data;
	} wd_bind;
	__u32 flags = 0;

	if (q->dma_flag & VFIO_WDEV_DMA_MULTI_PROC_MAP)
		flags = VFIO_IOMMU_BIND_PRIV;
	else if (q->dma_flag & VFIO_WDEV_DMA_SVM_NO_FAULT)
		flags = VFIO_IOMMU_BIND_NOPF;

	wd_bind.bind.flags = VFIO_IOMMU_BIND_PROCESS;
	wd_bind.data.pasid = q->pasid;
	wd_bind.data.flags = flags;
	wd_bind.bind.argsz = sizeof(wd_bind);

	return ioctl(q->container, VFIO_IOMMU_UNBIND, &wd_bind);
}
#endif

static int _get_wd_dev_info(struct wd_dev_info *wd_info)
{
	DIR *wdev;
	char attr_path[PATH_STR_SIZE];
	struct dirent *attr_file;
	int val, attr_count = 0;

	strcpy(attr_path, wd_info->dev_root);
	strcat(attr_path, "/device");
	strcat(attr_path, "/"VFIO_WDEV_PDEV_ATTRS_GRP_NAME);
	wdev = opendir(attr_path);
	if (!wdev) {
		WD_ERR("opendir %s fail\n!", attr_path);
		return -ENODEV;
	}
	while ((attr_file = readdir(wdev)) != NULL) {
		if (strncmp(attr_file->d_name, ".", 1) == 0 ||
		    strncmp(attr_file->d_name, "..", 2) == 0)
			continue;
		attr_count++;
		if (!strncmp(attr_file->d_name, WDPAN_PRIORITY,
		    strlen(WDPAN_PRIORITY))) {
			val = _get_attr_value(attr_path, WDPAN_PRIORITY);
			if (val < 100 && val >= 0) {
				wd_info->priority = val;
				continue;
			} else {
				closedir(wdev);
				WD_ERR("priority is not in range (%d) in dev (%s)\n",
					val, attr_path);
				return -EINVAL;
			}
		}
		if (!strncmp(attr_file->d_name, WDPAN_NODE_ID,
		     strlen(WDPAN_NODE_ID))) {
			val = _get_attr_value(attr_path, WDPAN_NODE_ID);
			if (val >= 0)
				wd_info->node_id = val;
			continue;
		}
		if (!strncmp(attr_file->d_name, WDPAN_IOMMU_TYPE,
		     strlen(WDPAN_IOMMU_TYPE))) {
			val = _get_attr_value(attr_path, WDPAN_IOMMU_TYPE);
			if (val >= 0)
				wd_info->iommu_type = val;
			continue;
		}
		if (!strncmp(attr_file->d_name, WDPAN_DMA_FLAG,
		     strlen(WDPAN_DMA_FLAG))) {
			val = _get_attr_value(attr_path, WDPAN_DMA_FLAG);
			if (val >= 0)
				wd_info->dma_flag = val;
			continue;
		}
	}
	closedir(wdev);
	return attr_count;
}
static int __alg_param_check(struct wd_algo_info *wa_info,
			     struct wd_capa *capa)
{
	/* We think it is always matching now */
	return 0;
}
static int __capa_check(struct wd_algo_info *wa_info, struct wd_capa *capa)
{
	int throughput, latency;
	struct wd_capa *alg_capa = &wa_info->capa;

	if (alg_capa->latency > 0 && alg_capa->latency > capa->latency) {
		return -ENODEV;
	} else {
		latency = _get_attr_value(wa_info->algo_path, WD_LATENCY);
		if (latency > capa->latency)
			return -ENODEV;
		alg_capa->latency = latency;
	}
	if (alg_capa->throughput > 0 &&
	    alg_capa->throughput < capa->throughput) {
		return -ENODEV;
	} else {
		throughput =
			_get_attr_value(wa_info->algo_path, WD_THROUGHPUT);
		if (throughput > capa->throughput)
			return -ENODEV;
		alg_capa->throughput = throughput;
	}

	return __alg_param_check(wa_info, capa);
}

static void __add_alg(struct wd_algo_info *alg, struct wd_dev_info *wd_info)
{
	struct wd_algo_info *alg_list = wd_info->alg_list;

	wd_info->alg_list = alg;
	alg->next = alg_list;
}

static int _get_wd_alg_info(struct wd_dev_info *wd_info, struct wd_capa *capa)
{
	char algo_path[PATH_STR_SIZE];
	DIR *drv_alg;
	struct dirent *attr_file;
	struct wd_algo_info *wa_info = NULL;
	char *sect, *d_alg;
	int cnt = 0;

	strncpy(algo_path, wd_info->dev_root, PATH_STR_SIZE);
	strcat(algo_path, "/device/mdev_supported_types");
	drv_alg = opendir(algo_path);
	if (!drv_alg) {
		WD_ERR("opendir %s fail\n!", algo_path);
		return -ENODEV;
	}
	while ((attr_file = readdir(drv_alg)) != NULL) {
		if (strncmp(attr_file->d_name, ".", 1) == 0 ||
		    strncmp(attr_file->d_name, "..", 2) == 0)
			continue;
		if (capa && !strstr(attr_file->d_name, capa->alg))
			continue;
		d_alg = attr_file->d_name;
		if (!wa_info) {
			alloc_obj(wa_info);
			if (!wa_info) {
				WD_ERR("alloc wa fail\n!");
				closedir(drv_alg);
				return -ENOMEM;
			}
		}
		memset(wa_info, 0, sizeof(*wa_info));
		strncpy(wa_info->algo_path, algo_path,
			PATH_STR_SIZE);
		strcat(wa_info->algo_path, "/");
		strcat(wa_info->algo_path, d_alg);
		if (capa && __capa_check(wa_info, capa) < 0)
			continue;
		sect = strstr(d_alg, "-");
		memcpy(wa_info->api, d_alg, sect - d_alg);
		strcpy(wa_info->name, sect + 1);
		wa_info->dinfo = wd_info;
		wa_info->available_instances =
		_get_attr_value(wa_info->algo_path, "available_instances");
		wa_info->flags =
		_get_attr_value(wa_info->algo_path, "flags");
		__add_alg(wa_info, wd_info);
		if (capa) {
			closedir(drv_alg);
			return 0;
		}
		cnt++;
	}
	if (capa) {
		free_obj(wa_info);
		closedir(drv_alg);
		return -ENODEV;
	} else {
		closedir(drv_alg);
		return cnt;
	}
}
int __iommu_type(struct wd_queue *q)
{
	return ((struct wd_algo_info *)q->alg_info)->dinfo->iommu_type;
}
int wd_set_queue_attr(struct wd_queue *q, const char *name, char *value)
{
	char path[PATH_STR_SIZE];

	strcpy(path, q->mdev_path);
	strcat(path, "/" VFIO_WDEV_MDEV_ATTRS_GRP_NAME "/");

	return _set_attr_value(path, name, value);
}
static void free_wd_dev_info(struct wd_dev_info *wd_info, int keep_dev)
{
	struct wd_algo_info *t_alg_list;

	while (wd_info && wd_info->alg_list) {
		t_alg_list = wd_info->alg_list;
		wd_info->alg_list = t_alg_list->next;
		free_obj(t_alg_list);
	}
	if (!keep_dev)
		free_obj(wd_info);
}
static int _find_available_res(struct wd_capa *capa)
{
	DIR *wd_cls;
	struct dirent *device;
	struct wd_dev_info *wd_info, *wdev;
	int cnt = 0;
	struct wd_algo_info *alg;

	TAILQ_FOREACH(wd_info, &wd_dev_cache_list, next) {
		alg = wd_info->alg_list;
		while (alg && capa) {
			if (strncmp(capa->alg, alg->name, strlen(capa->alg))) {
				alg = alg->next;
				continue;
			}
			if (__capa_check(alg, capa)) {
				alg = alg->next;
				continue;
			}

			return 1;
		}
	}
	wd_info = NULL;
	wd_cls = opendir(SYS_CLASS_DIR"/"VFIO_WDEV_CLASS_NAME);
	if (!wd_cls) {
		WD_ERR("WD framework is not enabled on this system!\n");
		return -ENODEV;
	}
	while ((device = readdir(wd_cls)) != NULL) {
		if (strncmp(device->d_name, ".", 1) == 0 ||
		    strncmp(device->d_name, "..", 2) == 0)
			continue;
		if (!wd_info) {
			alloc_obj(wd_info);
			if (!wd_info) {
				WD_ERR("alloc wd info fail\n!");
				closedir(wd_cls);
				return -ENOMEM;
			}
		}
		memset(wd_info, 0, sizeof(*wd_info));
		(void)strncpy(wd_info->dev_root,
		SYS_CLASS_DIR"/"VFIO_WDEV_CLASS_NAME"/", PATH_STR_SIZE);
		(void)strcat(wd_info->dev_root, device->d_name);
		if (_get_wd_dev_info(wd_info) < 0)
			continue;
		strncpy(wd_info->name, device->d_name, WD_NAME_SIZE);
		if (_get_wd_alg_info(wd_info, capa) < 0) {
			free_wd_dev_info(wd_info, 1);
			continue;
		}
		if (!capa) {
			TAILQ_INSERT_TAIL(&wd_resource_dump_list,
					   wd_info, next);
			cnt++;
			wd_info = NULL;
			continue;
		}
		if (TAILQ_EMPTY(&wd_dev_cache_list)) {
			TAILQ_INSERT_TAIL(&wd_dev_cache_list, wd_info, next);
			wd_info = NULL;
		} else {
			TAILQ_FOREACH(wdev, &wd_dev_cache_list, next) {
				if (wd_info->priority <= wdev->priority &&
				     TAILQ_NEXT(wdev, next)) {
					continue;
				} else if (wd_info->priority > wdev->priority) {
					TAILQ_INSERT_BEFORE(wdev, wd_info,
								next);
					wd_info = NULL;
					break;
				} else {
					TAILQ_INSERT_AFTER(&wd_dev_cache_list,
							wdev, wd_info, next);
					wd_info = NULL;
					break;
				}
			}
		}
		cnt++;
		free_wd_dev_info(wd_info, 1);
	}
	free_wd_dev_info(wd_info, 0);
	closedir(wd_cls);

	return cnt;
}

int wd_dump_all_algos(void)
{
	int ret;
	struct wd_dev_info *wd_info;
	struct wd_algo_info *alg;
	int dev_num = 0;

	ret = _find_available_res(NULL);
	if (ret <= 0) {
		WD_ERR("No device!\n!");
		return ret;
	}
	TAILQ_FOREACH(wd_info, &wd_resource_dump_list, next) {
		alg = wd_info->alg_list;
		printf("Device(%s): node_id=%d, priority=%d, iommu_type=%d\n",
			wd_info->name, wd_info->node_id,
			wd_info->priority, wd_info->iommu_type);
		while (alg) {
			printf("  Alg(%s): flags=%d, available_instances=%d\n",
			alg->name, alg->flags, alg->available_instances);
			alg = alg->next;
		}
		dev_num++;
	}
	return dev_num;
}
int _mdev_check(struct wd_queue *q, char *mname)
{
	char temp_path[PATH_STR_SIZE];
	int ret, len;

	strncpy(temp_path, q->mdev_path, PATH_STR_SIZE);
	strcat(temp_path, "/");
	strcat(temp_path, mname);
	strncpy(q->iommu_lpath, temp_path, PATH_STR_SIZE);
	strcat(q->iommu_lpath, "/iommu_group");
	ret = readlink(q->iommu_lpath, q->iommu_fpath, PATH_STR_SIZE - 1);
	if (ret < 0) {
		WD_ERR("read iommu group at %s fail!\n",q->iommu_lpath);
		return ret;
	}
	q->iommu_fpath[ret] = '\0';
	len = strlen(q->iommu_fpath);
	while (q->iommu_fpath[len - 1] != '/')
		len--;
	strcpy(q->iommu_name, &q->iommu_fpath[len]);
	strncpy(q->vfio_group_path, "/dev/vfio/", PATH_STR_SIZE);

	if (q->iommu_type == VFIO_NOIOMMU_IOMMU)
		strcat(q->vfio_group_path, "noiommu-");
	strcat(q->vfio_group_path, q->iommu_name);

	/* open group */
	q->group = open(q->vfio_group_path, O_RDWR);
	if (q->group < 0) {
		if (errno == EBUSY)
			return -EBUSY;
		WD_ERR("open vfio group fail(%s), ret=%d\n",
			q->vfio_group_path, q->group);
		return q->group;
	}
	strncpy(q->mdev_path, temp_path, PATH_STR_SIZE);

	return 0;
}

int _get_mdev_group(struct wd_queue *q)
{
	DIR *parent_dev;
	struct dirent *device;
	char *dname;
	int ret;

	if (!q) {
		WD_ERR("%s:input params err!\n", __func__);
		return -EINVAL;
	}
	parent_dev = opendir(q->mdev_path);
	if (!parent_dev) {
		WD_ERR("fail to open %s!\n", q->mdev_path);
		return -ENODEV;
	}
	while ((device = readdir(parent_dev)) != NULL) {
		dname = device->d_name;
		if (strncmp(dname, ".", 1) == 0 ||
		    strncmp(dname, "..", 2) == 0)
			continue;
		if (strlen(dname) < 36)
			continue;
		/* check if it is a uuid name, i think this is enough :) */
		if (dname[8] == '-' && dname[13] == '-' &&
		    dname[18] == '-' && dname[23] == '-') {
			ret = _mdev_check(q, dname);
			if (!ret) {
				strncpy(q->mdev_name, dname, WD_NAME_SIZE);
				closedir(parent_dev);
				return 0;
			} else if (ret == -EBUSY) {
				continue;
			} else {
				WD_ERR("Open %s unknow err!\n", dname);
				closedir(parent_dev);
				return -EINVAL;
			}
		}
	}
	closedir(parent_dev);
	return -ENODEV;
}

static void _put_algo_mdev(struct wd_queue *q)
{
	if (q->mdev > 0 && q->is_new_group)
		close(q->mdev);
}

static int _get_algo_mdev(struct wd_queue *q)
{
	int ret;
	struct wd_algo_info *ainfo;
	struct wd_dev_info *wd_info;

	/* Create by the order of priority of device */
	TAILQ_FOREACH(wd_info, &wd_dev_cache_list, next) {
		ainfo = wd_info->alg_list;
check_next_alg:
		if (!ainfo)
			continue;
		if (strncmp(ainfo->name, q->capa.alg, strlen(q->capa.alg)) ||
		    __capa_check(ainfo, &q->capa)) {
			ainfo = ainfo->next;
			goto check_next_alg;
		}
		strncpy(q->mdev_path, ainfo->algo_path, PATH_STR_SIZE);
		strcat(q->mdev_path, "/../..");
		q->iommu_type = ainfo->dinfo->iommu_type;
		if (wd_info->group_fd > 0) {
			q->group = wd_info->group_fd;
			strncpy(q->mdev_name, wd_info->mdev_name,
			    WD_NAME_SIZE);
			q->is_new_group = 0;
		} else {
			ret = _get_mdev_group(q);
			if (ret) {
				WD_ERR("fail to get mdev in %s\n",
					q->mdev_path);
				continue;
			}
			wd_info->group_fd = q->group;
			strncpy(wd_info->mdev_name, q->mdev_name,
			    WD_NAME_SIZE);
			q->is_new_group = 1;
		}
		q->hw_type = ainfo->api;
		q->alg_info = ainfo;

		return 0;
	}
	return -ENODEV;
}

static int _get_vfio_facility(struct wd_queue *q)
{
	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status) };
	struct wd_dev_info *dinfo;
	int ret;
	int iommu_ext;

	dinfo = ((struct wd_algo_info *)q->alg_info)->dinfo;

	/* container from outside */
	if (q->container > 0)
		q->is_ext_container = 1;

	if (q->container <= 0 && dinfo->container_fd > 0) {
		q->container = dinfo->container_fd;
		q->is_ext_container = 1;
	}

	if (q->container <= 0 && q->is_new_group) {
		/* Create a new vfio container */
		q->container = open("/dev/vfio/vfio", O_RDWR);
		if (q->container < 0) {
			WD_ERR("Create VFIO container fail!\n");
			ret = -ENODEV;
			goto out_with_group;
		}
		q->is_ext_container = 0;
		dinfo->container_fd = q->container;
	} else if (q->container <= 0 && !q->is_new_group) {

		/* while using old group, cannot create new container, because
		 * the old group has already been added into another container.
		 */
		WD_ERR("%s():group %d already added into a container!\n",
				__func__, q->group);
		ret = -EINVAL;
		goto out_with_group;
	}

	/* Check the exist vfio container */
	if (ioctl(q->container, VFIO_GET_API_VERSION) !=
	    VFIO_API_VERSION) {
		WD_ERR("VFIO version check fail!\n");
		ret = -EINVAL;
		goto out_with_group;
	}

	/* Support the IOMMU driver we want. */
	iommu_ext = dinfo->iommu_type;
	if (ioctl(q->container, VFIO_CHECK_EXTENSION, iommu_ext) < 0) {
		WD_ERR("VFIO iommu check fail!\n");
		ret = -EINVAL;
		goto out_with_group;
	}

	if (!q->is_new_group) {
		q->mdev = dinfo->mdev_fd;
		goto bind_directly;
	}

	ioctl(q->group, VFIO_GROUP_GET_STATUS, &group_status);
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		WD_ERR("VFIO group is not viable\n");
		ret = -ENODEV;
		goto out_with_group;
	}

	if ((ioctl(q->group, VFIO_GROUP_SET_CONTAINER, &q->container))) {
		WD_ERR("VFIO group fail on VFIO_GROUP_SET_CONTAINER\n");
		goto out_with_group;
	}

	if (ioctl(q->container, VFIO_SET_IOMMU, iommu_ext)) {
		WD_ERR("VFIO fail on VFIO_SET_IOMMU(%d)\n", iommu_ext);
		ret = -ENODEV;
		goto out_with_group;
	}

	q->mdev = ioctl(q->group, VFIO_GROUP_GET_DEVICE_FD, q->mdev_name);
	if (q->mdev < 0) {
		WD_ERR("VFIO fail on VFIO_GROUP_GET_DEVICE_FD\n");
		ret = q->mdev;
		goto out_with_group;
	}
	dinfo->mdev_fd = q->mdev;

bind_directly:
#ifdef WITH_SVA_SUPPORT
	q->dma_flag = dinfo->dma_flag;
	ret = _wd_bind_process(q);
	if (ret) {
		close(q->mdev);
		WD_ERR("VFIO fails to bind process!\n");
		goto out_with_group;

	}
#endif

	return 0;

out_with_group:
	if (q->group > 0)
		close(q->group);

	if (q->container > 0)
		close(q->container);

	return ret;
}

static void _put_vfio_facility(struct wd_queue *q)
{
#ifdef WITH_SVA_SUPPORT
	int ret;

	if (q->pasid <= 0) {
		WD_ERR("Wd queue pasid err! pasid=%d\n", q->pasid);
		return;
	}
	ret = _wd_unbind_process(q);
	if (ret) {
		WD_ERR("VFIO fails to unbind process!\n");
		return;
	}
#endif
	if (q->group > 0 && q->is_new_group)
		close(q->group);
	if (q->container > 0 && !q->is_ext_container)
		close(q->container);
}

static int _get_queue(struct wd_queue *q)
{
	int ret;

	if (q->mdev > 0) {
		ret = ioctl(q->mdev, VFIO_WDEV_CMD_GET_Q, (unsigned long)q->capa.alg);
		if (ret < 0) {
			printf("VFIO_WDEV_CMD_GET_Q ioctl fail!\n");
			return -1;
		}
		q->index = (__u16)ret;
	} else {
		printf("mdev is not open?\n");
		return -1;
	}

	return 0;
}

static void _put_queue(struct wd_queue *q)
{
	int ret;

	if (q->mdev > 0) {
		ret = ioctl(q->mdev, VFIO_WDEV_CMD_PUT_Q, (unsigned long)q->index);
		if (ret < 0)
			printf("VFIO_WDEV_CMD_PUT_Q ioctl fail!\n");
	}
}

static int _set_pasid(struct wd_queue *q)
{
	unsigned long data = 0;

	data |= q->pasid;

	/* here we think it is 64bit system, or will be fail! */
	data |= ((unsigned long)q->index << 32);

	return ioctl(q->mdev, VFIO_WDEV_CMD_SET_PASID, data);
}

static int _unset_pasid(struct wd_queue *q)
{
	int ret;
	unsigned long data = 0;

	/* here we think it is 64bit system, or will be fail! */
	data |= ((unsigned long)q->index << 32);
	ret = ioctl(q->mdev, VFIO_WDEV_CMD_CLR_PASID, data);
	if (ret) {
		WD_ERR("unset pasid ioctl fail!\n");
		return ret;
	}

	return 0;
}

int wd_request_queue(int container, struct wd_queue *q, struct wd_capa *capa)
{
	int ret;

	ret = _find_available_res(capa);
	if (ret < 0) {
		WD_ERR("Fail to find available algorithms!\n");
		return -ENODEV;
	}
	memcpy(&q->capa, capa, sizeof(*capa));
	q->container = container;
	ret = _get_algo_mdev(q);
	if (ret) {
		WD_ERR("Fail to get mdev!\n");
		return -ENODEV;
	}
	ret = _get_vfio_facility(q);
	if (ret) {
		WD_ERR("Fail to get VFIO facility!\n");
		goto out_with_mdev;
	}
	ret = _get_queue(q);
	if (ret) {
		WD_ERR("Fail to get queue!\n");
		goto out_with_vfio;
	}
	ret = _set_pasid(q);
	if (ret) {
		WD_ERR("set pasid fail!\n");
		goto set_pasid_fail;
	}
	ret = drv_open(q);
	if (ret) {
		WD_ERR("Driver queue init fail!\n");
		goto drv_exit;
	}

	return ret;

drv_exit:
	_unset_pasid(q);
set_pasid_fail:
	_put_queue(q);
out_with_vfio:
	_put_vfio_facility(q);
out_with_mdev:
	_put_algo_mdev(q);


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

int wd_send_sync(struct wd_queue *q, void *req, __u16 ms)
{
	int ret;
	unsigned long data;

	data = ((unsigned long)q->index << 16) | ((unsigned long)ms & 0xffff);
	while (1) {
		ret = wd_send(q, req);
		if (ret == -EBUSY) {
			wd_flush(q);
			ret = ioctl(q->mdev, VFIO_WDEV_CMD_WAIT, data);
			if (ret)
				return ret;
		} else
			return ret;
	}
}

int wd_recv_sync(struct wd_queue *q, void **resp, __u16 ms)
{
	int ret;
	unsigned long data;

	data = ((unsigned long)q->index << 16) | ((unsigned long)ms & 0xffff);
	while (1) {
		ret = wd_recv(q, resp);
		if (ret == -EBUSY) {
			wd_flush(q);
			ret = ioctl(q->mdev, VFIO_WDEV_CMD_WAIT, data);
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
	(void)_unset_pasid(q);
	_put_queue(q);
	_put_vfio_facility(q);
	_put_algo_mdev(q);
}

static int _wd_mem_share_type1(struct wd_queue *q, const void *addr,
			       size_t size, int flags)
{
	struct vfio_iommu_type1_dma_map dma_map;

	if (q->dma_flag & VFIO_WDEV_DMA_SVM_NO_FAULT)
		return mlock(addr, size);
#ifdef WITH_SVA_SUPPORT
	else if ((q->dma_flag & VFIO_WDEV_DMA_MULTI_PROC_MAP) &&
		 (q->pasid > 0))
		dma_map.pasid = q->pasid;
#endif
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

	if (q->dma_flag & VFIO_WDEV_DMA_SVM_NO_FAULT){
		(void)munlock(addr, size);
		return;
	}
#ifdef WITH_SVA_SUPPORT
	dma_unmap.iova = (__u64)addr;
	if ((q->dma_flag & VFIO_WDEV_DMA_MULTI_PROC_MAP) && (q->pasid > 0))
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

