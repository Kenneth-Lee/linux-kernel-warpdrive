/*
 * Copyright 2018 (c) HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/vfio_wdev.h>
#include "../qm.h"
#include "zip.h"

static void *hzip_wd_queue_list[HZIP_PF_DEF_Q_NUM];

static struct attribute *mdev_dev_attrs[] = {
	VFIO_WDEV_DEFAULT_MDEV_DEV_ATTRS
	NULL,
};

static const struct attribute_group mdev_dev_group = {
	.name  = VFIO_WDEV_MDEV_ATTRS_GRP_NAME,
	.attrs = mdev_dev_attrs,
};

/* this will be showed under virtual device's directory */
static const  struct attribute_group *mdev_dev_groups[] = {
	&mdev_dev_group,
	NULL,
};

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return 0;
}
MDEV_TYPE_ATTR_RO(name);

static ssize_t
device_api_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return 0;
}
MDEV_TYPE_ATTR_RO(device_api);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	/* how many free queues now one function can support */
	return 0;
}
MDEV_TYPE_ATTR_RO(available_instances);

/* fix me:
 * add zlib here. and why we add name, device_api, available_instances
 */
static struct attribute *hzip_zlib_type_attrs[] = {
	VFIO_WDEV_DEFAULT_MDEV_TYPE_ATTRS
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group hzip_zlib_type_group = {
	.name  = "zlib",
	.attrs = hzip_zlib_type_attrs,
};

/* this will be showed under physical device's supported_type_groups
 * directory
 */
static struct attribute_group *mdev_type_groups[] = {
	&hzip_zlib_type_group,
	NULL,
};

static struct vfio_wdev_queue *hzip_index_queue(struct vfio_wdev *wdev, u16 index)
{
	if (index >= HZIP_PF_DEF_Q_NUM)
		return NULL;
	return hzip_wd_queue_list[index];
}

static int hzip_get_queue(struct vfio_wdev *wdev, char *devalgo_name,
			  struct vfio_wdev_queue **q)
{
	struct hisi_zip *hzip = wdev->priv;
	struct qm_info *qm = hzip->qm_info;
	struct hisi_acc_qp *qp;
	struct vfio_wdev_queue *wd_q;
	int ret;

	u8 alg_type = 0; /* fix me here */

	ret = hisi_acc_create_qp(qm, &qp, HZIP_SQE_SIZE, alg_type);
	if (ret < 0) {
		dev_err(wdev->dev, "Can't create zip queue pair!\n");
		goto err_create_qp;
	}
	qp->type = WD_QUEUE;

	wd_q = kzalloc(sizeof(struct vfio_wdev_queue), GFP_KERNEL);
	if (!wd_q) {
		ret = -ENOMEM;
		goto err_wd_q;
	}
	wd_q->priv = qp;
	wd_q->wdev = hzip->wdev;
	wd_q->qid = (u16)ret;

	hzip_wd_queue_list[ret] = wd_q;
	*q = wd_q;

	return ret;

err_wd_q:
	hisi_acc_release_qp(qp);
err_create_qp:
	return ret;
}

static int hzip_put_queue(struct vfio_wdev_queue *q)
{
	struct hisi_acc_qp *qp = q->priv;

	/* need first stop harware queue(don't support in ES), then release
	 * resources.
	 */
	hisi_acc_release_qp(qp);

	kfree(q);

	return 0;
}

static int hzip_open(struct vfio_wdev *wdev)
{
	/* after sending a sqc/cqc mb, hardware queue can work */
	return 0;
}

static int hzip_close(struct vfio_wdev *wdev)
{
	/* hardware queue can not be closed in ES :( */
	return 0;
}

static int hzip_is_q_updated(struct vfio_wdev_queue *q)
{
	/* to do: now we did not support wd sync interface yet */
	return 0;
}

/* map sq/cq/doorbell to user space */
static int hzip_mmap(struct vfio_wdev_queue *q, struct vm_area_struct *vma)
{
	struct hisi_acc_qp *qp = (struct hisi_acc_qp *)q->priv;
	struct qm_info *qm = qp->parent;
	void *sq = qp->sq_base;
	void *cq = qp->cq_base;
	struct hisi_zip *hzip = (struct hisi_zip *)hisi_acc_qm_get_priv(qm);
	u8 region;

	vma->vm_flags |= (VM_IO | VM_LOCKED | VM_DONTEXPAND | VM_DONTDUMP);
	region = _VFIO_WDEV_REGION(vma->vm_pgoff);

	switch (region) {
	case 0:
		vma->vm_pgoff = 0;
		return dma_mmap_coherent(qp->p_dev, vma, sq,
					 qp->sq_base_dma, HZIP_SQ_SIZE);
	case 1:
		/* fix me */
		vma->vm_pgoff = 0;
		return dma_mmap_coherent(qp->p_dev, vma, cq,
					 qp->cq_base_dma, QM_CQ_SIZE);
	case 2:
	/* fix me: this is not safe as multiple queues use the same doorbell */
		return remap_pfn_range(vma, vma->vm_start,
				       hzip->phys_base >> PAGE_SHIFT,
				       hzip->size,
				       pgprot_noncached(vma->vm_page_prot));
	default:
		return -EINVAL;
	}
}

static int hzip_set_pasid(struct vfio_wdev_queue *q, int pasid)
{
	struct hisi_acc_qp *qp = q->priv;

	return hisi_acc_set_pasid(qp, (u16)pasid);
}

static int hzip_unset_pasid(struct vfio_wdev_queue *q)
{
	struct hisi_acc_qp *qp = q->priv;

	return hisi_acc_set_pasid(qp, -1);
}

static long hzip_ioctl(struct vfio_wdev *dev, unsigned int cmd, unsigned long arg)
{
	struct hisi_acc_qp *qp;
	struct vfio_wdev_queue *q;
	u16 id;

	switch (cmd) {

	/* user to read the data in SQC cache */
	case HACC_QM_MB_SQC:
		id = (u16)arg;
		q = hzip_index_queue(dev, id);
		if (!q)
			return -ENODEV;
		qp = q->priv;

		return qp->queue_id;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct vfio_wdev_ops hzip_ops = {
	.get_queue = hzip_get_queue,
	.put_queue = hzip_put_queue,
	.open = hzip_open,
	.close = hzip_close,
	.is_q_updated = hzip_is_q_updated,
	.mmap = hzip_mmap,
	.index_queue = hzip_index_queue,
	.set_pasid = hzip_set_pasid,
	.unset_pasid = hzip_unset_pasid,
	.ioctl = hzip_ioctl,
};

int hisi_zip_register_to_wd(struct hisi_zip *hisi_zip)
{
	struct pci_dev *pdev = hisi_zip->pdev;
	struct vfio_wdev *wdev;
	int ret;

	wdev = devm_kzalloc(&pdev->dev, sizeof(struct vfio_wdev), GFP_KERNEL);
	if (!wdev) {
		ret = -ENOMEM;
		goto err_wdev_alloc;
	}

	hisi_zip->wdev = wdev;

	wdev->iommu_type = VFIO_TYPE1_IOMMU;
	//wdev->dma_flag = VFIO_WDEV_DMA_MULTI_PROC_MAP;
	wdev->dma_flag = VFIO_WDEV_DMA_SVM_NO_FAULT;
	wdev->owner = THIS_MODULE;
	wdev->name = "hisi_zip";
	wdev->dev = &pdev->dev;
	wdev->is_vf = pdev->is_virtfn;
	wdev->priv = hisi_zip;
	wdev->node_id = pdev->dev.numa_node;
	wdev->priority = 0;
	wdev->api_ver = "wd_hzip_v1";
	wdev->throughput_level = 10;
	wdev->latency_level = 10;
	wdev->flags = 0;

	wdev->mdev_fops.mdev_attr_groups = mdev_dev_groups;
	wdev->mdev_fops.supported_type_groups = mdev_type_groups;
	wdev->ops = &hzip_ops;

	ret = vfio_wdev_register(wdev);
	if (ret) {
		dev_err(&pdev->dev, "Fail to register ZIP to WD system!\n");
		goto err_wdev_alloc;
	}

	return 0;

err_wdev_alloc:

	return ret;
}
