/*
 * Copyright 2018 (c) HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/vfio_wdev.h>
#include "zip.h"
#include "zip_wd.h"

#define HZIP_VF_NUM			63
#define HZIP_QUEUE_NUM_V1		4096
#define HZIP_QUEUE_NUM_V2		1024

#define HZIP_FSM_MAX_CNT		0x301008

#define HZIP_PORT_ARCA_CHE_0		0x301040
#define HZIP_PORT_ARCA_CHE_1		0x301044
#define HZIP_PORT_AWCA_CHE_0		0x301060
#define HZIP_PORT_AWCA_CHE_1		0x301064

#define HZIP_BD_RUSER_32_63		0x301110
#define HZIP_SGL_RUSER_32_63		0x30111c
#define HZIP_DATA_RUSER_32_63		0x301128
#define HZIP_DATA_WUSER_32_63		0x301134
#define HZIP_BD_WUSER_32_63		0x301140


char hisi_zip_name[] = "hisi_zip";

static const struct pci_device_id hisi_zip_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa250) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa251) },
	{ 0, }
};

static irqreturn_t hisi_zip_irq(int irq, void *data)
{
	struct qm_info *qm = (struct qm_info *)data;
	u32 int_source;

	/* There is an interrupt or not */
	int_source = hisi_acc_get_irq_source(qm);

	if (int_source)
		return IRQ_WAKE_THREAD;
	else
		return IRQ_HANDLED;
}

static int hisi_zip_sqe_handler(struct hisi_acc_qp *qp, void *sqe)
{

	u32 status = ((struct hisi_zip_sqe *)sqe)->dw3 & 0xff;

	if (!status) {
		/* fix me */
		return IRQ_HANDLED;
	}

	/* to handle err */
	return -1;
}

static void hisi_zip_set_user_domain_and_cache(struct hisi_zip *hisi_zip)
{
	/* to do: init zip user domain and cache */
	/* cache */
	writel(0xffffffff, hisi_zip->io_base + HZIP_PORT_ARCA_CHE_0);
	writel(0xffffffff, hisi_zip->io_base + HZIP_PORT_ARCA_CHE_1);
	writel(0xffffffff, hisi_zip->io_base + HZIP_PORT_AWCA_CHE_0);
	writel(0xffffffff, hisi_zip->io_base + HZIP_PORT_AWCA_CHE_1);
	/* user domain configurations */
	writel(0x40001070, hisi_zip->io_base + HZIP_BD_RUSER_32_63);
	writel(0x40001070, hisi_zip->io_base + HZIP_SGL_RUSER_32_63);
	writel(0x40001071, hisi_zip->io_base + HZIP_DATA_RUSER_32_63);
	writel(0x40001071, hisi_zip->io_base + HZIP_DATA_WUSER_32_63);
	writel(0x40001070, hisi_zip->io_base + HZIP_BD_WUSER_32_63);

	/* fsm count */
	writel(0xfffffff, hisi_zip->io_base + HZIP_FSM_MAX_CNT);

	/* to do: big/little endian configure: default: 32bit little */

	/* to do: SGL offset, later to do */
	/* hisi_zip_write(hisi_zip, SGE_OFFSET_REG_VAL, ZIP_SGL_CONTROL); */

	/* to do: PRP page size */
	/* hisi_zip_write(hisi_zip, PRP_PAGE_SIZE, ZIP_PAGE_CONTROL); */

	/* CRC initial*/
	/* hisi_zip_write(hisi_zip, T10_DIF_CRC_INITIAL, ZIP_DIF_CRC_INIT); */

	/* Compress head length */
	/* hisi_zip_write(hisi_zip, STORE_COMP_HEAD_LEN, ZIP_COM_HEAD_LENGTH);*/

	/* to check: clock gating, core, decompress verify enable */
	writel(0x10005, hisi_zip->io_base + 0x301004);

	/* to check: enable counters */

	/* to check: configure mastooo dfx & configure larger packet. */
}

static int hisi_zip_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_zip *hisi_zip;
	struct qm_info *qm;
	int ret;
	u16 ecam_val16;
	u32 q_base, q_num;

	pci_set_power_state(pdev, PCI_D0);
	ecam_val16 = (PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY);
	pci_write_config_word(pdev, PCI_COMMAND, ecam_val16);

	ret = pci_enable_device_mem(pdev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Can't enable device mem!\n");
		return ret;
	}

	ret = pci_request_mem_regions(pdev, hisi_zip_name);
	if (ret < 0) {
		dev_err(&pdev->dev, "Can't request mem regions!\n");
		goto err_pci_reg;
	}

	/* to do: zip ras */

	/* init hisi_zip */
	hisi_zip = devm_kzalloc(&pdev->dev, sizeof(*hisi_zip), GFP_KERNEL);
	if (!hisi_zip) {
		ret = -ENOMEM;
		goto err_hisi_zip;
	}

	hisi_zip->phys_base = pci_resource_start(pdev, 2);
	hisi_zip->size = pci_resource_len(pdev, 2);
	hisi_zip->io_base = devm_ioremap(&pdev->dev, hisi_zip->phys_base,
					 hisi_zip->size);
	if (!hisi_zip->io_base) {
		ret = -EIO;
		goto err_hisi_zip;
	}
	hisi_zip->pdev = pdev;

	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	pci_set_master(pdev);

	ret = pci_alloc_irq_vectors(pdev, 1, 2, PCI_IRQ_MSI);
	if (ret < 2) {
		dev_err(&pdev->dev, "Enable MSI vectors fail!\n");
		if (ret > 0)
			goto err_pci_irq;
		else
			goto err_hisi_zip;
	}

	ret = hisi_acc_qm_info_create(&pdev->dev, hisi_zip->io_base,
				      pdev->devfn, ES, &qm);
	if (ret) {
		dev_err(&pdev->dev, "Fail to create QM!\n");
		goto err_pci_irq;
	}

	if (pdev->is_physfn) {
		hisi_acc_set_user_domain(qm, ZIP);
		hisi_acc_set_cache(qm, ZIP);
		ret = hisi_acc_init_qm_mem(qm);
		if (ret) {
			dev_err(&pdev->dev, "Fail to hisi_acc_init_qm_mem!\n");
			goto err_pci_irq;
		}
		hisi_zip_set_user_domain_and_cache(hisi_zip);

		q_base = HZIP_PF_DEF_Q_BASE;
		q_num = HZIP_PF_DEF_Q_NUM;
		hisi_acc_qm_info_vft_config(qm, q_base, q_num);
	} else if (pdev->is_virtfn) {
		/* get queue base and number, ES did not support to get this
		 * from mailbox. so fix me...
		 */
		hisi_acc_get_vft_info(qm, &q_base, &q_num);
	}

	ret = hisi_acc_qm_info_create_eq(qm);
	if (ret) {
		dev_err(&pdev->dev, "Fail to create eq!\n");
		goto err_pci_irq;
	}

	ret = hisi_acc_qm_info_add_queue(qm, q_base, q_num);
	if (ret) {
		dev_err(&pdev->dev, "Fail to add queue to QM!\n");
		goto err_pci_irq;
	}

	hisi_zip->qm_info = qm;
	hisi_acc_qm_set_priv(qm, hisi_zip);

	ret = devm_request_threaded_irq(&pdev->dev, pci_irq_vector(pdev, 0),
					hisi_zip_irq, hacc_irq_thread,
					IRQF_SHARED, hisi_zip_name,
					hisi_zip->qm_info);
	if (ret)
		goto err_pci_irq;

	/* to do: exception irq handler register, ES did not support */

	ret = hisi_zip_register_to_wd(hisi_zip);
	if (ret)
		goto err_pci_irq;

	/* to do: register to crypto */

	return 0;

err_pci_irq:
	pci_free_irq_vectors(pdev);
err_hisi_zip:
	pci_release_mem_regions(pdev);
err_pci_reg:
	pci_disable_device(pdev);

	return ret;
}

static void hisi_zip_remove(struct pci_dev *pdev)
{
	struct vfio_wdev *wdev = pci_get_drvdata(pdev);

	vfio_wdev_unregister(wdev);
}

static int hisi_zip_pci_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	/* to do: set queue number for VFs */

	return 0;
}

static struct pci_driver hisi_zip_pci_driver = {
	.name		= "hisi_zip",
	.id_table	= hisi_zip_dev_ids,
	.probe		= hisi_zip_probe,
	.remove		= hisi_zip_remove,
	.sriov_configure = hisi_zip_pci_sriov_configure
};

static int __init hisi_zip_init(void)
{
	int ret;

	ret = pci_register_driver(&hisi_zip_pci_driver);
	if (ret < 0)
		pr_err("zip: can't register hisi zip driver.\n");

	return ret;
}

static void __exit hisi_zip_exit(void)
{
	pci_unregister_driver(&hisi_zip_pci_driver);
}

module_init(hisi_zip_init);
module_exit(hisi_zip_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("Driver for HiSilicon ZIP accelerator");
MODULE_DEVICE_TABLE(pci, hisi_zip_dev_ids);
