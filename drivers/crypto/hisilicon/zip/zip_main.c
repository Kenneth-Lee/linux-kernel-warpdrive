// SPDX-License-Identifier: GPL-2.0+
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/vfio_spimdev.h>
#include "zip.h"
#include "zip_crypto.h"

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

LIST_HEAD(hisi_zip_list);
DEFINE_MUTEX(hisi_zip_list_lock);

static const char hisi_zip_name[] = "hisi_zip";

static const struct pci_device_id hisi_zip_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa250) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa251) },
	{ 0, }
};

static inline void hisi_zip_add_to_list(struct hisi_zip *hisi_zip)
{
	mutex_lock(&hisi_zip_list_lock);
	list_add_tail(&hisi_zip->list, &hisi_zip_list);
	mutex_unlock(&hisi_zip_list_lock);
}

static void hisi_zip_set_user_domain_and_cache(struct hisi_zip *hisi_zip)
{
	/* to do: init zip user domain and cache */
	/* cache */
	/* kenny.fixme: should be writel_relax, isn't it? */
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_ARCA_CHE_0);
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_ARCA_CHE_1);
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_AWCA_CHE_0);
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_AWCA_CHE_1);
	/* user domain configurations */
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_BD_RUSER_32_63);
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_SGL_RUSER_32_63);
	writel(0x40001071, hisi_zip->qm.io_base + HZIP_DATA_RUSER_32_63);
	writel(0x40001071, hisi_zip->qm.io_base + HZIP_DATA_WUSER_32_63);
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_BD_WUSER_32_63);

	/* fsm count */
	writel(0xfffffff, hisi_zip->qm.io_base + HZIP_FSM_MAX_CNT);

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
	writel(0x10005, hisi_zip->qm.io_base + 0x301004);

	/* to check: enable counters */

	/* to check: configure mastooo dfx & configure larger packet. */
}

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
static ssize_t algorithm_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev->parent);

	return sprintf(buf, "todo: %s: zlib?gzip?\n", spimdev->name);
}

static ssize_t algorithm_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf,
				  size_t count)
{
	/* todo: set algorithm: zlib, gzip, etc. */
	return count;
}

static DEVICE_ATTR_RW(algorithm);

static struct attribute *mdev_dev_attrs[] = {
	&dev_attr_algorithm.attr,
	NULL,
};

static const struct attribute_group mdev_dev_group = {
	.name  = VFIO_SPIMDEV_PDEV_ATTRS_GRP_NAME,
	.attrs = mdev_dev_attrs,
};

static const struct attribute_group *mdev_dev_groups[] = {
	&mdev_dev_group,
	NULL,
};
#endif

static int hisi_zip_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_zip *hisi_zip;
	struct qm_info *qm;
	int ret;
	u32 val;

	hisi_zip = devm_kzalloc(&pdev->dev, sizeof(*hisi_zip), GFP_KERNEL);
	if (!hisi_zip)
		return -ENOMEM;
	hisi_zip_add_to_list(hisi_zip);

	qm = &hisi_zip->qm;

	qm->pdev = pdev;
	qm->ver = 1; /* fixme: should be set as per the hardware version */
	qm->sqe_size = HZIP_SQE_SIZE;
	ret = hisi_qm_init(hisi_zip_name, qm);
	if (ret)
		goto err_with_hisi_zip;

#define ZIP_ADDR(offset) QM_ADDR(qm, offset)

	if (pdev->is_physfn) {
		/* fixme:
		 * 1. should use writel_relax
		 * 2. should wrap into qm but need a wrap logic
		 */
		/* qm user domain */
		writel(0x40001070, ZIP_ADDR(QM_ARUSER_M_CFG_1));
		writel(0xfffffffe, ZIP_ADDR(QM_ARUSER_M_CFG_ENABLE));
		writel(0x40001070, ZIP_ADDR(QM_AWUSER_M_CFG_1));
		writel(0xfffffffe, ZIP_ADDR(QM_AWUSER_M_CFG_ENABLE));
		writel(0xffffffff, ZIP_ADDR(QM_WUSER_M_CFG_ENABLE));
		writel(0x4893, ZIP_ADDR(QM_CACHE_CTL));

		val = readl(ZIP_ADDR(QM_PEH_AXUSER_CFG));
		val |= (1 << 11);
		writel(val, ZIP_ADDR(QM_PEH_AXUSER_CFG));

		/* qm cache */
		writel(0xffff,     ZIP_ADDR(QM_AXI_M_CFG));
		writel(0xffffffff, ZIP_ADDR(QM_AXI_M_CFG_ENABLE));
		writel(0xffffffff, ZIP_ADDR(QM_PEH_AXUSER_CFG_ENABLE));

		ret = hisi_qm_mem_start(qm);
		if (ret)
			goto err_with_qm_init;

		hisi_zip_set_user_domain_and_cache(hisi_zip);

		qm->qp_base = HZIP_PF_DEF_Q_BASE;
		qm->qp_num = HZIP_PF_DEF_Q_NUM;
	}

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	qm->mdev_dev_groups = mdev_dev_groups;
#endif

	ret = hisi_qm_start(qm);
	if (ret)
		goto err_with_qm_init;

	/* todo: exception irq handler register, ES did not support */

	return 0;

err_with_qm_init:
	hisi_qm_uninit(qm);
err_with_hisi_zip:
	kfree(hisi_zip);
	return ret;
}

static void hisi_zip_remove(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);
	struct qm_info *qm = &hisi_zip->qm;

	hisi_qm_stop(qm);
	hisi_qm_uninit(qm);
	kfree(hisi_zip);
}

static int hisi_zip_pci_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	/* todo: set queue number for VFs */

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
	if (ret < 0) {
		pr_err("zip: can't register hisi zip driver.\n");
		return ret;
	}

	ret = hisi_zip_register_to_crypto();
	if (ret < 0) {
		pr_err("zip: can't register hisi zip to crypto.\n");
		pci_unregister_driver(&hisi_zip_pci_driver);
		return ret;
	}

	return 0;
}

static void __exit hisi_zip_exit(void)
{
	hisi_zip_unregister_from_crypto();
	pci_unregister_driver(&hisi_zip_pci_driver);
}

module_init(hisi_zip_init);
module_exit(hisi_zip_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("Driver for HiSilicon ZIP accelerator");
MODULE_DEVICE_TABLE(pci, hisi_zip_dev_ids);
