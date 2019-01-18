// SPDX-License-Identifier: GPL-2.0+
#include <linux/acpi.h>
#include <linux/aer.h>
#include <linux/bitops.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/seq_file.h>
#include <linux/topology.h>
#include <linux/uacce.h>
#include "hpre.h"

#define HPRE_VF_NUM			63
#define HPRE_QUEUE_NUM_V1		4096
#define HPRE_QUEUE_NUM_V2		1024
#define HPRE_CLUSTERS_NUM		4
#define HPRE_CLUSTER_CORES		4
#define HPRE_QM_ABNML_INT_MASK		0x100004
#define HPRE_COMM_CNT_CLR_CE		0x0
#define HPRE_FSM_MAX_CNT			0x301008
#define HPRE_VFG_AXQOS			0x30100c
#define HPRE_VFG_AXCACHE			0x301010
#define HPRE_RDCHN_INI_CFG		0x301014
#define HPRE_BD_ENDIAN			0x301020
#define HPRE_ECC_BYPASS			0x301024
#define HPRE_POISON_BYPASS		0x30102c
#define HPRE_BD_ARUSR_CFG		0x301030
#define HPRE_BD_AWUSR_CFG		0x301034
#define HPRE_INT_MASK			0x301400
#define HPRE_CORE_INT_DISABLE		0x3ff
#define HPRE_RAS_ECC_1BIT_TH		0x30140c

#define HPRE_TYPES_ENB			0x301038
#define HPRE_PORT_ARCA_CHE_0		0x301040
#define HPRE_PORT_ARCA_CHE_1		0x301044
#define HPRE_PORT_AWCA_CHE_0		0x301060
#define HPRE_PORT_AWCA_CHE_1		0x301064

#define HPRE_BD_RUSER_32_63		0x301110
#define HPRE_SGL_RUSER_32_63		0x30111c
#define HPRE_DATA_RUSER_32_63		0x301128
#define HPRE_DATA_WUSER_32_63		0x301134
#define HPRE_BD_WUSER_32_63		0x301140
#define HPRE_RDCHN_INI_ST			0x301a00
#define HPRE_CORE_ENB			0x302004
#define HPRE_CORE_INI_CFG			0x302020
#define HPRE_CORE_INI_STATUS		0x302080
#define HPRE_HAC_ECC1_CNT		0x301a04
#define HPRE_HAC_ECC2_CNT		0x301a08
#define HPRE_HAC_INT_ECC1		BIT(0)
#define HPRE_HAC_INT_ECC2		BIT(1)
#define HPRE_HAC_INT_STATUS		0x301800
#define HPRE_HAC_SOURCE_INT		0x301600
#define MASTER_GLOBAL_CTRL_SHUTDOWN	1
#define MASTER_TRANS_RETURN_RW		3
#define HPRE_MASTER_TRANS_RETURN		0x301500
#define HPRE_MASTER_GLOBAL_CTRL		0x300000

LIST_HEAD(hisi_hpre_list);
DEFINE_MUTEX(hisi_hpre_list_lock);
static const char hpre_name[] = "hisi_hpre";
static const struct pci_device_id hisi_hpre_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa258) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa259) },
	{ 0, }
};
struct hisi_hpre_hw_error {
	u32 int_msk;
	const char *msg;
};

static const struct hisi_hpre_hw_error hpre_hw_error[] = {
	{ .int_msk = BIT(0), .msg = "hpre_ecc_1bitt_err" },
	{ .int_msk = BIT(1), .msg = "hpre_ecc_2bit_err" },
	{ .int_msk = BIT(2), .msg = "hpre_axi_rresp_err" },
	{ .int_msk = BIT(3), .msg = "hpre_axi_bresp_err" },
	{ .int_msk = BIT(4), .msg = "hpre_src_addr_parse_err" },
	{ .int_msk = BIT(5), .msg = "hpre_dst_addr_parse_err" },
	{ .int_msk = BIT(6), .msg = "hpre_pre_in_addr_err" },
	{ .int_msk = BIT(7), .msg = "hpre_pre_in_data_err" },
	{ .int_msk = BIT(8), .msg = "hpre_com_inf_err" },
	{ .int_msk = BIT(9), .msg = "hpre_enc_inf_err" },
	{ .int_msk = BIT(10), .msg = "hpre_pre_out_err" },
	{ /* sentinel */ }
};

enum ctrl_debug_file_index {
	HPRE_CURRENT_QM,
	HPRE_CLEAR_ENABLE,
	HPRE_DEBUG_FILE_NUM,
};

struct ctrl_debug_file {
	enum ctrl_debug_file_index index;
	spinlock_t lock;
	struct hisi_hpre_ctrl *ctrl;
};

/*
 * One HPRE controller has one PF and multiple VFs, some global configurations
 * which PF has need this structure.
 *
 * Just relevant for PF.
 */
struct hisi_hpre_ctrl {
	u32 ctrl_q_num;
	u32 num_vfs;
	struct hisi_hpre *hisi_hpre;
	struct dentry *debug_root;
	struct ctrl_debug_file files[HPRE_DEBUG_FILE_NUM];
};

static int pf_q_num_set(const char *val, const struct kernel_param *kp)
{
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_HUAWEI, 0xa258,
					      NULL);
	u32 n, q_num;
	u8 rev_id;
	int ret;

	if (unlikely(!pdev)) {
		q_num = min_t(u32, HPRE_QUEUE_NUM_V1, HPRE_QUEUE_NUM_V2);
		pr_info("No device found currently, suppose queue number is %d\n",
			q_num);
	} else {
		rev_id = pdev->revision;
		switch (rev_id) {
		case 0x20:
			q_num = HPRE_QUEUE_NUM_V1;
			break;
		case 0x21:
			q_num = HPRE_QUEUE_NUM_V2;
			break;
		default:
			return -EINVAL;
		}
	}

	ret = kstrtou32(val, 10, &n);
	if (ret != 0 || n > q_num)
		return -EINVAL;

	return param_set_int(val, kp);
}

static const struct kernel_param_ops pf_q_num_ops = {
	.set = pf_q_num_set,
	.get = param_get_int,
};

static u32 pf_q_num = HPRE_PF_DEF_Q_NUM;
module_param_cb(pf_q_num, &pf_q_num_ops, &pf_q_num, 0444);
MODULE_PARM_DESC(pf_q_num, "Number of queues in PF(v1 0-4096, v2 0-1024)");

static int uacce_mode;
module_param(uacce_mode, int, UACCE_MODE_NOUACCE);
static inline void hisi_hpre_add_to_list(struct hisi_hpre *hisi_hpre)
{
	mutex_lock(&hisi_hpre_list_lock);
	list_add_tail(&hisi_hpre->list, &hisi_hpre_list);
	mutex_unlock(&hisi_hpre_list_lock);
}

static inline void hisi_hpre_remove_from_list(struct hisi_hpre *hisi_hpre)
{
	mutex_lock(&hisi_hpre_list_lock);
	list_del(&hisi_hpre->list);
	mutex_unlock(&hisi_hpre_list_lock);
}

static int hisi_hpre_set_user_domain_and_cache(struct hisi_hpre *hisi_hpre)
{
	int ret, i;
	u32 val;
	unsigned long offset;
	struct hisi_qm *qm = &hisi_hpre->qm;

#define HPRE_ADDR(offset) (qm->io_base + offset)
	writel(0xfffffffe, HPRE_ADDR(QM_ARUSER_M_CFG_ENABLE));
	writel(0xfffffffe, HPRE_ADDR(QM_AWUSER_M_CFG_ENABLE));
	writel_relaxed(0xffff, HPRE_ADDR(QM_AXI_M_CFG));

	/* HPRE need more time, we close this interupt */
	val = readl_relaxed(HPRE_ADDR(HPRE_QM_ABNML_INT_MASK));
	val |= (1 << 6);
	writel_relaxed(val, HPRE_ADDR(HPRE_QM_ABNML_INT_MASK));

	writel(0x1, hisi_hpre->qm.io_base + HPRE_TYPES_ENB);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_VFG_AXQOS);
	writel(0xff, hisi_hpre->qm.io_base + HPRE_VFG_AXCACHE);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_BD_ENDIAN);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_INT_MASK);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_RAS_ECC_1BIT_TH);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_POISON_BYPASS);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_COMM_CNT_CLR_CE);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_ECC_BYPASS);

	/* While enable data buffer pasid, we need set another REG set */
	writel(0x3, hisi_hpre->qm.io_base + HPRE_BD_ARUSR_CFG);
	writel(0x3, hisi_hpre->qm.io_base + HPRE_BD_AWUSR_CFG);
	writel(0x1, hisi_hpre->qm.io_base + HPRE_RDCHN_INI_CFG);
	ret = readl_relaxed_poll_timeout(hisi_hpre->qm.io_base +
					 HPRE_RDCHN_INI_ST, val,
					 val & BIT(0), 10, 1000);
	if (ret) {
		pr_err("\nHPRE:INI ST TIMEOUT");
		return -ETIMEDOUT;
	}
	for (i = 0; i < HPRE_CLUSTERS_NUM; i++) {
		offset = i * 0x1000;

		/* clusters initiating */
		writel(0xf, hisi_hpre->qm.io_base + offset + HPRE_CORE_ENB);
		writel(0x1, hisi_hpre->qm.io_base + offset + HPRE_CORE_INI_CFG);
		ret = readl_relaxed_poll_timeout(hisi_hpre->qm.io_base +
						 offset + HPRE_CORE_INI_STATUS,
						 val, ((val & 0xf) == 0xf),
						 10, 1000);
		if (ret) {
			pr_err("\nHPRE:CLUSTER %d INI ST STATUS timeout!", i);
			return -ETIMEDOUT;
		}
	}

	return ret;
}

#ifdef HPRE_RAS_ERR/* to be fixed */
static void hpre_hw_error_set_state(struct hisi_hpre *hisi_hpre, bool state)
{
	struct hisi_qm *qm = &hisi_hpre->qm;

	if (state)
		/* enable hpre hw error interrupts */
		writel(0, qm->io_base + HPRE_INT_MASK);
	else
		/* disable hpre hw error interrupts */
		writel(HPRE_CORE_INT_DISABLE, qm->io_base + HPRE_INT_MASK);
}
#endif

static int hisi_hpre_pf_probe_init(struct device *dev, struct hisi_qm *qm,
				  struct hisi_hpre *hisi_hpre)
{
	struct hisi_hpre_ctrl *ctrl;
	u32 nfe_flag;

	ctrl = devm_kzalloc(dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	hisi_hpre->ctrl = ctrl;
	ctrl->hisi_hpre = hisi_hpre;

	switch (qm->ver) {
	case QM_HW_V1:
		ctrl->ctrl_q_num = HPRE_QUEUE_NUM_V1;
		break;

	case QM_HW_V2:
		ctrl->ctrl_q_num = HPRE_QUEUE_NUM_V2;
		break;

	default:
		return -EINVAL;
	}

	hisi_hpre_set_user_domain_and_cache(hisi_hpre);

	nfe_flag = QM_BASE_NFE | QM_ACC_WB_NOT_READY_TIMEOUT;
	hisi_qm_hw_error_init(qm, QM_BASE_CE, nfe_flag, 0,
			      QM_DB_RANDOM_INVALID);
	/* hisi_zip_hw_error_set_state(hisi_hpre, true); */

	return 0;
}

static int hisi_hpre_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_hpre_ctrl *ctrl;
	struct hisi_hpre *hisi_hpre;
	struct hisi_qm *qm;
	enum qm_hw_ver rev_id;
	int ret;

	rev_id = hisi_qm_get_hw_version(pdev);
	if (rev_id < 0)
		return -ENODEV;
	hisi_hpre = devm_kzalloc(&pdev->dev, sizeof(*hisi_hpre), GFP_KERNEL);
	if (!hisi_hpre)
		return -ENOMEM;
	hisi_hpre_add_to_list(hisi_hpre);
	pci_set_drvdata(pdev, hisi_hpre);
	qm = &hisi_hpre->qm;
	qm->pdev = pdev;
	qm->ver = rev_id;
	ctrl = devm_kzalloc(&pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;
	hisi_hpre->ctrl = ctrl;
	qm->sqe_size = HPRE_SQE_SIZE;
	qm->dev_name = hpre_name;
	qm->fun_type = (pdev->device == 0xa258) ? QM_HW_PF : QM_HW_VF;
	qm->algs = "rsa\ndh\n";
	ret = hisi_qm_init(qm);
	if (ret)
		return ret;

	if (pdev->is_physfn) {
		ret = hisi_hpre_pf_probe_init(&pdev->dev, qm, hisi_hpre);
		if (ret)
			goto err_with_qm_init;

		qm->qp_base = HPRE_PF_DEF_Q_BASE;
		qm->qp_num = HPRE_PF_DEF_Q_NUM;
		/* qm->free_qp = qm->qp_num; */
	} else if (qm->fun_type == QM_HW_VF) {
		if (qm->ver == QM_HW_V1) {
			qm->qp_base = HPRE_PF_DEF_Q_NUM;
			qm->qp_num = HPRE_QUEUE_NUM_V1 - HPRE_PF_DEF_Q_NUM;
		} else if (qm->ver == QM_HW_V2)
			/* v2 starts to support get vft by mailbox */
			hisi_qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
	}
	ret = hisi_qm_start(qm);
	if (ret)
		goto err_with_qm_init;

	hisi_hpre_add_to_list(hisi_hpre);
	return 0;

err_with_qm_init:
	hisi_qm_uninit(qm);

	return ret;
}

static int hisi_hpre_vf_q_assign(struct hisi_hpre *hisi_hpre, int num_vfs)
{
	struct hisi_hpre_ctrl *ctrl = hisi_hpre->ctrl;
	struct hisi_qm *qm = &hisi_hpre->qm;
	u32 qp_num = qm->qp_num;
	u32 q_base = qp_num;
	int q_num, remain_q_num, i;
	int ret;

	remain_q_num = ctrl->ctrl_q_num - qp_num;
	q_num = remain_q_num / num_vfs;
	for (i = 1; i <= num_vfs; i++) {
		if (i == num_vfs)
			q_num += remain_q_num % num_vfs;
		ret = hisi_qm_set_vft(qm, i, q_base, (u32)q_num);
		if (ret)
			return ret;
		q_base += q_num;
	}
	return 0;
}

static int hisi_hpre_clear_vft_config(struct hisi_hpre *hisi_hpre)
{
	struct hisi_hpre_ctrl *ctrl = hisi_hpre->ctrl;
	struct hisi_qm *qm = &hisi_hpre->qm;
	u32 i, num_vfs = ctrl->num_vfs;
	int ret;

	for (i = 1; i <= num_vfs; i++) {
		ret = hisi_qm_set_vft(qm, i, 0, 0);
		if (ret)
			return ret;
	}
	ctrl->num_vfs = 0;
	return 0;
}

static int hisi_hpre_sriov_enable(struct pci_dev *pdev, int max_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);
	int pre_existing_vfs, num_vfs, ret;

	pre_existing_vfs = pci_num_vf(pdev);
	if (pre_existing_vfs) {
		dev_err(&pdev->dev,
			"Can't enable VF. Please disable pre-enabled VFs!\n");
		return 0;
	}
	num_vfs = min_t(int, max_vfs, HPRE_VF_NUM);
	ret = hisi_hpre_vf_q_assign(hisi_hpre, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't assign queues for VF!\n");
		return ret;
	}
	hisi_hpre->ctrl->num_vfs = num_vfs;
	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't enable VF!\n");
		hisi_hpre_clear_vft_config(hisi_hpre);
		return ret;
	}
	return num_vfs;
#else
	return 0;
#endif
}

static int hisi_hpre_sriov_disable(struct pci_dev *pdev)
{
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);

	if (pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev,
		"Can't disable VFs while VFs are assigned!\n");

		return -EPERM;
	}

	/* remove in hisi_hpre_pci_driver will be called to free VF resources */
	pci_disable_sriov(pdev);
	return hisi_hpre_clear_vft_config(hisi_hpre);
}

static int hisi_hpre_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return hisi_hpre_sriov_disable(pdev);
	else
		return hisi_hpre_sriov_enable(pdev, num_vfs);
}

static void hisi_hpre_log_hw_error(struct hisi_hpre *hisi_hpre, u32 err_sts)
{
	const struct hisi_hpre_hw_error *err = hpre_hw_error;
	struct device *dev = &hisi_hpre->qm.pdev->dev;
	u32 err_val;

	while (err->msg) {
		if (err->int_msk & err_sts) {
			dev_warn(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);
			if (HPRE_HAC_INT_ECC1 & err_sts) {
				err_val = readl(hisi_hpre->qm.io_base +
						HPRE_HAC_ECC1_CNT);
				dev_warn(dev, "hpre ecc 1bit sram num=0x%x\n",
					 err_val);
			}
			if (HPRE_HAC_INT_ECC2 & err_sts) {
				err_val = readl(hisi_hpre->qm.io_base +
				HPRE_HAC_ECC2_CNT);
				dev_warn(dev, "hpre ecc 2bit sram num=0x%x\n",
					 err_val);
			}
		}
		err++;
	}
}

static pci_ers_result_t hisi_hpre_hw_error_handle(struct hisi_hpre *hisi_hpre)
{
	u32 err_sts;

	/* read err sts */
	err_sts = readl(hisi_hpre->qm.io_base + HPRE_HAC_INT_STATUS);
	if (err_sts) {
		hisi_hpre_log_hw_error(hisi_hpre, err_sts);

		/* clear error interrupts */
		writel(err_sts, hisi_hpre->qm.io_base + HPRE_HAC_SOURCE_INT);
		return PCI_ERS_RESULT_NEED_RESET;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static pci_ers_result_t hisi_hpre_process_hw_error(struct pci_dev *pdev)
{
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	pci_ers_result_t qm_ret, hpre_ret, ret;

	if (!hisi_hpre) {
		dev_err(dev,
		  "Can't recover hpre-error occurred during device init\n");
		return PCI_ERS_RESULT_NONE;
	}

	/* log qm error */
	qm_ret = hisi_qm_hw_error_handle(&hisi_hpre->qm);

	/* log hpre error */
	hpre_ret = hisi_hpre_hw_error_handle(hisi_hpre);
	ret = (qm_ret == PCI_ERS_RESULT_NEED_RESET ||
		hpre_ret == PCI_ERS_RESULT_NEED_RESET) ?
		PCI_ERS_RESULT_NEED_RESET : PCI_ERS_RESULT_RECOVERED;

	return ret;
}

static pci_ers_result_t hisi_hpre_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	dev_info(&pdev->dev, "PCI error detected, state(=%d)!!\n", state);
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	return hisi_hpre_process_hw_error(pdev);
}

static int hisi_hpre_controller_reset_prepare(struct hisi_hpre *hisi_hpre)
{
	struct hisi_qm *qm = &hisi_hpre->qm;
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = hisi_qm_stop(qm);
	if (ret) {
		dev_err(&pdev->dev, "Fails to stop QM!\n");
		return ret;
	}
	if (test_and_set_bit(QM_RESET, &qm->flags)) {
		dev_warn(&pdev->dev, "Failed to set reset flag!");
		return -EPERM;
	}

	/* If having VFs enable, let's disable them firstly */
	if (hisi_hpre->ctrl->num_vfs) {
		ret = hisi_hpre_sriov_disable(pdev);
		if (ret) {
			dev_err(&pdev->dev, "Fails to disable VFs!\n");
			return ret;
		}
	}

	return 0;
}

static void hisi_hpre_set_mse(struct hisi_hpre *hisi_hpre, bool set)
{
	struct pci_dev *pdev = hisi_hpre->qm.pdev;
	u16 sriov_ctrl;
	int pos;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_word(pdev, pos + PCI_SRIOV_CTRL, &sriov_ctrl);
	if (set)
		sriov_ctrl |= PCI_SRIOV_CTRL_MSE;
	else
		sriov_ctrl &= ~PCI_SRIOV_CTRL_MSE;
	pci_write_config_word(pdev, pos + PCI_SRIOV_CTRL, sriov_ctrl);
}

static int hisi_hpre_soft_reset(struct hisi_hpre *hisi_hpre)
{
	struct hisi_qm *qm = &hisi_hpre->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;
	u32 val;

	/* Set VF MSE bit */
	hisi_hpre_set_mse(hisi_hpre, 1);

	/* OOO register set and check */
	writel(MASTER_GLOBAL_CTRL_SHUTDOWN,
	hisi_hpre->qm.io_base + HPRE_MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(hisi_hpre->qm.io_base +
				HPRE_MASTER_TRANS_RETURN, val,
				(val == MASTER_TRANS_RETURN_RW), 10,
				1000);
	if (ret) {
		dev_emerg(dev, "Bus lock! Please reset system.\n");
		return ret;
	}

	/* The reset related sub-control registers are not in PCI BAR */
	if (ACPI_HANDLE(dev)) {
		acpi_status s;

		s = acpi_evaluate_object(ACPI_HANDLE(dev), "_RST", NULL, NULL);
		if (ACPI_FAILURE(s)) {
			dev_err(dev, "Controller reset fails\n");
			return -EIO;
		}
	} else {
		dev_err(dev, "No reset method!\n");
		return -EINVAL;
	}

	return 0;
}

static int hisi_hpre_controller_reset_done(struct hisi_hpre *hisi_hpre)
{
	struct hisi_qm *qm = &hisi_hpre->qm;
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qp *qp;
	int i, ret;

	hisi_qm_clear_queues(qm);
	hisi_hpre_set_user_domain_and_cache(hisi_hpre);
	ret = hisi_qm_start(qm);
	if (ret) {
		dev_err(&pdev->dev, "Failed to start QM!\n");
		return -EPERM;
	}
	for (i = 0; i < qm->qp_num; i++) {
		qp = qm->qp_array[i];
		if (qp) {
			ret = hisi_qm_start_qp(qp, 0);
			if (ret < 0) {
				dev_err(&pdev->dev, "Start qp%d failed\n", i);
				return -EPERM;
			}
		}
	}
	ret = hisi_hpre_sriov_enable(pdev, pci_num_vf(pdev));
	if (ret) {
		dev_err(&pdev->dev, "Can't enable VFs!\n");
		return ret;
	}

	/* Clear VF MSE bit */
	hisi_hpre_set_mse(hisi_hpre, 0);

	return 0;
}

static int hisi_hpre_controller_reset(struct hisi_hpre *hisi_hpre)
{
	struct device *dev = &hisi_hpre->qm.pdev->dev;
	int ret;

	dev_info(dev, "Controller resetting...\n");
	ret = hisi_hpre_controller_reset_prepare(hisi_hpre);
	if (ret)
		return ret;
	ret = hisi_hpre_soft_reset(hisi_hpre);
	if (ret) {
		dev_err(dev, "Controller reset failed (%d)\n", ret);
		return ret;
	}

	ret = hisi_hpre_controller_reset_done(hisi_hpre);
	if (ret)
		return ret;
	dev_info(dev, "Controller reset complete\n");
	clear_bit(QM_RESET, &hisi_hpre->qm.flags);

	return 0;
}

static pci_ers_result_t hisi_hpre_slot_reset(struct pci_dev *pdev)
{
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);
	int ret;

	dev_info(&pdev->dev, "Requesting reset due to PCI error\n");
	pci_cleanup_aer_uncorrect_error_status(pdev);

	/* reset hpre controller */
	ret = hisi_hpre_controller_reset(hisi_hpre);
	if (ret) {
		dev_warn(&pdev->dev, "hisi_hpre controller reset failed (%d)\n",
			ret);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static void hisi_hpre_reset_prepare(struct pci_dev *pdev)
{
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_hpre->qm;
	struct device *dev = &pdev->dev;
	int ret;

	ret = hisi_qm_stop(qm);
	if (ret) {
		dev_err(&pdev->dev, "Fails to stop QM!\n");
		return;
	}
	if (test_and_set_bit(QM_RESET, &qm->flags)) {
		dev_warn(dev, "Failed to set reset flag!");
		return;
	}

	/* If having VFs in PF, disable VFs before PF FLR */
	if (pdev->is_physfn && hisi_hpre->ctrl->num_vfs) {
		ret = hisi_hpre_sriov_disable(pdev);
		if (ret) {
			dev_err(dev, "Fails to disable VFs\n");
			return;
		}
	}
	dev_info(dev, "FLR resetting...\n");
}

static void hisi_hpre_reset_done(struct pci_dev *pdev)
{
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_hpre->qm;
	struct device *dev = &pdev->dev;
	struct hisi_qp *qp;
	int i, ret;

	if (pdev->is_physfn) {
		hisi_qm_clear_queues(qm);
		hisi_hpre_set_user_domain_and_cache(hisi_hpre);
		ret = hisi_qm_start(qm);
		if (ret) {
			dev_err(dev, "Failed to start QM!\n");
			return;
		}
		for (i = 0; i < qm->qp_num; i++) {
			qp = qm->qp_array[i];
			if (qp) {
				ret = hisi_qm_start_qp(qp, 0);
				if (ret < 0) {
					dev_err(dev, "Start qp%d failed\n", i);
					return;
				}
			}
		}
		ret = hisi_hpre_sriov_enable(pdev, pci_num_vf(pdev));
		if (ret) {
			dev_err(dev, "Can't enable VFs!\n");
			return;
		}
		dev_info(dev, "FLR reset complete\n");
	}
}

static void hisi_hpre_remove(struct pci_dev *pdev)
{
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_hpre->qm;

	hisi_hpre_remove_from_list(hisi_hpre);
	if (qm->fun_type == QM_HW_PF && hisi_hpre->ctrl->num_vfs != 0)
		hisi_hpre_sriov_disable(pdev);

	hisi_qm_stop(qm);

	/* if (qm->fun_type == QM_HW_PF)
	 * hpre_hw_error_set_state(hisi_hpre, false);
	 */
	hisi_qm_uninit(qm);
}

static const struct pci_error_handlers hisi_hpre_err_handler = {
	.error_detected		= hisi_hpre_error_detected,
	.slot_reset		= hisi_hpre_slot_reset,
	.reset_prepare		= hisi_hpre_reset_prepare,
	.reset_done		= hisi_hpre_reset_done,
};

static struct pci_driver hisi_hpre_pci_driver = {
	.name			= hpre_name,
	.id_table		= hisi_hpre_dev_ids,
	.probe			= hisi_hpre_probe,
	.remove			= hisi_hpre_remove,
	.sriov_configure	= hisi_hpre_sriov_configure,
	.err_handler		= &hisi_hpre_err_handler,
};

static int __init hisi_hpre_init(void)
{
	int ret;

	ret = pci_register_driver(&hisi_hpre_pci_driver);
	if (ret < 0) {
		pr_err("hpre: can't register hisi hpre driver.\n");
		return ret;
	}
	if (uacce_mode == UACCE_MODE_UACCE)
		return 0;

	ret = hpre_algs_register();
	if (ret < 0) {
		pr_err("hpre: can't register hisi hpre to crypto.\n");
		pci_unregister_driver(&hisi_hpre_pci_driver);
		return ret;
	}

	return 0;
}

static void __exit hisi_hpre_exit(void)
{
	if (uacce_mode != UACCE_MODE_UACCE)
		hpre_algs_unregister();
	pci_unregister_driver(&hisi_hpre_pci_driver);
}

module_init(hisi_hpre_init);
module_exit(hisi_hpre_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zaibo Xu <xuzaibo@huawei.com>");
MODULE_DESCRIPTION("Driver for HiSilicon HPRE accelerator");
MODULE_DEVICE_TABLE(pci, hisi_hpre_dev_ids);
