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
#define HPRE_QM_ABNML_INT_MASK		0x100004
#define HPRE_CTRL_CNT_CLR_CE_BIT	BIT(0)
#define HPRE_COMM_CNT_CLR_CE		0x0
#define HPRE_CTRL_CNT_CLR_CE		0x301000
#define HPRE_FSM_MAX_CNT		0x301008
#define HPRE_VFG_AXQOS			0x30100c
#define HPRE_VFG_AXCACHE		0x301010
#define HPRE_RDCHN_INI_CFG		0x301014
#define HPRE_BD_ENDIAN			0x301020
#define HPRE_ECC_BYPASS			0x301024
#define HPRE_POISON_BYPASS		0x30102c
#define HPRE_BD_ARUSR_CFG		0x301030
#define HPRE_BD_AWUSR_CFG		0x301034
#define HPRE_TYPES_ENB			0x301038
#define HPRE_DATA_RUSER_CFG		0x30103c
#define HPRE_DATA_WUSER_CFG		0x301040
#define HPRE_INT_MASK			0x301400
#define HPRE_CORE_INT_ENABLE		0
#define HPRE_CORE_INT_DISABLE		0x003fffff
#define HPRE_RAS_ECC_1BIT_TH		0x30140c
#define HPRE_RDCHN_INI_ST		0x301a00
#define HPRE_CLUSTER_BASE		0x302000
#define HPRE_CORE_ENB			0x302004
#define HPRE_CORE_INI_CFG		0x302020
#define HPRE_CORE_INI_STATUS		0x302080
#define HPRE_HAC_ECC1_CNT		0x301a04
#define HPRE_HAC_ECC2_CNT		0x301a08
#define HPRE_HAC_INT_ECC1		BIT(0)
#define HPRE_HAC_INT_ECC2		BIT(1)
#define HPRE_HAC_INT_STATUS		0x301800
#define HPRE_HAC_SOURCE_INT		0x301600
#define MASTER_GLOBAL_CTRL_SHUTDOWN	1
#define MASTER_TRANS_RETURN_RW		3
#define HPRE_MASTER_TRANS_RETURN	0x301500
#define HPRE_MASTER_GLOBAL_CTRL		0x300000
#define HPRE_CLUSTER_ADDR_INTRVL	0x1000
#define HPRE_CLUSTER_INQURY		0x100
#define HPRE_CLUSTER_INQURY_RSLT	0x104

enum {
	HPRE_CORE0,
	HPRE_CORE1,
	HPRE_CORE2,
	HPRE_CORE3,
	HPRE_CLUSTER_CORES,
};

enum {
	HPRE_CLUSTER0,
	HPRE_CLUSTER1,
	HPRE_CLUSTER2,
	HPRE_CLUSTER3,
	HPRE_CLUSTERS_NUM,
};

static LIST_HEAD(hpre_list);
static DEFINE_MUTEX(hpre_list_lock);
static const char hpre_name[] = "hisi_hpre";
static struct dentry *hpre_debugfs_root;
static const struct pci_device_id hpre_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa258) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa259) },
	{ 0, }
};
struct hpre_hw_error {
	u32 int_msk;
	const char *msg;
};

static const struct hpre_hw_error hpre_hw_error[] = {
	{ .int_msk = BIT(0), .msg = "hpre_ecc_1bitt_err" },
	{ .int_msk = BIT(1), .msg = "hpre_ecc_2bit_err" },
	{ .int_msk = BIT(2), .msg = "hpre_data_wr_err" },
	{ .int_msk = BIT(3), .msg = "hpre_data_rd_err" },
	{ .int_msk = BIT(4), .msg = "hpre_bd_rd_err" },
	{ .int_msk = BIT(5), .msg = "hpre_ooo_2bit_ecc_err" },
	{ .int_msk = BIT(6), .msg = "hpre_cltr1_htbt_tm_out_err" },
	{ .int_msk = BIT(7), .msg = "hpre_cltr2_htbt_tm_out_err" },
	{ .int_msk = BIT(8), .msg = "hpre_cltr3_htbt_tm_out_err" },
	{ .int_msk = BIT(9), .msg = "hpre_cltr4_htbt_tm_out_err" },
	{ .int_msk = GENMASK(10, 15), .msg = "hpre_ooo_rdrsp_err" },
	{ .int_msk = GENMASK(16, 21), .msg = "hpre_ooo_wrrsp_err" },
	{ /* sentinel */ }
};

enum ctrl_dbgfs_file {
	HPRE_CURRENT_QM,
	HPRE_CLEAR_ENABLE,
	HPRE_CLUSTER_CTRL,
	HPRE_DEBUG_FILE_NUM,
};

static const char * const ctrl_debug_file_name[] = {
	[HPRE_CURRENT_QM]   = "current_qm",
	[HPRE_CLEAR_ENABLE] = "rdclr_en",
	[HPRE_CLUSTER_CTRL] = "cluster_ctrl",
};

struct hpre_debugfs_file {
	int index;
	enum ctrl_dbgfs_file type;
	spinlock_t lock;
	struct hpre_ctrl *ctrl;
};

#define HPRE_DEBUGFS_FILE_NUM	(HPRE_DEBUG_FILE_NUM + HPRE_CLUSTERS_NUM - 1)

/*
 * One HPRE controller has one PF and multiple VFs, some global configurations
 * which PF has need this structure.
 *
 * Just relevant for PF.
 */
struct hpre_ctrl {
	u32 ctrl_q_num;
	u32 num_vfs;
	struct hpre *hpre;
	struct dentry *debug_root;
	struct hpre_debugfs_file files[HPRE_DEBUGFS_FILE_NUM];
};

static const u64 hpre_cluster_offsets[] = {
	[HPRE_CLUSTER0] =
		HPRE_CLUSTER_BASE + HPRE_CLUSTER0 * HPRE_CLUSTER_ADDR_INTRVL,
	[HPRE_CLUSTER1] =
		HPRE_CLUSTER_BASE + HPRE_CLUSTER1 * HPRE_CLUSTER_ADDR_INTRVL,
	[HPRE_CLUSTER2] =
		HPRE_CLUSTER_BASE + HPRE_CLUSTER2 * HPRE_CLUSTER_ADDR_INTRVL,
	[HPRE_CLUSTER3] =
		HPRE_CLUSTER_BASE + HPRE_CLUSTER3 * HPRE_CLUSTER_ADDR_INTRVL,
};

static struct debugfs_reg32 hpre_cluster_dfx_regs[] = {
	{"CORES_EN_STATUS          ",  0x04ull},
	{"CORES_INI_CFG              ",  0x20ull},
	{"CORES_INI_STATUS         ",  0x80ull},
	{"CORES_HTBT_WARN         ",  0x8cull},
	{"CORES_IS_SCHD               ",  0x90ull},
};

static struct debugfs_reg32 hpre_com_dfx_regs[] = {
	{"READ_CLR_EN          ",  0x0ull},
	{"AXQOS                      ",  0x0cull},
	{"AWUSR_CFG              ",  0x18ull},
	{"BD_ENDIAN               ",  0x20ull},
	{"ECC_CHCK_CTRL       ",  0x24ull},
	{"RAS_INT_WIDTH       ",  0x28ull},
	{"POISON_BYPASS       ",  0x2cull},
	{"BD_ARUSER               ",  0x30ull},
	{"BD_AWUSER               ",  0x34ull},
	{"DATA_ARUSER            ",  0x3cull},
	{"DATA_AWUSER           ",  0x40ull},
	{"INT_STATUS               ",  0x800ull},
};

static int pf_q_num_set(const char *val, const struct kernel_param *kp)
{
	struct pci_dev *pdev;
	u32 n, q_num;
	u8 rev_id;
	int ret;

	if (!val)
		return -EINVAL;
	pdev = pci_get_device(PCI_VENDOR_ID_HUAWEI, 0xa258, NULL);
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

static int uacce_mode = UACCE_MODE_NOUACCE;
module_param(uacce_mode, int, 0444);
static inline void hpre_add_to_list(struct hpre *hpre)
{
	mutex_lock(&hpre_list_lock);
	list_add_tail(&hpre->list, &hpre_list);
	mutex_unlock(&hpre_list_lock);
}

static inline void hpre_remove_from_list(struct hpre *hpre)
{
	mutex_lock(&hpre_list_lock);
	list_del(&hpre->list);
	mutex_unlock(&hpre_list_lock);
}

struct hpre *find_hpre_device(int node)
{
	struct hpre *hpre, *ret = NULL;
	struct device *dev;
	int min_distance = 100;
	int dev_node = 0;

	mutex_lock(&hpre_list_lock);
	list_for_each_entry(hpre, &hpre_list, list) {
		dev = &hpre->qm.pdev->dev;
#ifdef CONFIG_NUMA
		dev_node = dev->numa_node;
		if (dev_node < 0)
			dev_node = 0;
#endif
		if (node_distance(dev_node, node) < min_distance) {
			ret = hpre;
			min_distance = node_distance(dev_node, node);
		}
	}
	mutex_unlock(&hpre_list_lock);

	return ret;
}

static int hpre_set_user_domain_and_cache(struct hpre *hpre)
{
	int ret, i;
	u32 val;
	unsigned long offset;
	struct hisi_qm *qm = &hpre->qm;

#define HPRE_ADDR(offset) (qm->io_base + (offset))
	writel(0xfffffffe, HPRE_ADDR(QM_ARUSER_M_CFG_ENABLE));
	writel(0xfffffffe, HPRE_ADDR(QM_AWUSER_M_CFG_ENABLE));
	writel_relaxed(0xffff, HPRE_ADDR(QM_AXI_M_CFG));

	/* HPRE need more time, we close this interupt */
	val = readl_relaxed(HPRE_ADDR(HPRE_QM_ABNML_INT_MASK));
	val |= (1 << 6);
	writel_relaxed(val, HPRE_ADDR(HPRE_QM_ABNML_INT_MASK));

	writel(0x1, HPRE_ADDR(HPRE_TYPES_ENB));
	writel(0xff, HPRE_ADDR(HPRE_VFG_AXCACHE));
	writel(0x0, HPRE_ADDR(HPRE_BD_ENDIAN));
	writel(0x0, HPRE_ADDR(HPRE_INT_MASK));
	writel(0x0, HPRE_ADDR(HPRE_RAS_ECC_1BIT_TH));
	writel(0x0, HPRE_ADDR(HPRE_POISON_BYPASS));
	writel(0x0, HPRE_ADDR(HPRE_COMM_CNT_CLR_CE));
	writel(0x0, HPRE_ADDR(HPRE_ECC_BYPASS));

	/* Enable data buffer pasid */
	if (qm->use_sva) {
		val = readl_relaxed(HPRE_ADDR(HPRE_DATA_RUSER_CFG));
		val |= (1 << 9);
		writel_relaxed(val, HPRE_ADDR(HPRE_DATA_RUSER_CFG));
		val = readl_relaxed(HPRE_ADDR(HPRE_DATA_WUSER_CFG));
		val |= (1 << 9);
		writel_relaxed(val, HPRE_ADDR(HPRE_DATA_WUSER_CFG));
	}
	writel(0x3, HPRE_ADDR(HPRE_BD_ARUSR_CFG));
	writel(0x3, HPRE_ADDR(HPRE_BD_AWUSR_CFG));
	writel(0x1, HPRE_ADDR(HPRE_RDCHN_INI_CFG));
	ret = readl_relaxed_poll_timeout(HPRE_ADDR(HPRE_RDCHN_INI_ST),
					 val, val & BIT(0), 10, 1000);
	if (ret) {
		pr_err("\nHPRE:INI ST TIMEOUT");
		return -ETIMEDOUT;
	}
	for (i = 0; i < HPRE_CLUSTERS_NUM; i++) {
		offset = i * HPRE_CLUSTER_ADDR_INTRVL;

		/* clusters initiating */
		writel(0xf, HPRE_ADDR(offset + HPRE_CORE_ENB));
		writel(0x1, HPRE_ADDR(offset + HPRE_CORE_INI_CFG));
		ret = readl_relaxed_poll_timeout(HPRE_ADDR(offset +
						 HPRE_CORE_INI_STATUS),
						 val, ((val & 0xf) == 0xf),
						 10, 1000);
		if (ret) {
			pr_err("\nHPRE:CLUSTER %d INI ST STATUS timeout!", i);
			return -ETIMEDOUT;
		}
	}

	return ret;
}

static void hpre_hw_error_set_state(struct hpre *hpre, bool state)
{
	struct hisi_qm *qm = &hpre->qm;

	if (state)
		/* enable hpre hw error interrupts */
		writel(HPRE_CORE_INT_ENABLE, qm->io_base + HPRE_INT_MASK);
	else
		/* disable hpre hw error interrupts */
		writel(HPRE_CORE_INT_DISABLE, qm->io_base + HPRE_INT_MASK);
}

static inline struct hisi_qm *file_to_qm(struct hpre_debugfs_file *file)
{
	struct hpre *hpre = file->ctrl->hpre;

	return &hpre->qm;
}

static u32 current_qm_read(struct hpre_debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_DFX_MB_CNT_VF);
}

static int current_qm_write(struct hpre_debugfs_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	struct hpre_ctrl *ctrl = file->ctrl;

	if (val > ctrl->num_vfs)
		return -EINVAL;

	writel(val, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(val, qm->io_base + QM_DFX_DB_CNT_VF);

	return  0;
}

static u32 clear_enable_read(struct hpre_debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + HPRE_CTRL_CNT_CLR_CE) &
	       HPRE_CTRL_CNT_CLR_CE_BIT;
}

static int clear_enable_write(struct hpre_debugfs_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp;

	if (val != 1 && val != 0)
		return -EINVAL;

	tmp = (readl(qm->io_base + HPRE_CTRL_CNT_CLR_CE) &
	       ~HPRE_CTRL_CNT_CLR_CE_BIT) | val;
	writel(tmp, qm->io_base + HPRE_CTRL_CNT_CLR_CE);

	return  0;
}

static u32 cluster_inqry_read(struct hpre_debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);
	int cluster_index = file->index - HPRE_CLUSTER_CTRL;
	unsigned long offset = HPRE_CLUSTER_BASE +
		cluster_index * HPRE_CLUSTER_ADDR_INTRVL;

	return readl(qm->io_base + offset + HPRE_CLUSTER_INQURY_RSLT);
}

static int cluster_inqry_write(struct hpre_debugfs_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	int cluster_index = file->index - HPRE_CLUSTER_CTRL;
	unsigned long offset = HPRE_CLUSTER_BASE +
		cluster_index * HPRE_CLUSTER_ADDR_INTRVL;

	writel(val, qm->io_base + offset + HPRE_CLUSTER_INQURY);

	return  0;
}

static ssize_t ctrl_debug_read(struct file *filp, char __user *buf,
			     size_t count, loff_t *pos)
{
	struct hpre_debugfs_file *file = filp->private_data;
	char tbuf[20];
	u32 val;
	int ret;

	spin_lock_irq(&file->lock);
	switch (file->type) {
	case HPRE_CURRENT_QM:
		val = current_qm_read(file);
		break;
	case HPRE_CLEAR_ENABLE:
		val = clear_enable_read(file);
		break;
	case HPRE_CLUSTER_CTRL:
		val = cluster_inqry_read(file);
		break;
	default:
		spin_unlock_irq(&file->lock);
		return -EINVAL;
	}
	spin_unlock_irq(&file->lock);
	ret = sprintf(tbuf, "%u\n", val);
	return simple_read_from_buffer(buf, count, pos, tbuf, ret);
}

static ssize_t ctrl_debug_write(struct file *filp, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct hpre_debugfs_file *file = filp->private_data;
	char tbuf[20];
	unsigned long val;
	int len, ret;

	if (*pos != 0)
		return 0;

	if (count >= 20)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, 20 - 1, pos, buf, count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	spin_lock_irq(&file->lock);
	switch (file->type) {
	case HPRE_CURRENT_QM:
		ret = current_qm_write(file, val);
		if (ret)
			goto err_input;
		break;
	case HPRE_CLEAR_ENABLE:
		ret = clear_enable_write(file, val);
		if (ret)
			goto err_input;
		break;
	case HPRE_CLUSTER_CTRL:
		ret = cluster_inqry_write(file, val);
		if (ret)
			goto err_input;
		break;
	default:
		ret = -EINVAL;
		goto err_input;
	}
	spin_unlock_irq(&file->lock);

	return count;

err_input:
	spin_unlock_irq(&file->lock);
	return ret;
}

static const struct file_operations ctrl_debug_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = ctrl_debug_read,
	.write = ctrl_debug_write,
};

static int hpre_create_debugfs_file(struct hpre_ctrl *ctrl, struct dentry *dir,
				enum ctrl_dbgfs_file type, int indx)
{
	struct dentry *tmp, *file_dir;

	if (dir)
		file_dir = dir;
	else
		file_dir = ctrl->debug_root;

	spin_lock_init(&ctrl->files[indx].lock);
	ctrl->files[indx].ctrl = ctrl;
	ctrl->files[indx].type = type;
	ctrl->files[indx].index = indx;
	tmp = debugfs_create_file(ctrl_debug_file_name[type], 0600,
			file_dir, ctrl->files + indx,
			&ctrl_debug_fops);
	if (!tmp)
		return -ENOENT;

	return 0;
}

static int hpre_pf_comm_regs_debugfs_init(struct hpre_ctrl *ctrl)
{
	struct hpre *hpre = ctrl->hpre;
	struct hisi_qm *qm = &hpre->qm;
	struct device *dev = &qm->pdev->dev;
	struct debugfs_regset32 *regset;
	struct dentry *tmp;

	regset = devm_kzalloc(dev, sizeof(*regset), GFP_KERNEL);
	if (!regset)
		return -ENOENT;

	regset->regs = hpre_com_dfx_regs;
	regset->nregs = ARRAY_SIZE(hpre_com_dfx_regs);
	regset->base = qm->io_base + HPRE_CTRL_CNT_CLR_CE;

	tmp = debugfs_create_regset32("regs", 0444,  ctrl->debug_root, regset);
	if (!tmp)
		return -ENOENT;

	return 0;
}

static int hpre_cluster_debugfs_init(struct hpre_ctrl *ctrl)
{
	struct hpre *hpre = ctrl->hpre;
	struct hisi_qm *qm = &hpre->qm;
	struct device *dev = &qm->pdev->dev;
	struct debugfs_regset32 *regset;
	struct dentry *tmp_d, *tmp;
	char buf[20];
	int i, ret;

	for (i = 0; i < HPRE_CLUSTERS_NUM; i++) {
		sprintf(buf, "cluster%d", i);

		tmp_d = debugfs_create_dir(buf, ctrl->debug_root);
		if (!tmp_d)
			return -ENOENT;

		regset = devm_kzalloc(dev, sizeof(*regset), GFP_KERNEL);
		if (!regset)
			return -ENOENT;

		regset->regs = hpre_cluster_dfx_regs;
		regset->nregs = ARRAY_SIZE(hpre_cluster_dfx_regs);
		regset->base = qm->io_base + hpre_cluster_offsets[i];

		tmp = debugfs_create_regset32("regs", 0444, tmp_d, regset);
		if (!tmp)
			return -ENOENT;
		ret = hpre_create_debugfs_file(ctrl, tmp_d, HPRE_CLUSTER_CTRL,
					i + HPRE_CLUSTER_CTRL);
		if (ret)
			return ret;
	}

	return 0;
}

static int hpre_ctrl_debug_init(struct hpre_ctrl *ctrl)
{
	int ret;


	ret = hpre_create_debugfs_file(ctrl, NULL, HPRE_CURRENT_QM,
				HPRE_CURRENT_QM);
	if (ret)
		return ret;
	ret = hpre_create_debugfs_file(ctrl, NULL, HPRE_CLEAR_ENABLE,
				HPRE_CLEAR_ENABLE);
	if (ret)
		return ret;

	ret = hpre_pf_comm_regs_debugfs_init(ctrl);
	if (ret)
		return ret;
	return hpre_cluster_debugfs_init(ctrl);
}

static int hpre_debugfs_init(struct hpre *hpre)
{
	struct hisi_qm *qm = &hpre->qm;
	struct device *dev = &qm->pdev->dev;
	struct dentry *dir;
	int ret;

	dir = debugfs_create_dir(dev_name(dev), hpre_debugfs_root);
	if (!dir)
		return -ENOENT;

	qm->debug.debug_root = dir;
	ret = hisi_qm_debug_init(qm);
	if (ret)
		goto failed_to_create;

	if (qm->pdev->device == 0xa258) {
		hpre->ctrl->debug_root = dir;
		ret = hpre_ctrl_debug_init(hpre->ctrl);
		if (ret)
			goto failed_to_create;
	}
	return 0;

failed_to_create:
	debugfs_remove_recursive(qm->debug.debug_root);
	return ret;
}

static void hpre_debugfs_exit(struct hpre *hpre)
{
	struct hisi_qm *qm = &hpre->qm;

	debugfs_remove_recursive(qm->debug.debug_root);
}

static int hpre_pf_probe_init(struct hpre *hpre)
{
	struct hpre_ctrl *ctrl;
	struct hisi_qm *qm = &hpre->qm;
	u32 nfe_flag;

	ctrl = devm_kzalloc(&qm->pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	hpre->ctrl = ctrl;
	ctrl->hpre = hpre;

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

	hpre_set_user_domain_and_cache(hpre);

	nfe_flag = QM_BASE_NFE;
	hisi_qm_hw_error_init(qm, QM_BASE_CE, nfe_flag, 0,
			      QM_DB_RANDOM_INVALID);
	hpre_hw_error_set_state(hpre, true);

	return 0;
}

static int hpre_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hpre_ctrl *ctrl;
	struct hpre *hpre;
	struct hisi_qm *qm;
	enum qm_hw_ver rev_id;
	int ret;

	rev_id = hisi_qm_get_hw_version(pdev);
	if (rev_id < 0)
		return -ENODEV;
	hpre = devm_kzalloc(&pdev->dev, sizeof(*hpre), GFP_KERNEL);
	if (!hpre)
		return -ENOMEM;
	pci_set_drvdata(pdev, hpre);
	qm = &hpre->qm;
	qm->pdev = pdev;
	qm->ver = rev_id;
	ctrl = devm_kzalloc(&pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;
	hpre->ctrl = ctrl;
	qm->sqe_size = HPRE_SQE_SIZE;
	qm->dev_name = hpre_name;
	qm->fun_type = (pdev->device == 0xa258) ? QM_HW_PF : QM_HW_VF;
	qm->algs = "rsa\ndh\n";
	switch (uacce_mode) {
	case UACCE_MODE_NOUACCE:
		qm->use_dma_api = true;
		qm->use_uacce = false;
		break;
	case UACCE_MODE_UACCE:
#ifdef CONFIG_IOMMU_SVA
		qm->use_dma_api = true;
		qm->use_sva = true;
#else
		qm->use_dma_api = false;
#endif
		qm->use_uacce = true;
		break;
	case UACCE_MODE_NOIOMMU:
		qm->use_dma_api = true;
		qm->use_uacce = true;
		break;
	default:
		return -EINVAL;
	}
	ret = hisi_qm_init(qm);
	if (ret)
		return ret;

	if (pdev->is_physfn) {
		ret = hpre_pf_probe_init(hpre);
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
	ret = hpre_debugfs_init(hpre);
	if (ret)
		dev_warn(&pdev->dev, "init debugfs fail!\n");

	hpre_add_to_list(hpre);
	return 0;

err_with_qm_init:
	hisi_qm_uninit(qm);

	return ret;
}

static int hpre_vf_q_assign(struct hpre *hpre, int num_vfs)
{
	struct hpre_ctrl *ctrl = hpre->ctrl;
	struct hisi_qm *qm = &hpre->qm;
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

static int hpre_clear_vft_config(struct hpre *hpre)
{
	struct hpre_ctrl *ctrl = hpre->ctrl;
	struct hisi_qm *qm = &hpre->qm;
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

static int hpre_sriov_enable(struct pci_dev *pdev, int max_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct hpre *hpre = pci_get_drvdata(pdev);
	int pre_existing_vfs, num_vfs, ret;

	pre_existing_vfs = pci_num_vf(pdev);
	if (pre_existing_vfs) {
		dev_err(&pdev->dev,
			"Can't enable VF. Please disable pre-enabled VFs!\n");
		return 0;
	}
	num_vfs = min_t(int, max_vfs, HPRE_VF_NUM);
	ret = hpre_vf_q_assign(hpre, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't assign queues for VF!\n");
		return ret;
	}
	hpre->ctrl->num_vfs = num_vfs;
	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't enable VF!\n");
		hpre_clear_vft_config(hpre);
		return ret;
	}
	return num_vfs;
#else
	return 0;
#endif
}

static int hpre_sriov_disable(struct pci_dev *pdev)
{
	struct hpre *hpre = pci_get_drvdata(pdev);

	if (pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev,
		"Can't disable VFs while VFs are assigned!\n");

		return -EPERM;
	}

	/* remove in hpre_pci_driver will be called to free VF resources */
	pci_disable_sriov(pdev);
	return hpre_clear_vft_config(hpre);
}

static int hpre_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return hpre_sriov_disable(pdev);
	else
		return hpre_sriov_enable(pdev, num_vfs);
}

static void hpre_log_hw_error(struct hpre *hpre, u32 err_sts)
{
	const struct hpre_hw_error *err = hpre_hw_error;
	struct device *dev = &hpre->qm.pdev->dev;
	u32 err_val;

	while (err->msg) {
		if (err->int_msk & err_sts) {
			dev_warn(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);
			if (HPRE_HAC_INT_ECC1 & err_sts) {
				err_val = readl(hpre->qm.io_base +
						HPRE_HAC_ECC1_CNT);
				dev_warn(dev, "hpre ecc 1bit sram num=0x%x\n",
					 err_val);
			}
			if (HPRE_HAC_INT_ECC2 & err_sts) {
				err_val = readl(hpre->qm.io_base +
				HPRE_HAC_ECC2_CNT);
				dev_warn(dev, "hpre ecc 2bit sram num=0x%x\n",
					 err_val);
			}
		}
		err++;
	}
}

static pci_ers_result_t hpre_hw_error_handle(struct hpre *hpre)
{
	u32 err_sts;

	/* read err sts */
	err_sts = readl(hpre->qm.io_base + HPRE_HAC_INT_STATUS);
	if (err_sts) {
		hpre_log_hw_error(hpre, err_sts);

		/* clear error interrupts */
		writel(err_sts, hpre->qm.io_base + HPRE_HAC_SOURCE_INT);
		return PCI_ERS_RESULT_NEED_RESET;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static pci_ers_result_t hpre_process_hw_error(struct pci_dev *pdev)
{
	struct hpre *hpre = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	pci_ers_result_t qm_ret, hpre_ret, ret;

	if (!hpre) {
		dev_err(dev, "Can't recover hpre-error at dev init\n");
		return PCI_ERS_RESULT_NONE;
	}

	/* log qm error */
	qm_ret = hisi_qm_hw_error_handle(&hpre->qm);

	/* log hpre error */
	hpre_ret = hpre_hw_error_handle(hpre);
	ret = (qm_ret == PCI_ERS_RESULT_NEED_RESET ||
		hpre_ret == PCI_ERS_RESULT_NEED_RESET) ?
		PCI_ERS_RESULT_NEED_RESET : PCI_ERS_RESULT_RECOVERED;

	return ret;
}

static pci_ers_result_t hpre_error_detected(struct pci_dev *pdev,
					    pci_channel_state_t state)
{
	dev_info(&pdev->dev, "PCI error detected, state(=%d)!!\n", state);
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	return hpre_process_hw_error(pdev);
}

static int hpre_controller_reset_prepare(struct hpre *hpre)
{
	struct hisi_qm *qm = &hpre->qm;
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
	if (hpre->ctrl->num_vfs) {
		ret = hpre_sriov_disable(pdev);
		if (ret) {
			dev_err(&pdev->dev, "Fails to disable VFs!\n");
			return ret;
		}
	}

	return 0;
}

static void hpre_set_mse(struct hpre *hpre, bool set)
{
	struct pci_dev *pdev = hpre->qm.pdev;
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

static int hpre_soft_reset(struct hpre *hpre)
{
	struct hisi_qm *qm = &hpre->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;
	u32 val;

	/* Set VF MSE bit */
	hpre_set_mse(hpre, 1);

	/* OOO register set and check */
	writel(MASTER_GLOBAL_CTRL_SHUTDOWN,
	hpre->qm.io_base + HPRE_MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(hpre->qm.io_base +
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

static int hpre_controller_reset_done(struct hpre *hpre)
{
	struct hisi_qm *qm = &hpre->qm;
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qp *qp;
	int i, ret;

	hisi_qm_clear_queues(qm);
	hpre_set_user_domain_and_cache(hpre);
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
	ret = hpre_sriov_enable(pdev, pci_num_vf(pdev));
	if (ret) {
		dev_err(&pdev->dev, "Can't enable VFs!\n");
		return ret;
	}

	/* Clear VF MSE bit */
	hpre_set_mse(hpre, 0);

	return 0;
}

static int hpre_controller_reset(struct hpre *hpre)
{
	struct device *dev = &hpre->qm.pdev->dev;
	int ret;

	dev_info(dev, "Controller resetting...\n");
	ret = hpre_controller_reset_prepare(hpre);
	if (ret)
		return ret;
	ret = hpre_soft_reset(hpre);
	if (ret) {
		dev_err(dev, "Controller reset failed (%d)\n", ret);
		return ret;
	}

	ret = hpre_controller_reset_done(hpre);
	if (ret)
		return ret;
	dev_info(dev, "Controller reset complete\n");
	clear_bit(QM_RESET, &hpre->qm.flags);

	return 0;
}

static pci_ers_result_t hpre_slot_reset(struct pci_dev *pdev)
{
	struct hpre *hpre = pci_get_drvdata(pdev);
	int ret;

	dev_info(&pdev->dev, "Requesting reset due to PCI error\n");
	pci_cleanup_aer_uncorrect_error_status(pdev);

	/* reset hpre controller */
	ret = hpre_controller_reset(hpre);
	if (ret) {
		dev_warn(&pdev->dev, "hpre controller reset failed (%d)\n",
			ret);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static void hpre_reset_prepare(struct pci_dev *pdev)
{
	struct hpre *hpre = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hpre->qm;
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
	if (pdev->is_physfn && hpre->ctrl->num_vfs) {
		ret = hpre_sriov_disable(pdev);
		if (ret) {
			dev_err(dev, "Fails to disable VFs\n");
			return;
		}
	}
	dev_info(dev, "FLR resetting...\n");
}

static void hpre_reset_done(struct pci_dev *pdev)
{
	struct hpre *hpre = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hpre->qm;
	struct device *dev = &pdev->dev;
	struct hisi_qp *qp;
	int i, ret;

	if (pdev->is_physfn) {
		hisi_qm_clear_queues(qm);
		hpre_set_user_domain_and_cache(hpre);
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
		ret = hpre_sriov_enable(pdev, pci_num_vf(pdev));
		if (ret) {
			dev_err(dev, "Can't enable VFs!\n");
			return;
		}
		dev_info(dev, "FLR reset complete\n");
	}
}

static void hpre_remove(struct pci_dev *pdev)
{
	struct hpre *hpre = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hpre->qm;

	hpre_remove_from_list(hpre);
	if (qm->fun_type == QM_HW_PF && hpre->ctrl->num_vfs != 0)
		hpre_sriov_disable(pdev);
	hpre_debugfs_exit(hpre);
	hisi_qm_stop(qm);
	if (qm->fun_type == QM_HW_PF)
		hpre_hw_error_set_state(hpre, false);
	hisi_qm_uninit(qm);
}

static const struct pci_error_handlers hpre_err_handler = {
	.error_detected		= hpre_error_detected,
	.slot_reset		= hpre_slot_reset,
	.reset_prepare		= hpre_reset_prepare,
	.reset_done		= hpre_reset_done,
};

static struct pci_driver hpre_pci_driver = {
	.name			= hpre_name,
	.id_table		= hpre_dev_ids,
	.probe			= hpre_probe,
	.remove			= hpre_remove,
	.sriov_configure	= hpre_sriov_configure,
	.err_handler		= &hpre_err_handler,
};

static void hpre_register_debugfs(void)
{
	if (!debugfs_initialized())
		return;

	hpre_debugfs_root = debugfs_create_dir(hpre_name, NULL);
	if (IS_ERR_OR_NULL(hpre_debugfs_root))
		hpre_debugfs_root = NULL;
}

static void hpre_unregister_debugfs(void)
{
	debugfs_remove_recursive(hpre_debugfs_root);
}

static int __init hpre_init(void)
{
	int ret;

	hpre_register_debugfs();
	ret = pci_register_driver(&hpre_pci_driver);
	if (ret < 0) {
		pr_err("hpre: can't register hisi hpre driver.\n");
		goto fail_to_register_pci;
	}
#ifndef CONFIG_IOMMU_SVA
	if (uacce_mode == UACCE_MODE_UACCE)
		return 0;
#endif
	ret = hpre_algs_register();
	if (ret < 0) {
		pr_err("hpre: can't register hisi hpre to crypto.\n");
		goto fail_to_register_algs;
	}
	return 0;

fail_to_register_algs:
	pci_unregister_driver(&hpre_pci_driver);
fail_to_register_pci:
	hpre_unregister_debugfs();
	return ret;
}

static void __exit hpre_exit(void)
{
#ifndef CONFIG_IOMMU_SVA
	if (uacce_mode != UACCE_MODE_UACCE)
		hpre_algs_unregister();
#else
	hpre_algs_unregister();
#endif
	pci_unregister_driver(&hpre_pci_driver);
	hpre_unregister_debugfs();
}

module_init(hpre_init);
module_exit(hpre_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zaibo Xu <xuzaibo@huawei.com>");
MODULE_DESCRIPTION("Driver for HiSilicon HPRE accelerator");
MODULE_DEVICE_TABLE(pci, hpre_dev_ids);
