/* SPDX-License-Identifier: GPL-2.0-or-later */
/**
 */

#include <asm/page.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/pci.h>

#define KENNY_GHMS "kenny_ghms"

#define IO_OFFSET_SM_DMA 0
#define IO_OFFSET_IRQ_ACK 8

struct hw_state {
	struct device *dev;
	void *io_va;
	dma_addr_t dma;
	int *sm_va;
	struct timer_list timer;
	bool use_level_irq;
	int private;
};

static void mem_update_timer(struct timer_list *timer)
{
	struct hw_state *hw = container_of(timer, struct hw_state, timer);
	*hw->sm_va = jiffies;
	mod_timer(&hw->timer, jiffies+5000);
	//dev_info(hw->dev, "timer on jiffies 0x%lx\n", jiffies);
}

static irqreturn_t ghms_irq_handler(int irq, void *opaqu)
{
	struct hw_state *hw = (struct hw_state *)opaqu;

	dev_dbg(hw->dev, "ghms interrupt!\n");

	if(hw->use_level_irq) {
		writeq((u64)1, hw->io_va + IO_OFFSET_IRQ_ACK);
	}

	return IRQ_HANDLED;
}

static struct hw_state *kenny_ghms_init(struct device *dev,
				        const struct resource *res,
					unsigned int irq,
					bool use_level_irq)
{
	struct hw_state *hw;
	int ret;

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return ERR_PTR(-ENOMEM);

	hw->io_va = devm_ioremap_resource(dev, res);
	if (IS_ERR(hw->io_va))
		return hw->io_va;

	hw->sm_va = dmam_alloc_coherent(dev, PAGE_SIZE, &hw->dma, GFP_KERNEL);
	if (!hw->sm_va)
		return ERR_PTR(-ENOMEM);

	hw->dev = dev;
	timer_setup(&hw->timer, mem_update_timer, 0);
	mod_timer(&hw->timer, jiffies+100);
	writeq(hw->dma, hw->io_va + IO_OFFSET_SM_DMA);
	dev_info(dev, "set dma(%llx) to io 0\n", hw->dma);
	hw->use_level_irq = use_level_irq;

	ret = devm_request_irq(dev, irq, ghms_irq_handler, 0,
			       KENNY_GHMS, hw);
	if (ret)
		return ERR_PTR(ret);

	dev_info(dev,
		 "init success with iobase=0x%llx(%llx, %llx), irq=%d(%s)\n",
		 (unsigned long long)hw->io_va,
		 res->start, res->end, irq, use_level_irq?"level":"edge");

	return hw;
}

static void kenny_ghms_fini(struct device *dev, struct hw_state *hw)
{
	unsigned long flags;

	local_irq_save(flags);
	del_timer(&hw->timer);
	local_irq_restore(flags);
}

static int kenny_ghms_probe(struct platform_device *pdev) {
	struct device *dev = &pdev->dev;
	struct hw_state *hw;
	struct resource *res;
	int irq;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "cannot find io space!\n");
		return -ENODEV;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(dev, "cannot find irq!\n");
		return -ENODEV;
	}

	hw = kenny_ghms_init(dev, res, irq, false);
	if (IS_ERR(hw))
		return PTR_ERR(hw);

	platform_set_drvdata(pdev, hw);
	return 0;
}

static int kenny_ghms_remove(struct platform_device *pdev)
{
	kenny_ghms_fini(&pdev->dev, platform_get_drvdata(pdev));
	return 0;
}

static int kenny_ghms_pci_probe(struct pci_dev *pdev,
				const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct hw_state *hw;
	int vectors;
	unsigned int irq;

	if (pci_enable_device(pdev))
		return -EINVAL;

	if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32)))
		return -EINVAL;

	vectors = pci_alloc_irq_vectors(pdev, 1, 1,
		PCI_IRQ_LEGACY | PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (vectors < 0) {
		dev_err(&pdev->dev,
			"failed to allocate interrupt vector (%d)\n", vectors);
	}

	irq = pci_irq_vector(pdev, 0); //assume it won't fail

	hw = kenny_ghms_init(dev, &pdev->resource[0], irq, !pdev->msi_enabled);
	if (IS_ERR(hw)) {
		pci_free_irq_vectors(pdev);
		return PTR_ERR(hw);
	}

	pci_set_drvdata(pdev, hw);
	return 0;
}

static void kenny_ghms_pci_remove(struct pci_dev *pdev) {
	pci_free_irq_vectors(pdev);
}

static void kenny_ghms_pci_shutdown(struct pci_dev *pdev) {}

#define PCI_VENDOR_ID_QEMU 0x1234
static const struct pci_device_id kenny_ghms_pci_tbl[] = {
	{PCI_VDEVICE(QEMU, 0x3000), 0},
	{0, }
};
MODULE_DEVICE_TABLE(pci, kenny_ghms_pic_tbl);

static struct pci_driver kenny_ghms_pci_drv = {
	.name     = "kenny_ghms_pci",
	.id_table = kenny_ghms_pci_tbl,
	.probe    = kenny_ghms_pci_probe,
	.remove   = kenny_ghms_pci_remove,
	.shutdown = kenny_ghms_pci_shutdown,
};

static const struct of_device_id kenny_ghms_of_match[] = {
	{.compatible = "kenny,ghms",},
	{},
};

static struct platform_driver kenny_ghms_drv = {
	.probe		= kenny_ghms_probe,
	.remove		= kenny_ghms_remove,
	.driver		= {
		.name		= KENNY_GHMS,
		.of_match_table = kenny_ghms_of_match,
	},
};

static int __init ghms_init(void)
{
	int ret;

	ret = pci_register_driver(&kenny_ghms_pci_drv);
	if (ret)
		goto err;

	ret = platform_driver_register(&kenny_ghms_drv);
	if (ret)
		goto err_with_pci;
	
	return 0;

err_with_pci:
	pci_unregister_driver(&kenny_ghms_pci_drv);
err:
	return ret;
}

static void __exit ghms_exit(void)
{
	platform_driver_unregister(&kenny_ghms_drv);
	pci_unregister_driver(&kenny_ghms_pci_drv);
}

module_init(ghms_init);
module_exit(ghms_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kenny's Host Guest Memory Sharing Module");
MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
