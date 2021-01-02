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

#define KENNY_BBOX "kenny-bbox"
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

static irqreturn_t bbox_irq_handler(int irq, void *opaqu)
{
	struct hw_state *hw = (struct hw_state *)opaqu;

	dev_dbg(hw->dev, "bbox interrupt!\n");

	/*
	if(hw->use_level_irq) {
		writeq((u64)1, hw->io_va + IO_OFFSET_IRQ_ACK);
	}
	*/

	return IRQ_HANDLED;
}

static int kenny_bbox_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct hw_state *hw;
	int vectors;
	unsigned int irq;
	int ret;

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

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;

	hw->use_level_irq = true;
	hw->io_va = devm_ioremap_resource(dev, &pdev->resource[0]);
	if (IS_ERR(hw->io_va))
		return PTR_ERR(hw->io_va);

	hw->sm_va = dmam_alloc_coherent(dev, PAGE_SIZE, &hw->dma, GFP_KERNEL);
	if (!hw->sm_va)
		return -ENOMEM;

	hw->dev = dev;
	writeq(hw->dma, hw->io_va + IO_OFFSET_SM_DMA);
	dev_info(dev, "set dma(%llx) to io 0\n", hw->dma);

	ret = devm_request_irq(dev, irq, bbox_irq_handler, 0,
			       KENNY_BBOX, hw);
	if (ret)
		return ret;

	dev_info(dev,
		 "init success with iobase=0x%llx(%llx, %llx), irq=%d(%s)\n",
		 (unsigned long long)hw->io_va,
		 pdev->resource[0].start, pdev->resource[0].end,
		 irq, hw->use_level_irq?"level":"edge");

	pci_set_drvdata(pdev, hw);
	return 0;
}

static void kenny_bbox_remove(struct pci_dev *pdev) {
	pci_free_irq_vectors(pdev);
}

static void kenny_bbox_shutdown(struct pci_dev *pdev) {}

#define PCI_VENDOR_ID_QEMU 0x1234
static const struct pci_device_id kenny_bbox_tbl[] = {
	{PCI_VDEVICE(QEMU, 0x3001), 0},
	{0, }
};
MODULE_DEVICE_TABLE(pci, kenny_bbox_tbl);

static struct pci_driver kenny_bbox_drv = {
	.name     = KENNY_BBOX,
	.id_table = kenny_bbox_tbl,
	.probe    = kenny_bbox_probe,
	.remove   = kenny_bbox_remove,
	.shutdown = kenny_bbox_shutdown,
};

module_pci_driver(kenny_bbox_drv);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kenny's Black Box Driver Module");
MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
