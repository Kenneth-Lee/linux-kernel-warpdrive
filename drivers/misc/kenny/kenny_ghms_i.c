/* SPDX-License-Identifier: GPL-2.0-or-later */
/**
 * This module is used to test the framework of WarpDrive.
 *
 * It support a simular device as dummy_wd_dev in qemu and do almost the same.
 * But it is a "real" hardware to the OS, so we can test the iommu feature
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

#define KENNY_GHMS "kenny_ghms"

struct hw_state {
	struct device *dev;
	void *io_va;
	dma_addr_t dma;
	int *sm_va;
	struct timer_list timer;
	int private;
};

static void mem_update_timer(struct timer_list *timer)
{
	struct hw_state *hw = container_of(timer, struct hw_state, timer);
	*hw->sm_va = jiffies;
	mod_timer(&hw->timer, jiffies+5000);
	dev_info(hw->dev, "timer on jiffies 0x%lx\n", jiffies);
}

static int kenny_ghms_probe(struct platform_device *pdev) {
	struct device *dev = &pdev->dev;
	struct hw_state *hw;
	struct resource *res;

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "cannot find io space!\n");
		return -ENODEV;
	}
	hw->io_va = devm_ioremap_resource(dev, res);
	if (IS_ERR(hw->io_va))
		return PTR_ERR(hw->io_va);

	hw->sm_va = dmam_alloc_coherent(dev, PAGE_SIZE, &hw->dma, GFP_KERNEL);
	if (!hw->sm_va)
		return -ENOMEM;

	hw->dev = dev;
	timer_setup(&hw->timer, mem_update_timer, 0);
	mod_timer(&hw->timer, jiffies+100);
	writeq(hw->dma, hw->io_va); //set share physical address
	dev_info(dev, "set dma(%llx) to io 0\n", hw->dma);

	platform_set_drvdata(pdev, hw);

	dev_info(dev,
		 "init success with iobase=0x%llx(%llx, %llx)",
		 (unsigned long long)hw->io_va,
		 res->start, res->end);

	return 0;
}

static int kenny_ghms_remove(struct platform_device *pdev)
{
	struct hw_state *hw = platform_get_drvdata(pdev);
	unsigned long flags;
	local_irq_save(flags);
	del_timer(&hw->timer);
	local_irq_restore(flags);
	return 0;
}

static const struct of_device_id kenny_ghms_of_match[] = {
	{.compatible = "kenny,ghms",},
	{},
};

static struct platform_driver kenny_ghms_pdrv = {
	.probe		= kenny_ghms_probe,
	.remove		= kenny_ghms_remove,
	.driver		= {
		.name		= KENNY_GHMS,
		.of_match_table = kenny_ghms_of_match,
	},
};

module_platform_driver(kenny_ghms_pdrv);

MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
MODULE_LICENSE("GPL");
