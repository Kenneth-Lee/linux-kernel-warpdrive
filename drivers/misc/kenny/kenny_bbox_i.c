/* SPDX-License-Identifier: GPL-2.0-or-later */
/**
 */

#include <asm/page.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>

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

static int kenny_bbox_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct hw_state *hw;

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;

	virtio_device_ready(vdev);

	dev_info(&vdev->dev, "%s\n", __FUNCTION__);

	return 0;
}

static void kenny_bbox_config_changed(struct virtio_device *vdev) {
	dev_info(&vdev->dev, "%s\n", __FUNCTION__);
}

static int kenny_bbox_validate(struct virtio_device *vdev) {
	dev_info(&vdev->dev, "%s\n", __FUNCTION__);
	return 0;
}

static void kenny_bbox_remove(struct virtio_device *pdev) {
	//pci_free_irq_vectors(pdev);
}

static unsigned int features[] = {
	1,
};

static unsigned int features_legacy[] = {
	1,
	2,
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_KENNY, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver kenny_bbox_drv = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.feature_table_legacy = features_legacy,
	.feature_table_size_legacy = ARRAY_SIZE(features_legacy),
	.driver.name =	KBUILD_MODNAME, //KENNY_BBOX?
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.validate =	kenny_bbox_validate,
	.probe =	kenny_bbox_probe,
	.remove =	kenny_bbox_remove,
	.config_changed = kenny_bbox_config_changed,
};

module_virtio_driver(kenny_bbox_drv);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kenny's Black Box Driver Module");
MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
