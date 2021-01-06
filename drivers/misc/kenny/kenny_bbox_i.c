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

struct bbox_record {
	uint64_t data1;
	uint64_t data2;
};

struct hw_state {
	struct device *dev;
	struct timer_list timer;
	spinlock_t lock;
	struct virtqueue *vq;
	uint64_t conf;
	int count;
};

struct bbox_conf {
	uint64_t flags;
};

static void kenny_bbox_timer(struct timer_list *timer)
{
	struct hw_state *hw = container_of(timer, struct hw_state, timer);
	unsigned long flags;
	struct bbox_record *rec;
	struct scatterlist top_sg, bottom_sg;
	struct scatterlist *sgs[2] = { &top_sg, &bottom_sg };

	mod_timer(&hw->timer, jiffies+5000);

	spin_lock_irqsave(&hw->lock, flags);
	if(hw->count < 10) {
		rec = kmalloc(2*sizeof(*rec), GFP_ATOMIC);
		if (rec) {
			sg_init_one(&top_sg, &rec[0], sizeof(*rec));
			sg_init_one(&bottom_sg, &rec[1], sizeof(*rec));
			virtqueue_add_sgs(hw->vq, sgs, 1, 1, rec, GFP_ATOMIC);
			hw->count++;
			if (unlikely(!virtqueue_kick(hw->vq)))
				dev_err(hw->dev, "kick rec fail\n");
			else
				dev_info(hw->dev, "kick rec(%d) to other side\n", hw->count);
		} else {
			dev_err(hw->dev, "allocate rec fail %d\n", hw->count);
		}
	}
	spin_unlock_irqrestore(&hw->lock, flags);
}

static void req_done(struct virtqueue *vq)
{
	struct hw_state *hw = vq->vdev->priv;
	struct bbox_record *rec;
	unsigned int len;
	unsigned long flags;

	dev_info(hw->dev, "data come back (%d)\n", hw->count);

	spin_lock_irqsave(&hw->lock, flags);
	while ((rec = virtqueue_get_buf(hw->vq, &len)) != NULL) {
		dev_info(hw->dev, "get rec %p\n", rec);

		if (len) {
			hw->count--;
			kfree(rec);
		}
	}
	spin_unlock_irqrestore(&hw->lock, flags);

	dev_info(hw->dev, "req done\n");
}

static int kenny_bbox_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct hw_state *hw;

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;

	virtio_cread(vdev, struct bbox_conf, flags, &hw->conf);

	hw->vq = virtio_find_single_vq(vdev, req_done, "requests");
	if (IS_ERR(hw->vq)) {
		dev_info(hw->dev, "find queue fail\n");
		return PTR_ERR(hw->vq);
	}

	spin_lock_init(&hw->lock);

	timer_setup(&hw->timer, kenny_bbox_timer, 0);
	vdev->priv = hw;
	hw->dev = &vdev->dev;

	dev_info(&vdev->dev, "%s: %llx\n", __FUNCTION__, hw->conf);
	virtio_device_ready(vdev);

	mod_timer(&hw->timer, jiffies+1000);

	return 0;
}

static void kenny_bbox_config_changed(struct virtio_device *vdev) {
	dev_info(&vdev->dev, "%s\n", __FUNCTION__);
}

static int kenny_bbox_validate(struct virtio_device *vdev) {
	dev_info(&vdev->dev, "%s\n", __FUNCTION__);
	return 0;
}

static void kenny_bbox_remove(struct virtio_device *vdev) {
	unsigned long flags;
	struct hw_state *hw = vdev->priv;

	local_irq_save(flags);
	del_timer(&hw->timer);
	local_irq_restore(flags);
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
