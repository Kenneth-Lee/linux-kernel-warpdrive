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

struct bbox_record_set {
	struct scatterlist sg[4];
	struct scatterlist *sgs[4];
	struct bbox_record rec[4];
};

static struct bbox_record_set *bbox_create_record(void)
{
	struct bbox_record_set *rs = kmalloc(sizeof(*rs), GFP_ATOMIC);
	int i;
	const int d0=0x11111111;
	static int d=d0;

	if (rs) {
		for(i=0; i<4; i++) {
			rs->rec[i].data1 = d;
			d+=d0;
			rs->rec[i].data2 = d;
			d+=d0;
		}
		for(i=0; i<4; i++) {
			rs->sgs[i] = &rs->sg[i];
			sg_init_one(rs->sgs[i], &rs->rec[i], sizeof(rs->rec[0]));
		}
	}

	return rs;
}

static void kenny_bbox_timer(struct timer_list *timer)
{
	struct hw_state *hw = container_of(timer, struct hw_state, timer);
	struct bbox_record_set *brs = bbox_create_record();
	unsigned long flags;

	mod_timer(&hw->timer, jiffies+5000);
	if (!brs) {
		dev_err(hw->dev, "no memory\n");
		return;
	}

	spin_lock_irqsave(&hw->lock, flags);
	if(hw->count < 10) {
		if (brs) {
			virtqueue_add_sgs(hw->vq, brs->sgs, 3, 1, brs, GFP_ATOMIC);
			hw->count++;
			if (unlikely(!virtqueue_kick(hw->vq)))
				dev_err(hw->dev, "kick rec fail\n");
			else
				dev_info(hw->dev, "kick rec(%d) to other side: %llx\n", hw->count, (uint64_t)brs);
		} else {
			dev_err(hw->dev, "allocate rec fail %d\n", hw->count);
		}
	}
	spin_unlock_irqrestore(&hw->lock, flags);
}

static void req_done(struct virtqueue *vq)
{
	struct hw_state *hw = vq->vdev->priv;
	struct bbox_record_set *brs;
	int len;
	unsigned long flags;

	dev_info(hw->dev, "data come back (%d)\n", hw->count);

	spin_lock_irqsave(&hw->lock, flags);
	while ((brs = virtqueue_get_buf(hw->vq, &len)) != NULL) {
		dev_info(hw->dev, "get rec %llx(%d): %llx, %llx\n", (uint64_t)brs, len, 
			brs->rec[3].data1, brs->rec[3].data2);

		if (len) {
			hw->count--;
		}

		kfree(brs);
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
