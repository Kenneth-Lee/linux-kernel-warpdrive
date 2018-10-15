/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/module.h>
#include <linux/iommu.h>
#include <linux/slab.h>
#include <linux/uacce.h>

static int uacce_counter_fn(struct device *dev, void *arg)
{
	int *counter = arg;
	(*counter)++;
	return 0;
}

int uacce_set_iommu_domain(struct device *dev)
{
	struct iommu_group *group;
	struct iommu_domain *domain;
	int ret;
	int dev_nr = 0;

	group = iommu_group_get(dev);
	if (!group) {
		ret = -ENODEV;
		goto out;
	}

	iommu_group_for_each_dev(group, &dev_nr, uacce_counter_fn);
	if (dev_nr != 1)
		dev_err(dev, "dev's iommu is not exclusive for uacce, %d\n",
			dev_nr);
	
	/* allocate and attach a unmanged domain */
	domain = iommu_domain_alloc(dev->bus);
	if (!domain) {
		ret = -ENODEV;
		goto err_with_group;
	}

	ret = iommu_attach_group(domain, group);

err_with_group:
	iommu_group_put(group);
out:
	return ret;
}
EXPORT_SYMBOL_GPL(uacce_set_iommu_domain);

void uacce_unset_iommu_domain(struct device *dev)
{
	struct iommu_group *group;
	struct iommu_domain *domain;

	group = iommu_group_get(dev);
	domain = iommu_get_domain_for_dev(dev);
	iommu_detach_group(domain, group);
	iommu_group_put(group);
}
EXPORT_SYMBOL_GPL(uacce_unset_iommu_domain);

/* Allocate a page and share it between kernel and device with the same virutal
 * address.
 * This will not work on passthough mode
 */
struct uacce_share_mem *uacce_alloc_shared_mem(struct device *dev, size_t size,
					       int prot)
{
	struct uacce_share_mem *sm;
	int ret;
	struct iommu_domain *domain;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		ret = -ENODEV;
		goto err;
	}

	sm = kzalloc(sizeof(*sm), GFP_KERNEL);
	if (!sm) {
		ret = -ENOMEM;
		goto err;
	}

	sm->dev = dev;
	sm->order = get_order(size);
	sm->va = (void *)__get_free_pages(GFP_KERNEL, sm->order);
	if (!sm->va) {
		ret = -ENOMEM;
		goto err_with_sm;
	}

	memset(sm->va, 0, 1 << sm->order);
	ret = iommu_map(domain, (unsigned long)sm->va, (phys_addr_t)sm->va,
			1 << sm->order, prot);
	if (ret) {
		ret = -ENODEV;
		goto err_with_va;
	}

	return sm;

err_with_va:
	free_pages((unsigned long)sm->va, sm->order);
err_with_sm:
	kfree(sm);
err:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(uacce_alloc_shared_mem);

void uacce_free_shared_mem(struct uacce_share_mem *sm)
{
	struct iommu_domain *domain;
	size_t unmap_size;

	domain = iommu_get_domain_for_dev(sm->dev);
	if (!domain) {
		dev_err(sm->dev, "no domain when free shared memory\n");
	}

	unmap_size = iommu_unmap(domain, (unsigned long)sm->va, 1 << sm->order);
	WARN(unmap_size != 1 << sm->order, "unmap share memory fail\n");

	free_pages((unsigned long)sm->va, sm->order);
	kfree(sm);
}
EXPORT_SYMBOL_GPL(uacce_free_shared_mem);

/* map share memory to user space */
int uacce_mmap_shared_mem(struct uacce_share_mem *sm,
			  struct vm_area_struct *vma)
{
	size_t sz = vma->vm_end - vma->vm_start;

	vma->vm_flags |= VM_PFNMAP;
	if (sz > 1 << sm->order)
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start, virt_to_phys(sm->va), sz,
			       vma->vm_page_prot);
}
EXPORT_SYMBOL_GPL(uacce_mmap_shared_mem);
