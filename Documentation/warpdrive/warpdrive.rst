Introduction of WarpDrive
=========================

*WarpDrive* is a general accelerator framework for the user application to
access the hardware without going through the kernel in data path.

It can be used as the quick channel for accelerators, network adaptors or
other hardware for application in user space.

This may make some implementation simpler.  E.g.  you can reuse most of the
*netdev* driver in kernel and just share some ring buffer to the user space
driver for *DPDK* [4] or *ODP* [5]. Or you can combine the RSA accelerator with
the *netdev* in the user space as a Web reversed proxy, etc.

*WarpDrive* takes the hardware accelerator as a heterogeneous processor which
can share particular load from the CPU:

.. image:: wd.svg
        :alt: WarpDrive Concept

The virtual concept, queue, is used to manage the requests sent to the
accelerator. The application send request to the queue by writing to some
particular address, the hardware take the request directly from the address
and send feedback accordingly.

The format of the queue can differ from hardware to hardware. But the
application need not to make any system call for the communication.

*WarpDrive* tries to create a shared virtual address space for all involved
accelerators. Within this space, the requests sent to queue can refer to any 
virtual address, which will be valid to the application and all involved
accelerators.

The name *WarpDrive* is simply a cool and general name meaning the framework
makes the application faster. It includes general user library, kernel management
module and drivers for the hardware. In kernel, the management module is
called *uacce*, meaning "Unified/User-space-access-intended Accelerator
Framework".


How does it work
================

*WarpDrive* uses *mmap* and *IOMMU* to play the trick.

The device registering to *uacce* will create a chrdev. Openning the chrdev
will can get a queue from the device. And mmap-ing to the queue file will get
the share memory between the application and the accelerator.

The following figure demonstrated the file address space:

.. image:: wd_q_addr_space.svg
        :alt: WarpDrive Queue Address Space

The first region of the space, device region, is used for the application to
write request or read answer to or from the hardware.

Normally, there can be two types of device regions, mmio and memory regions.
It is recommended to use common memory for request/answer description and use
the mmio space for device notification, such as doorbell. But of course, this
is all up to the interface designer.

The Static Share Virtual Memory region is necessary only when the device IOMMU
does not support "Share Virtual Memory". This will be explained after the
*IOMMU* idea.

The communication between user land application can all be done by writing or
reading on the mmap memory.

In kernel, *uacce* makes the memory sharing work by the IOMMU API. The driver
that registers to *uacce* should use iommu API instead of dma API for DMA
operation. By creating its own iommu_group and iommu_domain, its IOMMU will
work on IOMMU_DOMAIN_UNMANAGED rather than IOMMU_DOMAIN_DMA mode. So the
device driver in kernel can always map the same virtual address to IOMMU as
the application to MMU.

Architecture
------------

The full *WarpDrive* architecture is represented in the following class
diagram:

.. image:: wd-arch.svg
        :alt: WarpDrive Architecture


The user API
------------

We adopt a polling style interface in the user space: ::

        int wd_request_queue(struct wd_queue *q);
        void wd_release_queue(struct wd_queue *q);

        int wd_send(struct wd_queue *q, void *req);
        int wd_recv(struct wd_queue *q, void **req);
        int wd_recv_sync(struct wd_queue *q, void **req);
        void wd_flush(struct wd_queue *q);

wd_recv_sync() is a wrapper to its non sync version. It will trapped into
kernel and waits until the queue become available.

If the queue do not support SVA/SVM. The following helper function
can be used to create Static Virtual Share Memory: ::

        void *wd_preserve_share_memory(struct wd_queue *q, size_t size);

The user API is not mandatory. It is simply a suggestion and hint what the
kernel interface is supposed to support.


The user driver
---------------

The queue file mmap space will need a user driver to wrap the communication
protocol. *UACCE* provides some attributes in sysfs for the user driver to match
the right accelerator accordingly.

The *UACCE* device attribute is under the following directory:

/sys/class/uacce/<dev-name>/params

The following attributes is supported:

nr_queue_remained (ro)
        number of queue remained

api_version (ro)
        a string to identify the queue mmap space format and its version

device_attr (ro)
        attributes of the device, see UACCE_DEV_xxx flag defined in uacce.h

numa_node (ro)
        id of numa node

priority (rw)
        Priority or the device, bigger is higher


Multiple processes support
==========================

In the latest mainline kernel (4.19) when this document is written, the IOMMU
subsystem do not support multiple process page tables yet.

Most IOMMU hardware implementation support multi-process with the concept
of PASID. But they may use different name, e.g. it is call sub-stream-id in
SMMU of ARM. With PASID or similar design, multi page table can be added to
the IOMMU and referred by its PASID.

*JPB* has a patchset to enable this[1]_. We have tested it with our hardware
(which is known as *D06*). It works well. *WarpDrive* rely on them to support
multiple processes. If it is not enabled, *WarpDrive* can still work, but it
support only one process, which will share the same io map table with kernel
(but the user application cannot access the kernel address, So it is not going
to be a security problem). This is called Share IOMMU mode.

Static Share Virtual Memory mode should be adopted in share IOMMU mode.


Legacy Mode Support
===================
For the hardware without IOMMU, WarpDrive can still work, the only problem is
VA cannot be used in the device. The driver should adopt another strategy for
the shared memory. It is only for testing, it is not recommended.


The Folk Scenario
=================
If a process with allocated queues and shared memory, what happen if it forks
a child?

The fd of the queue will be duplicated on folk, so the child can send request
to the same queue as its parent. But the requests which is sent from processes
except for the one who open the queue will be blocked.

It is recommended to add O_CLOEXEC to the queue file.

The queue mmap space has a VM_DONTCOPY in its VMA. So the child will lost all
those VMA.

This is why *WarpDrive* does not adopt the mode used in *VFIO* and *InfiniBand*.
Both solution can set any user pointer for hardware sharing. But they cannot
support fork when the dma is in process. Or the "Copy-On-Write" procedure will
make the parent process lost its physical pages.


References
==========
.. [1] https://patchwork.kernel.org/patch/10394851/

.. vim: tw=78
