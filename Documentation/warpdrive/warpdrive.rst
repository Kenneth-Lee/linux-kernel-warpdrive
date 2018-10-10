Introduction of WarpDrive
=========================

*WarpDrive* is a general accelerator framework for the user application to
access the hardware without going through the kernel.

It can be used as the quick channel for accelerators, network adaptors or
other hardware in user space. This may make some implementation simpler.  E.g.
you can reuse most of the *netdev* driver in kernel and just share some ring
buffer to the user space driver for *DPDK*[4] or *ODP*[5]. Or you can combine
the RSA accelerator with the *netdev* in the user space as a Web reversed
proxy, etc.

The name *WarpDrive* is simply a cool and general name meaning the framework
makes the application faster. In kernel, the framework is called uacce,
meaning "Unified/User-space-access-intended Accelerator Framework".


How does it work
================

*WarpDrive* takes the hardware accelerator as a heterogeneous processor which
can share particular load from the CPU:

.. image:: wd.svg
        :alt: WarpDrive Concept

So it provides the capability to the user application to:

1. Send requests to the hardware (without syscall)
2. Share memory of the application with the accelerators

*WarpDrive* uses the concept, "queue", as the command channel between the user
process and the accelerator hardware. From perspective of the user process,
queue is a file description by open a *WarpDrive* device.

The user driver accesses the hardware by mmapping the file. The following figure
demonstrated the file address space:

.. image:: wd_q_addr_space.svg
        :alt: WarpDrive Queue Address Space

The first section of the space, device space, is used for the application to
send request to the hardware. It is recommended to use common memory for
command description and use the mmio space for device notification, such as
doorbell for the device to get the command from the memory.

This will be enough for device with "share virtual memory" capability. The
command can refer to any virtual address of the process space.

For the device without "share virtual memory" support, the second section come
to help. When this section is mmmaped, *WarpDrive* allocate DMA memory and
map its mmapp virtual address to the physical address with IOMMU. Memory in
this section can still be referred by the request directly.


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

wd_recv_sync() is a wrapper to its non sync version. It waits until the queue
become available.

If the queue do not support SVA/SVM. The following helper function
can be adopted: ::

        void *wd_preserve_share_memory(struct wd_queue *q, size_t size);

The user API is not mandatory. It is simply a suggestion and hint what the
kernel interface is supposed to support.


The user driver
---------------

*WarpDrive* expose the hardware IO space to the user process (via *mmap*). So
it will require user driver for implementing the user API. The following API
is suggested for a user driver: ::

        int open(struct wd_queue *q);
        int close(struct wd_queue *q);
        int send(struct wd_queue *q, void *req);
        int recv(struct wd_queue *q, void **req);

These callback enable the communication between the user application and the
device. You will still need the hardware-depend algorithm driver to access the
algorithm functionality of the accelerator itself.


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

In share IOMMU mode, the kernel driver should not direct use iommu_map other
than dma_map to map the kernel memory. The can make sure the user VA and the
kernel IOVA will not conflict.


Legacy Mode Support
===================
For the hardware without IOMMU, WarpDrive can still work, the only problem is
VA cannot be used in the driver. The driver should adopt another strategy for
the shared memory.


The Folk Scenario
=================
If a process with allocated queues and shared memory, what happen if it forks
a child?

The fd of the queue will be duplicated on folk, so the child can send request
to the same queue as its parent. But the requests which is sent from processes
except for the one who open the queue will be blocked.

It is recommended to add O_CLOEXEC to the queue file.

The mmap to the device space should not be used by the child, so the
VM_DONTCOPY flag will be added. The child will not use those space.

The shared memory should not be used by the child. There are 2 categories
here:

1. With SVM/SVA, the memory is not shared at all, so it is not a problem.
2. Without SVM/SVA, the process mush use wd_preserve_share_memory() to
   preserve the memory, which will be "copy-on-write-ed". It is taken the same
   as the other allocated memory. It will not cause any trouble.


References
==========
.. [1] https://patchwork.kernel.org/patch/10394851/

.. vim: tw=78
