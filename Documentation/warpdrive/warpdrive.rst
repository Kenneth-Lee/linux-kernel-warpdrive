Introduction of WarpDrive
=========================

*WarpDrive* is a general accelerator framework for user space. It intends to
provide interface for the user process to send request to hardware
accelerator without heavy user-kernel interaction cost.

The *WarpDrive* user library is supposed to provide a pipe-based API, such as:
        ::
        int wd_request_queue(struct wd_queue *q);
        void wd_release_queue(struct wd_queue *q);

        int wd_send(struct wd_queue *q, void *req);
        int wd_recv(struct wd_queue *q, void **req);
        int wd_recv_sync(struct wd_queue *q, void **req);
        int wd_flush(struct wd_queue *q);

*wd_request_queue* creates the pipe connection, *queue*, between the
application and the hardware. The application sends request and pulls the
answer back by asynchronized wd_send/wd_recv, which directly interact with the
hardware (by MMIO or share memory) without syscall.

*WarpDrive* maintains a unified application address space among all involved
accelerators.  With the following APIs: ::

        int wd_mem_share(struct wd_queue *q, const void *addr,
                         size_t size, int flags);
        void wd_mem_unshare(struct wd_queue *q, const void *addr, size_t size);

The referred process space shared by these APIs can be directly referred by the
hardware. The process can also dedicate its whole process space with flags,
*WD_SHARE_ALL* (not in this patch yet).

The name *WarpDrive* is simply a cool and general name meaning the framework
makes the application faster. As it will be explained in this text later, the
facility in kernel is called *SDMDEV*, namely "Share Domain Mediated Device".


How does it work
================

*WarpDrive* is built upon *VFIO-MDEV*. The queue is wrapped as *mdev* in VFIO.
So memory sharing can be done via standard VFIO standard DMA interface.

The architecture is illustrated as follow figure:

.. image:: wd-arch.svg
        :alt: WarpDrive Architecture

Accelerator driver shares its capability via *SDMDEV* API: ::

        vfio_sdmdev_register(struct vfio_sdmdev *sdmdev);
        vfio_sdmdev_unregister(struct vfio_sdmdev *sdmdev);
        vfio_sdmdev_wake_up(struct spimdev_queue *q);

*vfio_sdmdev_register* is a helper function to register the hardware to the
*VFIO_MDEV* framework. The queue creation is done by *mdev* creation interface.

*WarpDrive* User library mmap the mdev to access its mmio space and shared
memory. Request can be sent to, or receive from, hardware in this mmap-ed
space until the queue is full or empty.

The user library can wait on the queue by ioctl(VFIO_SDMDEV_CMD_WAIT) the mdev
if the queue is full or empty. If the queue status is changed, the hardware
driver use *vfio_sdmdev_wake_up* to wake up the waiting process.


Multiple processes support
==========================

In the latest mainline kernel (4.18) when this document is written,
multi-process is not supported in VFIO yet.

Jean Philippe Brucker has a patchset to enable it[1]_. We have tested it
with our hardware (which is known as *D06*). It works well. *WarpDrive* rely
on them to support multiple processes. If it is not enabled, *WarpDrive* can
still work, but it support only one mdev for a process, which will share the
same io map table with kernel. (But it is not going to be a security problem,
since the user application cannot access the kernel address space)

When multiprocess is support, mdev can be created based on how many
hardware resource (queue) is available. Because the VFIO framework accepts only
one open from one mdev iommu_group. Mdev become the smallest unit for process
to use queue. And the mdev will not be released if the user process exist. So
it will need a resource agent to manage the mdev allocation for the user
process. This is not in this document's range.


Legacy Mode Support
===================
For the hardware on which IOMMU is not support, WarpDrive can run on *NOIOMMU*
mode. That require some update to the mdev driver, which is not included in
this version yet.


References
==========
.. [1] https://patchwork.kernel.org/patch/10394851/

.. vim: tw=78
