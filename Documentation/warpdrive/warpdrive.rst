Introduction of WarpDrive
=========================

*WarpDrive* is a general accelerator framework for the user application to
communicate with the hardware without going through the kernel in data path.

It can be used as a quick channel for accelerators, network adaptors or
other hardware for application in user space.

It may also make some exist solution simpler.  E.g.  you can reuse most of the
*netdev* driver in kernel and just share some ring buffer to the user space
driver for *DPDK* [4] or *ODP* [5]. Or you can combine the RSA accelerator
with the *netdev* in the user space as a https reversed proxy, etc.

*WarpDrive* takes the hardware accelerator as a heterogeneous processor which
can share particular load from the CPU:

.. image:: wd.svg
        :alt: WarpDrive Concept

A virtual concept, queue, is used for the communication. It provides a FIFO
-like interface. And it maintains a unify address space between the
application and all involved hardware.

The name *WarpDrive* is simply a cool and general name meaning the framework
makes the application faster. It includes general user library, kernel
management module and drivers for the hardware. In kernel, the management
module is called *uacce*, meaning "Unified/User-space-access-intended
Accelerator Framework".


How does it work
================

*WarpDrive* uses *mmap* and *IOMMU* to play the trick.

*Uacce* create a chrdev for every device registered to it. New queue is
created when user application open the chrdev. The file descriptor is used as
the user handle of the queue.

The control path to the hardware is via file operation, while data path is via
mmap space of the queue fd.

The following figure demonstrated the queue file address space:

.. image:: wd_q_addr_space.svg
        :alt: WarpDrive Queue Address Space

All regions are optional and differ from device type to type. The
communication protocol is wrapped by the user driver.

The device mmio region is mapped to the hardware mmio space. It is generally
used for doorbell or other notification to the hardware. It is not fast enough
as data channel.

The device kernel-only region is necessary only if the device IOMMU has no
PASID support or it cannot send kernel-only address request. In this case, if
the kernel need to share memory with the device. It has to share iova address
space with the user process. This will be explained in the kernel DMA API
section.

The device user share region is used for share data buffer with the device.
It can be merged into other region. But a separated region can help on device
state management. For example, the device can be started when this region is
mapped.

The static share virtual memory region is used for share data buffer with the
device. Its size is set according to the application requirement.

All regions except for mmio are not necessary if the device support SVA. In
this case, the whole user process space is shared with the device.

Todo: we may need a interface for SVA device to use another page table other
than the user process's. (But this may not be a practical requirement. So it
will be kept as a "todo" for a while)


Difference to the VFIO and IB framework
---------------------------------------
The essential function of WarpDrive is to let the device access the user
address directly. There are many device drivers doing the same in the kernel.
And both VFIO and IB can provide similar function in framework level.

But WarpDrive has its own intension, which is to "share address space". It is
not taken the request to the accelerator as a enclosure data structure. It
takes the accelerator as another thread of the same process. So the
accelerator can refer to any address used by the process.

Both VFIO and IB are taken this as "memory sharing", not "address sharing".
They care more on sharing the block of memory. But if there is an address
stored in the block and referring to another memory region. The address may
not be valid.

By adding more constrain to the VFIO and IB framework, in some sense, we may 
achieve similar goal. But we gave up finally. Both VFIO and IB have extra
assumption which is unnecessary to WarpDrive. They may hurt each other if we
try to merge them together.

VFIO manages resource of a hardware as a "virtual device". If a device need to
serve a separated application. It must isolate the resource as separate
virtual device.  And the life cycle of the application and virtual device are 
unnecessary unrelated. And most of concepts, such as bus, driver, probe and
so on, to make it as a "device" is unnecessary either. And the logic added to
VFIO to make address sharing do no help on "creating a virtual device".

IB creates a "verbs" standard for sharing memory region to another remote
entity.  Most of these verbs are to make memory region between entities to be
synchronized.  This is not what accelerator need. Accelerator is in the same
memory system with the CPU. It refers to the same memory system among CPU and
devices. So the local memory terms/verbs are good enough for it. Extra "verbs"
are not necessary. And its queue (like queue pair in IB) is the communication
channel direct to the accelerator hardware. There is nothing about memory
itself.

Further, both VFIO and IB use the "pin" (get_user_page) way to lock local
memory in place.  This is flexible. But it can cause other problem. For
example, if the user process fork a child process. The COW procedure may make
the parent process lost its pages which are sharing with the device. These may
be fixed in the future. But is not going to be easy. (There is a discussion
about this on Linux Plumbers Conference 2018 [2]_)

So we choose to build the solution directly on top of IOMMU interface. IOMMU
is the essential way for device and process to share their page mapping from
the hardware perspective. It will be safe to create a software solution on
this assumption.  Uacce manages the IOMMU interface for the accelerator
device, so the device driver can export some of the resource to the user
space. Uacce than can make sure the device and the process have the same
address space.


Architecture
------------

The full *WarpDrive* architecture is represented in the following class
diagram:

.. image:: wd-arch.svg
        :alt: WarpDrive Architecture

It is quite straightforwards. The accelerator device present itself as a
"uacce" object, which export as chrdev to the user space. The user application
communicates with the hardware by ioctl (as control path) or share memory (as
data path).


The user API
------------

We adopt a polling style interface in the user space: ::

        int wd_request_queue(struct wd_queue *q);
        void wd_release_queue(struct wd_queue *q);

        int wd_send(struct wd_queue *q, void *req);
        int wd_recv(struct wd_queue *q, void **req);
        int wd_recv_sync(struct wd_queue *q, void **req);
        void wd_flush(struct wd_queue *q);

wd_recv_sync() is a wrapper to its non-sync version. It will trapped into
kernel and waits until the queue become available.

If the queue do not support SVA/SVM. The following helper function
can be used to create Static Virtual Share Memory: ::

        void *wd_preserve_share_memory(struct wd_queue *q, size_t size);

The user API is not mandatory. It is simply a suggestion and hint what the
kernel interface is supposed to be.


The user driver
---------------

The queue file mmap space will need a user driver to wrap the communication
protocol. *UACCE* provides some attributes in sysfs for the user driver to
match the right accelerator accordingly.

The *UACCE* device attribute is under the following directory:

/sys/class/uacce/<dev-name>/attrs

The following attributes is supported:

id (ro)
        N. Id of the device. The chrdev of this uacce is /dev/uaN

nr_queue_remained (ro)
        Number of queue remained

hw_ver (ro)
        A string to identify the hardware user interface. Used to match the
        user driver.

algorithms (ro)
        A white space separated string to identify the algorithms supported by
        this accelerator.

device_attr (ro)
        Attributes of the device, see UACCE_DEV_xxx flag defined in uacce.h

numa_node (ro)
        Id of numa node

priority (rw)
        Priority or the device, bigger is higher

(This is not yet implemented in RFC version)


The Memory Sharing Model
------------------------
The perfect form of a uacce device is to support SVM/SVA. We built this upon
Jean Philippe Brucker's SVA patches. [1]_

If the hardware support SVA, the user process's page table is shared to the
opened queue. So the device can access any address in the process address
space. And it can raise a page fault if the physical page is not available
yet. It can also access the address in the kernel space, which is referred by
another page table particular to the kernel. Most of IOMMU implementation can
handle this by a tag on the address request of the device. For example, ARM
SMMU uses SSV bit to indicate that the address request is for kernel or user
space.

The device_attr UACCE_DEV_SVA is used to indicate this capability of the
device. It is a combination of UACCE_DEV_FAULT_FROM_DEV and UACCE_DEV_PASID.

If the device does not support UACCE_DEV_FAULT_FROM_DEV but UACCE_DEV_PASID.
*Uacce* will create a unmanaged iommu_domain for the device. So it can be
bound to multiple processes. In this case, the device cannot share the user
page table directly. The user process must map the Static Share Queue File
Region to create the connection. The *Uacce* kernel module will allocate
physical memory to the region for both the device and the user process.

If the device does is not support UACCE_DEV_PASID either. There is no way for 
*uacce* to support multiple process. Every *Uacce* allow only one process at
the same time. In this case, DMA API cannot be used in this device. If the
device driver need to share memory with the device, it should use QFRT_KO
queue file region instead. This region is mmaped from the user space but valid
only for kernel.

The device can also be declared as UACCE_DEV_NOIOMMU. It can be used when the
device has no iommu support or the iommu is set in pass through mode.  In this
case, the driver should map address to device by itself with DMA API.  In
this mode, the device may also need a continue physical page for DMA
operation. The UACCE_DEV_CONT_PAGE flag can enforce this requirement. The
ioctl(UACCE_CMD_GET_SS_PA) can be used to get the physical address. Using
UCCE_DEV_CONT_PAGE and UACCE_CMD_GET_SS_PA is taken as an untrusted and
kernel-tainted behavior.

We suggest the driver use uacce_mode module parameter to choose the working
mode of the device. It can be:

UACCE_MODE_NOUACCE (0)
        Do not register to uacce. In this mode, the driver can register to
        other kernel framework, such as crypto

UACCE_MODE_UACCE (1)
        Register to uacce. In this mode, the driver register to UACCE. It can
        register to other kernel framework according to whether it supports
        PASID.

UACCE_MODE_NOIOMMU
        Register to uacce and assume there is no IOMMU or IOMMU in
        pass-through mode. In this case, DMA API is available, so it can also
        register to other kernel framework.

        In this case, mmap operations except for QRFT_SS will be passed
        through to the uacce->ops->mmap() call back.


The uacce register API
-----------------------
The *uacce* register API is defined in uacce.h. If the hardware support SVM/SVA,
The driver need only the following API functions: ::

        int uacce_register(uacce);
        void uacce_unregister(uacce);
        void uacce_wake_up(q);

*uacce_wake_up* is used to notify the process who epoll() on the queue file.

According to the IOMMU capability, *uacce* categories the devices as follow:

UACCE_DEV_NOIOMMU
        The device has no IOMMU. The user process cannot use VA on the hardware
        This mode is not recommended.

UACCE_DEV_SVA (UACCE_DEV_PASID | UACCE_DEV_FAULT_FROM_DEV)
        The device has IOMMU which can share the same page table with user
        process

UACCE_DEV_SHARE_DOMAIN
        This is used for device which need QFR_KO.

If the device works in mode other than UACCE_DEV_NOIOMMU, *uacce* will set its
IOMMU to IOMMU_DOMAIN_UNMANAGED.


The Folk Scenario
=================
For a process with allocated queues and shared memory, what happen if it forks
a child?

The fd of the queue will be duplicated on folk, so the child can send request
to the same queue as its parent. But the requests which is sent from processes
except for the one who open the queue will be blocked.

It is recommended to add O_CLOEXEC to the queue file.

The queue mmap space has a VM_DONTCOPY in its VMA. So the child will lost all
those VMAs.

This is a reason why *WarpDrive* does not adopt the mode used in *VFIO* and
*InfiniBand*.  Both solutions can set any user pointer for hardware sharing.
But they cannot support fork when the dma is in process. Or the
"Copy-On-Write" procedure will make the parent process lost its physical
pages.


The Sample Code
===============
There is a sample user land implementation with a simple driver for Hisilicon
Hi1620 ZIP Accelerator.

To test, do the following in samples/warpdrive (for the case of PC host): ::
        ./autogen.sh
        ./conf.sh       # or simply ./configure if you build on target system
        make

Then you can get test_hisi_zip in the test subdirectory. Copy it to the target
system and make sure the hisi_zip driver is enabled (the major and minor of
the uacce chrdev can be gotten from the dmesg or sysfs), and run: ::
        mknod /dev/ua1 c <major> <minior>
        test/test_hisi_zip -z < data > data.zip
        test/test_hisi_zip -g < data > data.gzip


References
==========
.. [1] https://patchwork.kernel.org/patch/10394851/
.. [2] https://lwn.net/Articles/774411/

.. vim: tw=78
