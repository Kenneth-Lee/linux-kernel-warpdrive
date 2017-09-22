Queue Inquiry Protocals
=======================
The queue inquiry protocols defines how the connection is created between the
user land application and the accelerator drivers.

(NOTES: A Rough description is used in this version for the definition. It
will be updated when the code deduction is finished)


Accelerator Register
--------------------
The accelerator device is registered to *wd_framework* as *wd_dev* with
*wd_ops*. It is will taken as a *vfio-mdev* parent device.

The *wd_dev->dev* is registered to class *wd_dev*, so it can be enumerated
in::

        /sys/class/wrapdrive

The following attribute group will be add to it::

        /sys/class/wd_dev/<dev_id>/wdev
        /sys/class/wd_dev/<dev_id>/mdev_supported_types/<dev_drv>-<algo_type>

with the following attribute:

        wdev.zone_id(rw)
                A changeable value to identify the location of the
                accelerator. In most case it is not necessary to be changed.
                But in case the system make a mistake...

        wdev.priority(rw)
                A changeable value to indentify the priority of the
                accelerator to be selected. Range in [-100, 99], default is 0,
                smaller is preferred. A value which is out of range will
                disable the device to be chosen.

        wdev.iommu(ro)
                The VFIO iommu type, such as the number value of
                VFIO_TYPE1_IOMMU

        <dev_drv>-<algo_type>.name(ro)
                Name of the algorithm, it is the same as <algo_type>. But this
                is the value should be relied on for the user application

        <dev_drv>-<algo_type>.latency(ro)/throughput
                The latency and throught put level of the algo. Range in [0,
                99], 10 is used as the average level. (need to refine. How a
                new device can set its level?)

        <dev_drv>-<algo_type>.flags(ro)
                A 32-bit bit mask to identify the feature can be supported in the
                algorithm. The lower 8bit is used for wrapdriver framework and
                the other bits are used by the algorithm.

                This is a value in hex format

                bit 0 - WD_CAPA_SHARE_ALL

                bit 1 - WD_CAPA_SGL_MEM

        <dev_drv>-<algo_type>.available_instances(ro)
                Remained number of instances

        <dev_drv>-<algo_type>.device_api(ro)
                A string to identify the API version of the queue for the
                algorithm



Queue Inquirying
----------------

The *WrapDrive_u* libary search for a queue by:

1. Enumerating the /sys/class/wrapdrive directory
2. Match the algorithm by <dev_drv>-<algo_type>/name
3. Match the sub-feature of the algorithm by <dev_drv>-<algo_type>/flags
4. Check the device_api and make sure the user drive is available
5. Choose a best device from the matched pool according the wrapdrive_dev
   attributes.
6. Write a uuid to the <dev_drv>-<algo_type>/create to create the queue
7. Set parameters in /sys/class/wd_dev/<dev_id>/<mdev_uuid>/params according
   to the API

Now the queue is ready to go


Queue Reclaiming
================

The Queue can be reclaimed by writing to <dev_drv>-<algo_type>/remove by the
*WrapDrive_u*.

If the *WrapDrive_u* cannot do this (say it is crashed before remove the
device. A Daemon can be used to clear it up if the process who allocated the
mdev (the pid is recorded as a mdev attribute under
/sys/class/wd_dev/<dev_id>/mdev_uuid/params/queue_pid) has been released 

.. vim: tw=78
