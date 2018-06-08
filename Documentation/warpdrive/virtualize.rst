Virtualization Support in *WarpDrive*
======================================

*WarpDrive* is intended to support the following features:

1. Expose the hardware to the guest
2. Support the guest being live-migrated to the other host

We are going to support these feature on KVM-based solution.


Exposing the hardware to the guest
----------------------------------
This can be support by the same framework of VFIO. The accelerator can create
some VFs by means of vfio-pci or vfio-platform and expose the device to the
guest by the same way as the other devices do.

To support VFIO with 2-stages DMA address translation in ARM based system.
vSMMU feature need to be enabled. So the *WarpDrive* legacy mode will be
support in this scenario.

todo


Live Migration Support
----------------------
todo
