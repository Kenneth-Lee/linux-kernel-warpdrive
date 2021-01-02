ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
	make -j3 O=../armbuild-kernel $1

#note:
#make kernel with this:
#CONFIG_CROSS_COMPILE="aarch64-linux-gnu-"
#CONFIG_INITRAMFS_SOURCE="/home/kenny/work/hisi-repo/buildroot.git/output/images/rootfs.cpio"
#CONFIG_NET_9P=y
#CONFIG_NET_9P_VIRTIO=y
