#!/bin/bash

set -e

CURDIR=$(dirname $0)
THIRD=$(realpath $CURDIR/../../others)
KERNEL=$THIRD/kernel-sw-prefetch/build/arch/x86_64/boot/bzImage
DISK=$THIRD/disk.img
BOOT_DISK=$THIRD/boot.img
SEED_DISK=$THIRD/seed.img
ISO_DISK=$THIRD/install.img

if [ ! -f $ISO_DISK ]; then
	echo Downloading install disk ...
	wget -O $ISO_DISK https://releases.ubuntu.com/22.04.5/ubuntu-22.04.5-live-server-amd64.iso
fi

# if [ ! -f $SEED_DISK ]; then
# 	echo Creating seed disk ...
# 	genisoimage -output $SEED_DISK -volid cidata -joliet -rock ./boot_config/*
# fi

# if [ ! -f $BOOT_DISK ]; then
# 	echo Downloading boot image ...
# 	image_url=https://cloud-images.ubuntu.com/jammy/20250619/jammy-server-cloudimg-amd64-disk-kvm.img
# 	wget -O $BOOT_DISK $image_url
# fi

if [ ! -f $DISK ]; then
	echo Creating $DISK ...
	qemu-img create -f qcow2 $DISK 30G
fi

sudo qemu-system-x86_64 \
	-m 16G \
	-cpu host \
	-smp 8 \
	-boot d \
	-machine accel=kvm \
	-cdrom $ISO_DISK \
	-drive file=$DISK,format=qcow2 \
	-device virtio-net-pci,netdev=net0 \
	-netdev user,id=net0 \
	-device virtio-net-pci,netdev=net1 \
	-netdev user,id=net1,hostfwd=tcp::2222-:22 \
	-nographic

