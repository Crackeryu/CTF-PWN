#!/bin/sh

qemu-system-x86_64  \
-m 64M \
-cpu kvm64,+smep \
-kernel ./bzImage \
-initrd rootfs.img \
-nographic \
-s \
-append "console=ttyS0 kaslr quiet"
