#!/bin/bash

qemu-system-x86_64 -initrd ramdisk.cpio.gz -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm --nographic  -monitor /dev/null -m 64M -gdb tcp::1234  -smp cores=1,threads=1 -cpu kvm64,+smep
#add-symbol-file babydriver.ko 0xffffffffc0000000