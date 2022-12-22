#!/bin/sh
qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./rootfs_debug.cpio \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr quiet" \
    -no-reboot \
    -cpu kvm64,+smep,+smap \
    -monitor /dev/null \
    -nographic -enable-kvm \
    -gdb tcp::12345
