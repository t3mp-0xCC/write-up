#!/bin/sh
qemu-system-x86_64 -m 64M \
  -kernel bzImage \
  -initrd rootfs.cpio \
  -append "loglevel=3 console=ttyS0 oops=panic panic=-1 kaslr" \
  -no-reboot \
  -nographic \
  -net user -net nic -device e1000 \
  -smp cores=2,threads=2 -cpu kvm64,+smep \
  -gdb tcp::12345