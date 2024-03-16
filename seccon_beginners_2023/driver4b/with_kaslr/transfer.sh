#!/bin/sh

set -e
echo "[+] compiling exploit..."
gcc exploit.c -o exploit -static
echo "[+] extract rootfs..."
mkdir rootfs
cd ./rootfs
sudo cpio -idv < ../rootfs.cpio > 1&>/dev/null
echo "[+] transfer exploit binary..."
cp ../exploit .
echo "[+] repack normal rootfs..."
sudo find . -print0 | sudo cpio -o --format=newc --null > ../rootfs.cpio
cd ..
sudo rm -rf ./rootfs
echo "[+] Done !"
