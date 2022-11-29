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
echo "[+] repack debug rootfs..."
sudo sed -e "s/setuidgid 1337/setuidgid 0/g" ./etc/init.d/S99pawnyable > /tmp/S99pawnyable
sudo cp -f /tmp/S99pawnyable ./etc/init.d/S99pawnyable
rm /tmp/S99pawnyable
echo -e "#!/bin/sh\necho 0 > /proc/sys/kernel/kptr_restrict\n" > disable_kadr.sh
chmod +x ./disable_kadr.sh
sudo find . -print0 | sudo cpio -o --format=newc --null > ../rootfs_debug.cpio
cd ..
sudo rm -rf ./rootfs
echo "[+] Done !"
