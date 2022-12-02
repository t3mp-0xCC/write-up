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
cp ./etc/passwd /tmp/passwd
sudo echo -e "debug::0:0:root:/root:/bin/sh" >> /tmp/passwd
sudo cp -f /tmp/passwd ./etc/passwd
sudo rm /tmp/passwd
echo -e "#!/bin/sh\necho 0 > /proc/sys/kernel/kptr_restrict\n" > disable_kadr.sh
chmod +x ./disable_kadr.sh
sudo find . -print0 | sudo cpio -o --format=newc --null > ../rootfs_debug.cpio
cd ..
sudo rm -rf ./rootfs
echo "[+] Done !"
