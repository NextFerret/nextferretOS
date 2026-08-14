#!/bin/bash
set -e

mkdir -p /tmp/rootfs_staging /tmp/iso_build/live /tmp/iso_build/boot/grub

rsync -aAXv / /tmp/rootfs_staging/ \
  --exclude={/dev/*,/proc/*,/sys/*,/tmp/*,/run/*,/mnt/*,/media/*,/*.iso,/nextferret-plymouth-theme,/build_iso.sh,/*sha256}

mkdir -p /tmp/rootfs_staging/{dev,proc,sys,tmp,run,mnt,media}
chmod 1777 /tmp/rootfs_staging/tmp

mksquashfs /tmp/rootfs_staging /tmp/iso_build/live/filesystem.squashfs -comp xz -noappend -processors 8

KERNEL_VERSION="6.12.86+deb13-amd64"

cp /boot/vmlinuz-$KERNEL_VERSION /tmp/iso_build/live/vmlinuz
cp /boot/initrd.img-$KERNEL_VERSION /tmp/iso_build/live/initrd.img

cat <<EOF > /tmp/iso_build/boot/grub/grub.cfg
insmod part_gpt
insmod part_msdos
insmod ext2

set default=0
set timeout=5

menuentry "Arvor Linux 7.1 (Sable) Beta 14826 Desktop" {
    search --no-floppy --set=root --file /live/vmlinuz
    linux /live/vmlinuz boot=live components quiet splash
    initrd /live/initrd.img
}

menuentry "UEFI Firmware Settings" {
    fwsetup
}

EOF

grub-mkrescue -o /arvorlinux-x86_64-sable.iso /tmp/iso_build


sha256sum /arvorlinux-x86_64-sable.iso > /arvorlinux-x86_64-sable.iso.sha256
