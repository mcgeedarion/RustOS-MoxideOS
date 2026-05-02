#!/bin/bash
set -e
QEMU=${QEMU:-qemu-system-x86_64}
"$QEMU" \
  -machine q35 \
  -cpu qemu64 \
  -m 256M \
  -kernel kernel.bin \
  -drive file=disk.img,if=virtio,format=raw \
  -initrd initramfs.cpio \
  -nographic \
  -serial mon:stdio \
  -no-reboot
