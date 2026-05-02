#!/bin/bash
# Pack userspace binaries into initramfs.cpio
set -e
cd userspace
cargo build --release 2>&1
cd ..
mkdir -p initramfs/{bin,etc,tmp,proc,sys,dev}
cp userspace/target/*/release/{init,sh,cat,ls,echo,hello,devtest} initramfs/bin/ 2>/dev/null || true
find initramfs | cpio -o -H newc > initramfs.cpio
echo "initramfs.cpio ready"
