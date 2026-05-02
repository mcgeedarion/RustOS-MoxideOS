# RustOS

A hobby operating system kernel written in Rust, targeting x86_64 (primary) and RISC-V 64 (secondary).

## Features

- UEFI bootloader entry
- x86_64: GDT, IDT, APIC, paging (4-level), syscall/sysret, serial
- RISC-V 64: SBI boot, CSR helpers, sv39 paging, trap handling
- Memory: buddy allocator, PMM, VMM, mmap, heap (slab-style)
- Processes: fork, clone, scheduler, signals, futex, CoW, wait
- Filesystem: ext2 (read-write), VFS, devfs, procfs, sysfs, ramfs, initramfs
- Drivers: virtio-blk (read+write), virtio-net, PCIe, PS/2, TTY, UART
- Networking: Ethernet, ARP, IPv4, TCP, UDP, ICMP, DHCP, DNS
- Userspace: init, sh, cat, ls, echo, hello, devtest, thread_test

## Building (x86_64)

```sh
bash build_x86.sh
```

## Running

```sh
bash tools/run_qemu.sh
```
