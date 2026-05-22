# userspace/Makefile
# Builds all userspace C programs as static musl-libc ELF64 binaries.
#
# Prerequisites (install once):
#   x86_64:  apt install musl-tools   # provides musl-gcc
#   RISC-V:  build musl from source targeting riscv64-linux-musl
#            or: apt install gcc-riscv64-linux-gnu musl-dev
#
# Usage:
#   make              # build x86_64 binaries (default)
#   make ARCH=riscv64 # build RISC-V binaries
#
# Output layout (matches build_initramfs.sh staging expectations):
#   build/<arch>/init               → staged as /init        (PID 1)
#   build/<arch>/hello              → staged as /bin/hello
#   build/<arch>/rustos-compositor  → staged as /usr/bin/rustos-compositor
#   build/<arch>/smoke              → staged as /bin/smoke   (QEMU smoke test)

ARCH       ?= x86_64
BUILD_DIR  := build/$(ARCH)

ifeq ($(ARCH),x86_64)
  CC      := musl-gcc
  CFLAGS  := -static -O2 -ffreestanding -fno-stack-protector \
             -Wall -Wextra -std=c11
else ifeq ($(ARCH),riscv64)
  CC      := riscv64-linux-musl-gcc
  CFLAGS  := -static -O2 -march=rv64gc -mabi=lp64d \
             -fno-stack-protector -Wall -Wextra -std=c11
else
  $(error Unsupported ARCH=$(ARCH). Use x86_64 or riscv64)
endif

# List every subdirectory that contains a C program here.
PROGRAMS := init hello wayland smoke

.PHONY: all clean install $(PROGRAMS)

all: $(PROGRAMS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

init: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/init init/init.c

hello: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/hello hello/hello.c

# Minimal QEMU smoke binary:
#   - prints a well-known marker to the serial console
#   - returns 0 on success
#   - can be extended later with basic invariants (e.g. /proc/1 exists).
smoke: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/smoke smoke/smoke.c

# The Wayland compositor is a privileged userspace process.
# It is installed as /usr/bin/rustos-compositor in the initramfs.
# The kernel spawns it as PID 2 via execve() after init (PID 1) starts.
#
# CFLAGS notes:
#   -fstack-protector-strong  — re-enabled (unlike other binaries); the
#     compositor handles untrusted data from Wayland clients.
#   _GNU_SOURCE               — required for epoll_create1, SOCK_CLOEXEC,
#     accept4, and the seccomp BPF headers.
wayland: $(BUILD_DIR)
	$(CC) -static -O2 -D_GNU_SOURCE -fstack-protector-strong \
	      -Wall -Wextra -std=c11 \
	      -o $(BUILD_DIR)/rustos-compositor \
	      wayland/compositor.c

# Copies built binaries into a staging rootfs tree whose layout matches
# what build_initramfs.sh expects when it packs the CPIO archive:
#
#   DESTDIR/
#     init                        ← exec'd directly as PID 1 by the kernel
#     bin/hello
#     bin/smoke                   ← small QEMU smoke-test helper
#     usr/bin/rustos-compositor   ← spawned by init as PID 2
#
# Usage: make install DESTDIR=path/to/initramfs/root
DESTDIR ?= $(BUILD_DIR)/rootfs
install: all
	mkdir -p $(DESTDIR)/bin $(DESTDIR)/usr/bin
	cp $(BUILD_DIR)/init                $(DESTDIR)/init
	cp $(BUILD_DIR)/hello               $(DESTDIR)/bin/hello
	cp $(BUILD_DIR)/smoke               $(DESTDIR)/bin/smoke
	cp $(BUILD_DIR)/rustos-compositor   $(DESTDIR)/usr/bin/rustos-compositor

clean:
	rm -rf build/
