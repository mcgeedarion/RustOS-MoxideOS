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
PROGRAMS := init hello wayland

.PHONY: all clean install $(PROGRAMS)

all: $(PROGRAMS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

init: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/init init/init.c

hello: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/hello hello/hello.c

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

# Install all built binaries into a staging rootfs tree.
# Usage: make install DESTDIR=path/to/initramfs/root
DESTDIR ?= $(BUILD_DIR)/rootfs
install: all
	mkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/bin $(DESTDIR)/sbin
	cp $(BUILD_DIR)/init                $(DESTDIR)/sbin/init
	cp $(BUILD_DIR)/hello               $(DESTDIR)/usr/bin/hello
	cp $(BUILD_DIR)/rustos-compositor   $(DESTDIR)/usr/bin/rustos-compositor

clean:
	rm -rf build/
