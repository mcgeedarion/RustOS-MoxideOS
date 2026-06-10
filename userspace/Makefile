# userspace/Makefile
# Builds all userspace C programs as static musl-libc ELF64 binaries.
#
# Prerequisites (install once):
#   x86_64:  apt install musl-tools   # provides musl-gcc
#   RISC-V:  build musl from source targeting riscv64-linux-musl
#            or: apt install gcc-riscv64-linux-gnu musl-dev
#   AArch64: build musl from source targeting aarch64-linux-musl
#            or install/provide aarch64-linux-musl-gcc on PATH
#
# Usage:
#   make               # build x86_64 binaries (default)
#   make ARCH=riscv64  # build RISC-V binaries
#   make ARCH=aarch64  # build AArch64 binaries
#   make help          # show available targets
#
# Output layout (matches build_initramfs.sh staging expectations):
#   build/<arch>/init               → staged as /init        (PID 1)
#   build/<arch>/hello              → staged as /bin/hello
#   build/<arch>/rustos-compositor  → staged as /usr/bin/rustos-compositor
#   build/<arch>/smoke              → staged as /bin/smoke   (QEMU smoke test)
#   build/<arch>/kmtest             → staged as /bin/kmtest  (kernel test runner)

ARCH       ?= x86_64
BUILD_DIR  := build/$(ARCH)

COMMON_CFLAGS := -static -O2 -Wall -Wextra -std=c11

ifeq ($(ARCH),x86_64)
  CC           := musl-gcc
  ARCH_CFLAGS  := -ffreestanding
else ifeq ($(ARCH),riscv64)
  CC           := riscv64-linux-musl-gcc
  ARCH_CFLAGS  := -march=rv64gc -mabi=lp64d
else ifeq ($(ARCH),aarch64)
  CC           := aarch64-linux-musl-gcc
  ARCH_CFLAGS  := -march=armv8-a
else
  $(error Unsupported ARCH=$(ARCH). Use x86_64, riscv64, or aarch64)
endif

CFLAGS := $(COMMON_CFLAGS) $(ARCH_CFLAGS) -fno-stack-protector

# Wayland compositor requires special CFLAGS for security and compatibility.
# See wayland target comments below for detailed rationale.
WAYLAND_CFLAGS := $(COMMON_CFLAGS) $(ARCH_CFLAGS) -D_GNU_SOURCE -fstack-protector-strong

# List every subdirectory that contains a C program here.
PROGRAMS := init hello smoke kmtest wayland

.PHONY: all clean install help check-tools $(PROGRAMS)

# ============================================================================
# Default target and tool validation
# ============================================================================

all: check-tools $(PROGRAMS)

help:
	@echo "RustOS Userspace Build System"
	@echo ""
	@echo "Usage: make [ARCH=x86_64|riscv64|aarch64] [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  all      - Build all userspace binaries (default)"
	@echo "  install  - Install binaries to DESTDIR (default: build/<arch>/rootfs)"
	@echo "  clean    - Remove all build artifacts"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make                              # Build x86_64 binaries"
	@echo "  make ARCH=riscv64                 # Build RISC-V binaries"
	@echo "  make ARCH=aarch64                 # Build AArch64 binaries"
	@echo "  make install DESTDIR=/tmp/rootfs  # Install to custom location"

check-tools:
	@command -v $(CC) >/dev/null 2>&1 || { \
		echo "Error: $(CC) not found. Please install the required toolchain."; \
		echo "For x86_64: apt install musl-tools"; \
		echo "For RISC-V: Build musl from source or apt install gcc-riscv64-linux-gnu musl-dev"; \
		echo "For AArch64: Build musl from source targeting aarch64-linux-musl or provide aarch64-linux-musl-gcc"; \
		exit 1; \
	}

# ============================================================================
# Build directory setup
# ============================================================================

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ============================================================================
# Program build rules (generic pattern + special cases)
# ============================================================================

# Standard build rule for simple programs
$(BUILD_DIR)/init: init/init.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD_DIR)/hello: hello/hello.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Minimal QEMU smoke binary:
#   - prints a well-known marker to the serial console
#   - returns 0 on success
#   - can be extended later with basic invariants (e.g. /proc/1 exists).
$(BUILD_DIR)/smoke: smoke/smoke.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Kernel test runner:
#   - calls SYS_KMTEST_LIST to discover registered tests
#   - calls SYS_KMTEST_RUN per test (or a named subset from argv)
#   - exits non-zero on any failure, making it CI-friendly
#   - _GNU_SOURCE required for snprintf in strict -std=c11 mode with musl
$(BUILD_DIR)/kmtest: kmtest/kmtest.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o $@	$<

# The Wayland compositor is a privileged userspace process.
# It is installed as /usr/bin/rustos-compositor in the initramfs.
# The kernel spawns it as PID 2 via execve() after init (PID 1) starts.
#
# CFLAGS notes:
#   -fstack-protector-strong  — re-enabled (unlike other binaries); the
#     compositor handles untrusted data from Wayland clients.
#   _GNU_SOURCE               — required for epoll_create1, SOCK_CLOEXEC,
#     accept4, and the seccomp BPF headers.
$(BUILD_DIR)/rustos-compositor: wayland/compositor.c | $(BUILD_DIR)
	$(CC) $(WAYLAND_CFLAGS) -o $@ $<

# ============================================================================
# Convenience targets (map to actual binaries)
# ============================================================================

init: $(BUILD_DIR)/init

hello: $(BUILD_DIR)/hello

smoke: $(BUILD_DIR)/smoke

kmtest: $(BUILD_DIR)/kmtest

wayland: $(BUILD_DIR)/rustos-compositor

# ============================================================================
# Installation and cleanup
# ============================================================================

# Copies built binaries into a staging rootfs tree whose layout matches
# what build_initramfs.sh expects when it packs the CPIO archive:
#
#   DESTDIR/
#     init                        ← exec'd directly as PID 1 by the kernel
#     bin/hello
#     bin/smoke                   ← small QEMU smoke-test helper
#     bin/kmtest                  ← kernel test runner
#     usr/bin/rustos-compositor   ← spawned by init as PID 2
#
# Usage: make install DESTDIR=path/to/initramfs/root
DESTDIR ?= $(BUILD_DIR)/rootfs
install: all
	mkdir -p $(DESTDIR)/bin $(DESTDIR)/usr/bin
	cp $(BUILD_DIR)/init                $(DESTDIR)/init
	cp $(BUILD_DIR)/hello               $(DESTDIR)/bin/hello
	cp $(BUILD_DIR)/smoke               $(DESTDIR)/bin/smoke
	cp $(BUILD_DIR)/kmtest              $(DESTDIR)/bin/kmtest
	cp $(BUILD_DIR)/rustos-compositor   $(DESTDIR)/usr/bin/rustos-compositor

clean:
	rm -rf build/
