# userspace/Makefile
# Builds all userspace C programs as static musl-libc ELF64 binaries.
#
# Prerequisites (install once):
#   x86_64:  apt install musl-tools   # provides musl-gcc
#   RISC-V:  build musl from source targeting riscv64-linux-musl
#            or: apt install gcc-riscv64-linux-gnu musl-dev
#
# Usage:
#   make           # build x86_64 binaries (default)
#   make ARCH=riscv64  # build RISC-V binaries

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
PROGRAMS := init hello

.PHONY: all clean $(PROGRAMS)

all: $(PROGRAMS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

init: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/init init/init.c
	hello: $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/hello hello/hello.c

clean:
	rm -rf build/
