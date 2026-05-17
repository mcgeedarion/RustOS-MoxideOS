# userspace/libc-shim/Makefile
#
# Build the shim as a static archive (libshim.a) for linking into
# -nostdlib binaries, OR as a thin object file.
#
# Variables (override from the parent Makefile or command line):
#   ARCH       — x86_64 (default) or riscv64
#   CC         — compiler (default: musl-gcc for the static shim)
#   SYSROOT    — path to musl sysroot (optional; not needed for shim-only builds)

ARCH       ?= x86_64
CC         ?= gcc
AR         ?= ar
RANLIB     ?= ranlib

CFLAGS     := -std=c11 -ffreestanding -nostdlib \
               -fno-stack-protector -fno-builtin \
               -Wall -Wextra -O2 \
               -D__rustos_shim__

ifeq ($(ARCH),x86_64)
CFLAGS     += -mno-red-zone -mcmodel=small
else ifeq ($(ARCH),riscv64)
CFLAGS     += -march=rv64gc -mabi=lp64d
else
$(error Unsupported ARCH=$(ARCH))
endif

OBJS       := shim.o
LIB        := libshim.a

all: $(LIB)

shim.o: shim.c shim.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

clean:
	rm -f $(OBJS) $(LIB)

.PHONY: all clean
