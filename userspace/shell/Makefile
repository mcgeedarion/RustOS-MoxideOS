# userspace/shell/Makefile
#
# Build the minimal rustos shell.  Links against either:
#   a) musl-libc (preferred, full POSIX)  — set MUSL=1
#   b) the libc shim (shim.c)             — default, -nostdlib

ARCH       ?= x86_64
MUSL       ?= 0
SHIM_DIR   := ../libc-shim

ifeq ($(MUSL),1)
CC         ?= musl-gcc
CFLAGS     := -std=c11 -static -O2 -Wall -Wextra
LDFLAGS    := -static
SRCS       := shell.c
else
CC         ?= gcc
CFLAGS     := -std=c11 -ffreestanding -nostdlib \
               -fno-stack-protector -fno-builtin \
               -Wall -Wextra -O2 \
               -D__rustos_shim__ \
               -I$(SHIM_DIR)
LDFLAGS    := -nostdlib -L$(SHIM_DIR) -lshim
SRCS       := shell.c
endif

ifeq ($(ARCH),x86_64)
CFLAGS     += -mno-red-zone -mcmodel=small
else ifeq ($(ARCH),riscv64)
CFLAGS     += -march=rv64gc -mabi=lp64d
endif

OUT        := rustos-shell

all: $(OUT)

$(OUT): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OUT)

.PHONY: all clean
