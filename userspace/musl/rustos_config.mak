# rustos_config.mak — included by the musl Makefile after configure.
#
# Overrides the sysdep layer so musl issues syscalls the way RustOS expects:
#
#   x86_64:  syscall instruction, number in rax, args in rdi rsi rdx r10 r8 r9
#            errno returned as negative value in rax (no errno global for
#            static musl; per-thread errno lives at fs:0x00 in the TCB)
#
#   riscv64: ecall instruction, number in a7, args in a0..a5
#            errno returned as negative value in a0
#
# The kernel side (src/syscall/mod.rs) already follows Linux ABI exactly,
# so no kernel changes are required — only the musl sysdep glue is patched.

# Configuration Validation: Ensure required environment variables are defined
ifndef SYSROOT
$(error SYSROOT must be defined)
endif

ifndef ARCH
$(error ARCH must be defined)
endif

# Normalize SYSROOT path to absolute path
SYSROOT := $(realpath $(SYSROOT))

# Common compiler flags applied to all architectures
COMMON_CFLAGS  := -ffreestanding \
                  -nostdinc \
                  -isystem $(SYSROOT)/$(ARCH)/include \
                  -D__rustos__=1 \
                  -DMUSL_VDSO_CLOCK=1

# Architecture-specific configuration
ifeq ($(ARCH),x86_64)
  SYSDEP_ARCH    := x86_64
  # Note: x86_64 requires assembly implementations of longjmp; 
  # riscv64 uses C implementations instead
  SYSDEP_FILES   := syscall.s setjmp.s longjmp.s clone.s
  EXTRA_CFLAGS   := -mno-red-zone -mcmodel=small
else ifeq ($(ARCH),riscv64)
  SYSDEP_ARCH    := riscv64
  # Note: riscv64 implements longjmp as C code, x86_64 requires assembly
  SYSDEP_FILES   := syscall.s setjmp.s clone.s
  EXTRA_CFLAGS   := -march=rv64gc -mabi=lp64d
else
  $(error Unsupported ARCH=$(ARCH))
endif

# musl build variables consumed by the upstream Makefile.
AR             := llvm-ar
RANLIB         := llvm-ranlib
CFLAGS         += $(EXTRA_CFLAGS) $(COMMON_CFLAGS)

# Optional: Enable verbose output for debugging builds
ifdef VERBOSE
$(info Building musl for $(ARCH) at $(SYSROOT))
$(info SYSDEP_FILES: $(SYSDEP_FILES))
$(info CFLAGS: $(CFLAGS))
endif

# Install step: copy static archive and headers.
install:
	$(MAKE)
	mkdir -p $(SYSROOT)/$(ARCH)/lib
	cp lib/libc.a $(SYSROOT)/$(ARCH)/lib/libc.a
	ln -sf libc.a $(SYSROOT)/$(ARCH)/lib/libmusl.a
	$(MAKE) install-headers DESTDIR=$(SYSROOT)/$(ARCH)

.PHONY: install
