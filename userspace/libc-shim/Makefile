# userspace/libc-shim/Makefile
#
# Build the shim as a static archive (libshim.a) for linking into
# -nostdlib binaries, OR as a thin object file.
#
# Variables (override from the parent Makefile or command line):
#   ARCH       — x86_64 (default) or riscv64
#   CC         — compiler (default: musl-gcc for the static shim)
#   SYSROOT    — path to musl sysroot (optional; not needed for shim-only builds)
#   V          — verbose output (0=quiet, 1=verbose; default: 0)
#   PREFIX     — installation prefix (default: /usr/local)

# ============================================================================
# Configuration
# ============================================================================

ARCH       ?= x86_64
CC         ?= gcc
AR         ?= ar
RANLIB     ?= ranlib
V          ?= 0
PREFIX     ?= /usr/local
LIBDIR     ?= $(PREFIX)/lib
INCDIR     ?= $(PREFIX)/include

# ============================================================================
# Compiler Validation
# ============================================================================

ifeq ($(shell which $(CC) 2>/dev/null),)
$(error Compiler "$(CC)" not found. Set CC=your-compiler)
endif

# ============================================================================
# Flags
# ============================================================================

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

# ============================================================================
# Build Output Control (Quiet vs Verbose)
# ============================================================================

ifeq ($(V),0)
    QUIET := @
    MSG   := @echo
else
    QUIET :=
    MSG   := @true
endif

# ============================================================================
# Targets and Dependencies
# ============================================================================

OBJS       := shim.o
DEPS       := shim.d
LIB        := libshim.a

# ============================================================================
# Rules
# ============================================================================

.PHONY: all clean install help

all: build-check $(LIB)

build-check:
	$(MSG) "Building libshim for $(ARCH) with $(CC)..."

shim.o: shim.c shim.h
	$(MSG) "CC  $@"
	$(QUIET)$(CC) $(CFLAGS) -c -o $@ $<
	$(MSG) "Generating dependencies for $<"
	$(QUIET)$(CC) $(CFLAGS) -MM $< > shim.d

$(LIB): $(OBJS) | build-check
	$(MSG) "AR  $@"
	$(QUIET)$(AR) rcs $@ $^
	$(MSG) "RANLIB $@"
	$(QUIET)$(RANLIB) $@

clean:
	$(MSG) "Cleaning build artifacts..."
	$(QUIET)rm -f $(OBJS) $(LIB) $(DEPS)

install: $(LIB)
	$(MSG) "Installing $(LIB) to $(LIBDIR)..."
	$(QUIET)install -D -m 644 $(LIB) $(LIBDIR)/$(LIB)
	$(MSG) "Installing shim.h to $(INCDIR)..."
	$(QUIET)install -D -m 644 shim.h $(INCDIR)/shim.h

help:
	@echo "=== libshim Makefile ==="
	@echo ""
	@echo "Usage: make [ARCH=x86_64|riscv64] [CC=compiler] [V=0|1]"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build $(LIB) (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  install - Install library and headers to $(PREFIX)"
	@echo "  help    - Display this help message"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH    - Target architecture (x86_64, riscv64) [$(ARCH)]"
	@echo "  CC      - C compiler [$(CC)]"
	@echo "  AR      - Archive tool [$(AR)]"
	@echo "  RANLIB  - Archive index tool [$(RANLIB)]"
	@echo "  V       - Verbose output (0=quiet, 1=verbose) [$(V)]"
	@echo "  PREFIX  - Installation prefix [$(PREFIX)]"
	@echo ""
	@echo "Examples:"
	@echo "  make                          # Build for x86_64"
	@echo "  make ARCH=riscv64             # Build for riscv64"
	@echo "  make V=1                      # Verbose build"
	@echo "  make install PREFIX=$$HOME    # Install to home directory"
	@echo ""

# ============================================================================
# Dependencies
# ============================================================================

-include $(DEPS)
