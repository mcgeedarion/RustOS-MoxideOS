# userspace/shell/Makefile
#
# Build the minimal rustos shell.  Links against either:
#   a) musl-libc (preferred, full POSIX)  — set MUSL=1
#   b) the libc shim (shim.c)             — default, -nostdlib
#
# Usage:
#   make              - Build the shell
#   make clean        - Remove build artifacts
#   make install      - Install shell to $(INSTALL_DIR)
#   make help         - Show this help
#
# Options:
#   MUSL=1            - Use musl-libc instead of shim
#   ARCH=riscv64      - Target architecture (x86_64 or riscv64)
#   V=1               - Verbose build output
#   INSTALL_DIR=...   - Installation directory (default: /usr/local/bin)

# ============================================================================
# Variable Definitions
# ============================================================================

ARCH              ??= x86_64
MUSL              ??= 0
SHIM_DIR          := ../libc-shim
OUT               := rustos-shell
INSTALL_DIR       ??= /usr/local/bin

# Verbose output control
V                 ?= 0
ifeq ($(V),0)
  QUIET           := @
  ECHO            := @echo
else
  QUIET           :=
  ECHO            := @true
endif

SRCS              := shell.c
OBJS              := $(SRCS:.c=.o)
DEPS              := $(SRCS:.c=.d)

# ============================================================================
# Compiler Configuration
# ============================================================================

ifeq ($(MUSL),1)
  CC              ??= musl-gcc
  CFLAGS          := -std=c11 -static -O2 -Wall -Wextra
  LDFLAGS         := -static
  LINK_TARGET     := MUSL
else
  CC              ??= gcc
  CFLAGS          := -std=c11 -ffreestanding -nostdlib \
                     -fno-stack-protector -fno-builtin \
                     -Wall -Wextra -O2 \
                     -D__rustos_shim__ \
                     -I$(SHIM_DIR)
  LDFLAGS         := -nostdlib -L$(SHIM_DIR) -lshim
  LINK_TARGET     := SHIM
endif

# Architecture-specific flags
ifeq ($(ARCH),x86_64)
  CFLAGS          += -mno-red-zone -mcmodel=small
  ARCH_TARGET     := x86_64
else ifeq ($(ARCH),riscv64)
  CFLAGS          += -march=rv64gc -mabi=lp64d
  ARCH_TARGET     := riscv64
else
  $(error Unsupported architecture: $(ARCH). Use x86_64 or riscv64)
endif

# ============================================================================
# Validation
# ============================================================================

# Check that required compiler exists
$(if $(shell command -v $(CC) 2>/dev/null),,$(error $(CC) not found. Please install the appropriate compiler))

# ============================================================================
# Build Rules
# ============================================================================

.PHONY: all clean install help

all: $(OUT)

$(OUT): $(OBJS)
	$(ECHO) "Linking $@ [$(ARCH_TARGET)/$(LINK_TARGET)]..."
	$(QUIET)$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(ECHO) "Compiling $<..."
	$(QUIET)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Include dependency files (will be generated on first build)
-include $(DEPS)

# ============================================================================
# Installation
# ============================================================================

install: $(OUT)
	$(ECHO) "Installing $(OUT) to $(INSTALL_DIR)..."
	$(QUIET)install -D -m 755 $(OUT) $(INSTALL_DIR)/$(OUT)
	@echo "✓ Installation complete: $(INSTALL_DIR)/$(OUT)"

# ============================================================================
# Cleanup
# ============================================================================

clean:
	$(ECHO) "Cleaning build artifacts..."
	$(QUIET)rm -f $(OUT) $(OBJS) $(DEPS)
	@echo "✓ Clean complete"

# ============================================================================
# Help
# ============================================================================

help:
	@echo "=============================================="
	@echo "RustOS Shell Build System"
	@echo "=============================================="
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build $(OUT) (default)"
	@echo "  clean       - Remove build artifacts"
	@echo "  install     - Install to $(INSTALL_DIR)"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  MUSL=1      - Use musl-libc (default: 0)"
	@echo "  ARCH=...    - Target: x86_64 (default) or riscv64"
	@echo "  V=1         - Enable verbose output"
	@echo "  INSTALL_DIR - Installation directory (default: $(INSTALL_DIR))"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build with default settings"
	@echo "  make MUSL=1             # Build with musl-libc"
	@echo "  make ARCH=riscv64 V=1   # Build for RISC-V with verbose output"
	@echo "  make install            # Build and install to system"
	@echo ""
