# Build musl libc for RustOS
# Targets: x86_64-rustos-musl  riscv64-rustos-musl
#
# Prerequisites (Debian/Ubuntu):
#   apt install musl-tools clang lld python3
#   or: cargo install xargo  (if using xargo for sysroot)
#
# Usage:
#   make help      — show this help message
#   make x86_64    — build libmusl.a + libc.so for x86_64
#   make riscv64   — build for riscv64
#   make all       — both arches
#   make sysroot   — install musl headers into sysroot/<arch>/include/
#   make clean     — remove build artifacts
#   make distclean — remove everything including sysroot

# ──────────────────────────────────────────────────────────────────────────────
# Configuration Variables
# ──────────────────────────────────────────────────────────────────────────────

MUSL_VERSION   ?= 1.2.5
MUSL_SRC       ?= musl-$(MUSL_VERSION)
MUSL_TARBALL   ?= $(MUSL_SRC).tar.gz
MUSL_URL       := https://musl.libc.org/releases/$(MUSL_TARBALL)

# SHA256 checksum for tarball validation (update if MUSL_VERSION changes)
MUSL_SHA256    ?= 

TOPDIR         := $(shell pwd)
SYSROOT        := $(TOPDIR)/sysroot
PATCH_DIR      := $(TOPDIR)/patches

# Build configuration
VERBOSE        ?= 0
JOBS           ?= $(shell nproc 2>/dev/null || echo 4)

# ──────────────────────────────────────────────────────────────────────────────
# Toolchain Configuration
# ──────────────────────────────────────────────────────────────────────────────

X86_CC         ?= clang --target=x86_64-unknown-linux-musl
X86_LD         ?= ld.lld
RV64_CC        ?= clang --target=riscv64-unknown-linux-musl
RV64_LD        ?= ld.lld

# ──────────────────────────────────────────────────────────────────────────────
# Helper functions & rules
# ──────────────────────────────────────────────────────────────────────────────

ifeq ($(VERBOSE),1)
  ECHO = @true
  HIDE = 
else
  ECHO = @echo
  HIDE = @
endif

# ──────────────────────────────────────────────────────────────────────────────
# Download & Patch Rules
# ──────────────────────────────────────────────────────────────────────────────

$(MUSL_TARBALL):
	$(ECHO) "[DOWNLOAD] Fetching musl-$(MUSL_VERSION)..."
	$(HIDE)wget -q $(MUSL_URL) -O $(MUSL_TARBALL)
	$(ECHO) "[VERIFY] Validating tarball checksum..."
	$(HIDE)if [ -n "$(MUSL_SHA256)" ]; then \
		echo "$(MUSL_SHA256)  $(MUSL_TARBALL)" | sha256sum -c -; \
	else \
		echo "[WARN] No MUSL_SHA256 specified, skipping verification"; \
	fi

$(MUSL_SRC)/.patched: $(MUSL_TARBALL)
	$(ECHO) "[EXTRACT] Extracting musl-$(MUSL_VERSION)..."
	$(HIDE)set -e; \
	tar -xzf $(MUSL_TARBALL); \
	if [ -d "$(PATCH_DIR)" ] && [ $$(find $(PATCH_DIR) -name "*.patch" -type f 2>/dev/null | wc -l) -gt 0 ]; then \
		$(ECHO) "[PATCH] Applying patches..."; \
		cd $(MUSL_SRC) && \
		for p in $(PATCH_DIR)/*.patch; do \
			echo "  Applying $$p..."; \
			patch -p1 < $$p || exit 1; \
		done; \
	else \
		$(ECHO) "[PATCH] No patches to apply"; \
	fi
	$(HIDE)touch $@

# ──────────────────────────────────────────────────────────────────────────────
# x86_64 Build Target
# ──────────────────────────────────────────────────────────────────────────────

BUILD_X86 := build-x86_64

x86_64: $(MUSL_SRC)/.patched
	$(ECHO) "[BUILD] x86_64 musl libc..."
	$(HIDE)mkdir -p $(BUILD_X86)
	$(HIDE)cd $(BUILD_X86) && \
	  ../$(MUSL_SRC)/configure \
	    CC="$(X86_CC)" \
	    LDFLAGS="-fuse-ld=lld" \
	    --target=x86_64 \
	    --prefix=$(SYSROOT)/x86_64 \
	    --syslibdir=$(SYSROOT)/x86_64/lib \
	    --disable-shared \
	    $(MUSL_EXTRA_FLAGS) && \
	  $(MAKE) -f $(TOPDIR)/rustos_config.mak ARCH=x86_64 -j$(JOBS) install
	$(ECHO) "[OK] x86_64 build complete"

# ──────────────────────────────────────────────────────────────────────────────
# riscv64 Build Target
# ──────────────────────────────────────────────────────────────────────────────

BUILD_RV64 := build-riscv64

riscv64: $(MUSL_SRC)/.patched
	$(ECHO) "[BUILD] riscv64 musl libc..."
	$(HIDE)mkdir -p $(BUILD_RV64)
	$(HIDE)cd $(BUILD_RV64) && \
	  ../$(MUSL_SRC)/configure \
	    CC="$(RV64_CC)" \
	    LDFLAGS="-fuse-ld=lld" \
	    --target=riscv64 \
	    --prefix=$(SYSROOT)/riscv64 \
	    --syslibdir=$(SYSROOT)/riscv64/lib \
	    --disable-shared \
	    $(MUSL_EXTRA_FLAGS) && \
	  $(MAKE) -f $(TOPDIR)/rustos_config.mak ARCH=riscv64 -j$(JOBS) install
	$(ECHO) "[OK] riscv64 build complete"

# ──────────────────────────────────────────────────────────────────────────────
# Aggregate Targets
# ──────────────────────────────────────────────────────────────────────────────

all: x86_64 riscv64
	$(ECHO) "[OK] All architectures built successfully"

# ──────────────────────────────────────────────────────────────────────────────
# Sysroot Installation
# ──────────────────────────────────────────────────────────────────────────────

# Copies musl public headers from the build tree into sysroot/<arch>/include/rustos/
# so the kernel and other userspace programs can #include <rustos/...>.
#
# The source is the per-arch build tree ($(BUILD_X86)/include, $(BUILD_RV64)/include),
# NOT $(TOPDIR)/sysroot/include (which is the destination — copying a directory into
# itself would produce an infinite recursive tree on some cp implementations).
#
sysroot: all
	$(ECHO) "[INSTALL] Installing musl headers into sysroot..."
	$(HIDE)mkdir -p $(SYSROOT)/x86_64/include/rustos
	$(HIDE)mkdir -p $(SYSROOT)/riscv64/include/rustos
	$(HIDE)cp -r $(BUILD_X86)/include/.  $(SYSROOT)/x86_64/include/rustos/
	$(HIDE)cp -r $(BUILD_RV64)/include/. $(SYSROOT)/riscv64/include/rustos/
	$(ECHO) "[OK] Headers installed"

# ──────────────────────────────────────────────────────────────────────────────
# Cleanup Targets
# ──────────────────────────────────────────────────────────────────────────────

clean:
	$(ECHO) "[CLEAN] Removing build artifacts..."
	$(HIDE)rm -rf $(BUILD_X86) $(BUILD_RV64) $(MUSL_SRC) $(MUSL_TARBALL)
	$(ECHO) "[OK] Build artifacts removed"

distclean: clean
	$(ECHO) "[DISTCLEAN] Removing sysroot..."
	$(HIDE)rm -rf $(SYSROOT)
	$(ECHO) "[OK] Sysroot removed"

# ──────────────────────────────────────────────────────────────────────────────
# Help Target
# ──────────────────────────────────────────────────────────────────────────────

help:
	@echo "RustOS musl libc Build System"
	@echo ""
	@echo "Usage: make [target] [VARIABLE=value]"
	@echo ""
	@echo "Targets:"
	@echo "  help               — Display this help message"
	@echo "  x86_64             — Build musl for x86_64 architecture"
	@echo "  riscv64            — Build musl for riscv64 architecture"
	@echo "  all                — Build for all architectures (default)"
	@echo "  sysroot            — Install headers into sysroot/<arch>/include/"
	@echo "  clean              — Remove build directories and source"
	@echo "  distclean          — Remove everything including sysroot"
	@echo ""
	@echo "Variables:"
	@echo "  MUSL_VERSION       — musl version (default: 1.2.5)"
	@echo "  VERBOSE            — Verbose output (default: 0, set to 1 for details)"
	@echo "  JOBS               — Number of parallel build jobs (default: auto-detect)"
	@echo "  MUSL_SHA256        — SHA256 checksum for tarball validation"
	@echo "  MUSL_EXTRA_FLAGS   — Additional configure flags"
	@echo ""
	@echo "Prerequisites:"
	@echo "  Debian/Ubuntu: apt install musl-tools clang lld python3"
	@echo ""
	@echo "Examples:"
	@echo "  make all"
	@echo "  make sysroot"
	@echo "  make VERBOSE=1 x86_64"
	@echo "  make JOBS=8 all"
	@echo "  make distclean"

# ──────────────────────────────────────────────────────────────────────────────
# Declare phony targets
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: all x86_64 riscv64 sysroot clean distclean help
