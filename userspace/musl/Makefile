# Build musl libc for RustOS
# Targets: x86_64-rustos-musl  riscv64-rustos-musl
#
# Prerequisites (Debian/Ubuntu):
#   apt install musl-tools clang lld python3
#   or: cargo install xargo  (if using xargo for sysroot)
#
# Usage:
#   make x86_64    — build libmusl.a + libc.so for x86_64
#   make riscv64   — build for riscv64
#   make all       — both arches
#   make sysroot   — install headers + libs into sysroot/
#   make clean

MUSL_VERSION   ?= 1.2.5
MUSL_SRC       ?= musl-$(MUSL_VERSION)
MUSL_TARBALL   ?= $(MUSL_SRC).tar.gz
MUSL_URL       := https://musl.libc.org/releases/$(MUSL_TARBALL)

TOPDIR         := $(shell pwd)
SYSROOT        := $(TOPDIR)/sysroot
PATCH_DIR      := $(TOPDIR)/patches

# ── Toolchain ──────────────────────────────────────────────────────────────
X86_CC         ?= clang --target=x86_64-unknown-linux-musl
X86_LD         ?= ld.lld
RV64_CC        ?= clang --target=riscv64-unknown-linux-musl
RV64_LD        ?= ld.lld

# ── Fetch & patch ──────────────────────────────────────────────────────────
$(MUSL_SRC)/.patched: $(MUSL_TARBALL)
	tar -xzf $(MUSL_TARBALL)
	cd $(MUSL_SRC) && \
	  for p in $(PATCH_DIR)/*.patch; do patch -p1 < $$p; done
	touch $@

$(MUSL_TARBALL):
	wget -q $(MUSL_URL) -O $(MUSL_TARBALL)

# ── x86_64 build ───────────────────────────────────────────────────────────
BUILD_X86      := build-x86_64

x86_64: $(MUSL_SRC)/.patched
	mkdir -p $(BUILD_X86)
	cd $(BUILD_X86) && \
	  ../$(MUSL_SRC)/configure \
	    CC="$(X86_CC)" \
	    LDFLAGS="-fuse-ld=lld" \
	    --target=x86_64 \
	    --prefix=$(SYSROOT)/x86_64 \
	    --syslibdir=$(SYSROOT)/x86_64/lib \
	    --disable-shared \
	    $(MUSL_EXTRA_FLAGS) && \
	  $(MAKE) -f $(TOPDIR)/rustos_config.mak ARCH=x86_64 install

# ── riscv64 build ──────────────────────────────────────────────────────────
BUILD_RV64     := build-riscv64

riscv64: $(MUSL_SRC)/.patched
	mkdir -p $(BUILD_RV64)
	cd $(BUILD_RV64) && \
	  ../$(MUSL_SRC)/configure \
	    CC="$(RV64_CC)" \
	    LDFLAGS="-fuse-ld=lld" \
	    --target=riscv64 \
	    --prefix=$(SYSROOT)/riscv64 \
	    --syslibdir=$(SYSROOT)/riscv64/lib \
	    --disable-shared \
	    $(MUSL_EXTRA_FLAGS) && \
	  $(MAKE) -f $(TOPDIR)/rustos_config.mak ARCH=riscv64 install

all: x86_64 riscv64

# ── Install headers into kernel sysroot ────────────────────────────────────
sysroot: all
	cp -r $(TOPDIR)/sysroot/include $(SYSROOT)/x86_64/include/rustos
	cp -r $(TOPDIR)/sysroot/include $(SYSROOT)/riscv64/include/rustos

clean:
	rm -rf $(BUILD_X86) $(BUILD_RV64) $(MUSL_SRC) $(MUSL_TARBALL)

.PHONY: all x86_64 riscv64 sysroot clean
