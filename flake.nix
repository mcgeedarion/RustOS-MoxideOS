{
  description = "rustos — Rust bare-metal OS (x86_64 + RISC-V + ARM64)";

  # IMPORTANT: keep the nightly date here in sync with:
  #   rust-toolchain.toml  (channel = "nightly-YYYY-MM-DD")
  #   Dockerfile           (ARG NIGHTLY_DATE=YYYY-MM-DD)
  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url    = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rustToolchain = pkgs.rust-bin.nightly."2025-05-15".default.override {
          extensions = [
            "rust-src"            # required by -Z build-std
            "llvm-tools-preview"  # cargo-objcopy / llvm-strip
            "rustfmt"
            "clippy"
          ];
          targets = [
            "riscv64gc-unknown-none-elf"
            "x86_64-unknown-none"
            # riscv64-uefi.json and aarch64-uefi-loader.json are custom JSON targets; not rustup targets.
          ];
        };

        # ---------------------------------------------------------------------------
        # Per-architecture OVMF firmware
        #
        # RISC-V UEFI and x86_64 UEFI require different EDK2 firmware blobs.
        # Mixing them causes silent boot failures (wrong arch, wrong SEC phase).
        #
        # ovmfRiscV  — EDK2 built for RISC-V 64; exposed as RustosOvmfRiscV64.fd
        # ovmfX86_64 — standard OVMF for x86_64;  exposed as OVMF.fd
        # ---------------------------------------------------------------------------
        ovmfRiscV = pkgs.OVMF.override {
          # nixpkgs builds edk2-riscv64 for the riscv64 UEFI target.
          # The resulting package exposes the firmware at $out/FV/RUSTOS_RISCV64.fd
          # (or the upstream name RustosOvmfRiscV64.fd depending on nixpkgs version).
          arches = [ "RISCV64" ];
        };

        ovmfX86_64 = pkgs.OVMF.override {
          arches = [ "X64" ];
        };

        # ---------------------------------------------------------------------------
        # Native build / dev tools
        # ---------------------------------------------------------------------------
        nativeDeps = with pkgs; [
          clang_18
          lld_18
          nasm
          pkgsCross.riscv64-embedded.buildPackages.binutils
          qemu

          # ---- per-arch OVMF (replaces the previous single ovmf entry) -----------
          ovmfRiscV
          ovmfX86_64

          git
          gnumake
          python3

          # ---- newly added -------------------------------------------------------

          # cargo-binutils: rust-objdump, rust-nm, rust-size, rust-objcopy
          # Wraps LLVM tools so they respect the active Rust toolchain target.
          cargo-binutils

          # gdb-multiarch: single GDB binary with support for both x86_64 and
          # RISC-V. Used with QEMU's -s -S flags for kernel source-level debugging.
          gdb-multiarch

          # mdbook: renders docs/ (Markdown) into a browseable HTML book.
          # Run:  mdbook serve docs/
          mdbook

          # nixpkgs-fmt: canonical Nix formatter; enables `nix fmt` on this flake.
          nixpkgs-fmt
        ];

      in {
        # ---------------------------------------------------------------------------
        # Dev shell — `nix develop`
        # ---------------------------------------------------------------------------
        devShells.default = pkgs.mkShell {
          name = "rustos-dev";

          buildInputs = [ rustToolchain ] ++ nativeDeps;

          shellHook = ''
            export CARGO_TERM_COLOR=always
            export CARGO_INCREMENTAL=0

            # RISC-V bare-metal assembler / archiver (from binutils cross toolchain)
            export RISCV_AS=$(which riscv64-unknown-elf-as 2>/dev/null || echo "")
            export RISCV_AR=$(which riscv64-unknown-elf-ar 2>/dev/null || echo "")

            # OVMF firmware paths — consumed by run_qemu_*.sh and xtask
            export OVMF_RISCV=${ovmfRiscV}/FV/RUSTOS_RISCV64.fd
            export OVMF_X86_64=${ovmfX86_64}/FV/OVMF.fd

            echo ""
            echo " rustos dev shell — $(rustc --version)"
            echo ""
            echo "  Build (RISC-V UEFI): cargo build"
            echo "  Build (RISC-V SBI):  cargo build --target riscv64gc-unknown-none-elf --no-default-features"
            echo "                         -Z build-std=core,alloc,compiler_builtins"
            echo "                         -Z build-std-features=compiler-builtins-mem"
            echo "  Build (x86_64):      cargo build --target x86_64-unknown-none --no-default-features"
            echo "  Build (ARM64 UEFI):  cargo build --target targets/aarch64-uefi-loader.json"
            echo "                         -Z build-std=core,alloc,compiler_builtins"
            echo "                         -Z build-std-features=compiler-builtins-mem"
            echo "  Run QEMU:            ./run_qemu_x86_64.sh"
            echo "  Run QEMU (RISC-V):   ./run_qemu_riscv.sh"
            echo "  Debug (GDB):         qemu-system-x86_64 -s -S ... then gdb-multiarch"
            echo "  Inspect binary:      rust-objdump -d target/.../rustos"
            echo "  Kernel docs:         mdbook serve docs/"
            echo "  Format this flake:   nixpkgs-fmt flake.nix"
            echo ""
          '';
        };

        # ---------------------------------------------------------------------------
        # Packages
        # ---------------------------------------------------------------------------

        # `nix build` — RISC-V UEFI image (default, unchanged behaviour)
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname   = "rustos-riscv-uefi";
          version = "0.2.0";
          src     = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ rustToolchain ] ++ nativeDeps;

          buildPhase = ''
            cargo build --release \
              --target riscv64-uefi.json \
              --features uefi_boot \
              -Z build-std=core,alloc,compiler_builtins \
              -Z build-std-features=compiler-builtins-mem
          '';

          installPhase = ''
            mkdir -p $out/boot
            cp target/riscv64-uefi/release/rustos.efi $out/boot/rustos-riscv.efi

            # Embed the correct OVMF blob alongside the image so run scripts
            # have a single store path to reference.
            cp ${ovmfRiscV}/FV/RUSTOS_RISCV64.fd $out/boot/OVMF_RISCV64.fd
          '';

          doCheck = false;
        };

        # `nix build .#x86_64-uefi` — x86_64 UEFI image
        packages.x86_64-uefi = pkgs.rustPlatform.buildRustPackage {
          pname   = "rustos-x86_64-uefi";
          version = "0.2.0";
          src     = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ rustToolchain ] ++ nativeDeps;

          buildPhase = ''
            cargo build --release \
              --target x86_64-unknown-none \
              --no-default-features \
              --features uefi_boot \
              -Z build-std=core,alloc,compiler_builtins \
              -Z build-std-features=compiler-builtins-mem
          '';

          installPhase = ''
            mkdir -p $out/boot
            cp target/x86_64-unknown-none/release/rustos.efi $out/boot/rustos-x86_64.efi

            # Embed the correct OVMF blob alongside the image.
            cp ${ovmfX86_64}/FV/OVMF.fd $out/boot/OVMF_X86_64.fd
          '';

          doCheck = false;
        };

        # `nix build .#riscv-sbi` — RISC-V SBI (no UEFI, raw ELF for QEMU/virt)
        packages.riscv-sbi = pkgs.rustPlatform.buildRustPackage {
          pname   = "rustos-riscv-sbi";
          version = "0.2.0";
          src     = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ rustToolchain ] ++ nativeDeps;

          buildPhase = ''
            cargo build --release \
              --target riscv64gc-unknown-none-elf \
              --no-default-features \
              -Z build-std=core,alloc,compiler_builtins \
              -Z build-std-features=compiler-builtins-mem
          '';

          installPhase = ''
            mkdir -p $out/boot
            cp target/riscv64gc-unknown-none-elf/release/rustos $out/boot/rustos-riscv-sbi.elf
          '';

          doCheck = false;
        };

      }
    );
}
