{
  description = "rustos — Rust bare-metal OS (x86_64 + RISC-V)";

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
            # riscv64-uefi.json is a custom JSON target; not a rustup target.
          ];
        };

        nativeDeps = with pkgs; [
          clang_18
          lld_18
          nasm
          pkgsCross.riscv64-embedded.buildPackages.binutils
          qemu
          ovmf
          git
          gnumake
          python3
        ];

      in {
        # Usage:
        #   nix develop                        # enter dev shell
        #   nix develop --command cargo build  # build without entering
        devShells.default = pkgs.mkShell {
          name = "rustos-dev";

          buildInputs  = [ rustToolchain ] ++ nativeDeps;

          shellHook = ''
            export CARGO_TERM_COLOR=always
            export CARGO_INCREMENTAL=0
            export RISCV_AS=$(which riscv64-unknown-elf-as 2>/dev/null || echo "")
            export RISCV_AR=$(which riscv64-unknown-elf-ar 2>/dev/null || echo "")

            echo ""
            echo " rustos dev shell — $(rustc --version)"
            echo ""
            echo "  Build (RISC-V UEFI): cargo build"
            echo "  Build (RISC-V SBI):  cargo build --target riscv64gc-unknown-none-elf --no-default-features"
            echo "                         -Z build-std=core,alloc,compiler_builtins"
            echo "                         -Z build-std-features=compiler-builtins-mem"
            echo "  Build (x86_64):      cargo build --target x86_64-unknown-none --no-default-features"
            echo "                         -Z build-std=core,alloc,compiler_builtins"
            echo "                         -Z build-std-features=compiler-builtins-mem"
            echo "  Run QEMU:            ./run_qemu.sh"
            echo "  Run QEMU (RISC-V):   ./run_qemu_riscv.sh"
            echo ""
          '';
        };

        # Allows: nix build
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname   = "rustos";
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
            cp target/riscv64-uefi/release/rustos.efi $out/boot/
          '';

          doCheck = false;
        };
      }
    );
}
