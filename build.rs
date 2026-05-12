use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    // ── RISC-V: assemble uentry trampoline ────────────────────────────────────
    if target_arch == "riscv64" {
        let asm_src = "src/arch/riscv64/uentry.S";
        println!("cargo:rerun-if-changed={asm_src}");
        let obj = out.join("uentry_riscv64.o");
        let status = Command::new("riscv64-unknown-elf-as")
            .args(["-march=rv64gc", "-mabi=lp64d", "-o"])
            .arg(&obj)
            .arg(asm_src)
            .status();
        match status {
            Ok(s) if s.success() => {
                let lib = out.join("libuentry_riscv64.a");
                Command::new("riscv64-unknown-elf-ar")
                    .args(["crs"])
                    .arg(&lib)
                    .arg(&obj)
                    .status()
                    .expect("ar failed");
                println!("cargo:rustc-link-search=native={}", out.display());
                println!("cargo:rustc-link-lib=static=uentry_riscv64");
            }
            _ => {
                println!("cargo:warning=riscv64-unknown-elf-as not found; skipping uentry assembly");
            }
        }
    }

    // ── x86_64 UEFI boot: produce a PE32+ .efi image ─────────────────────────
    //
    // When feature "uefi_boot" is active (the default), we post-process the
    // ELF kernel binary into a PE32+ UEFI application using llvm-objcopy.
    // The output is placed at:
    //   target/esp/EFI/BOOT/BOOTX64.EFI
    //
    // That directory tree is a valid EFI System Partition (ESP) FAT image
    // root, usable directly by OVMF in QEMU or by dd-copying to a real
    // FAT-formatted EFI partition.
    //
    // The ELF → PE conversion uses llvm-objcopy's --target=efi-app-x86_64
    // mode, which:
    //   • rewrites the ELF header to a PE32+ COFF header,
    //   • sets the PE subsystem to EFI_APPLICATION (10),
    //   • preserves all sections (.text, .rodata, .data, .bss).
    //
    // Requires: llvm-tools-preview component (installed via rust-toolchain.toml)
    //   rustup component add llvm-tools-preview
    //
    // If llvm-objcopy is not found we emit a cargo warning and skip the step
    // so that CI environments without llvm-tools still compile cleanly.

    let uefi_boot = std::env::var("CARGO_FEATURE_UEFI_BOOT").is_ok();
    if target_arch == "x86_64" && uefi_boot {
        println!("cargo:rerun-if-changed=target/x86_64-unknown-none/debug/rustos");
        println!("cargo:rerun-if-changed=target/x86_64-unknown-none/release/rustos");

        // Determine profile: release if OUT_DIR contains "/release/"
        let out_str = out.to_string_lossy();
        let profile = if out_str.contains("/release/") { "release" } else { "debug" };
        let elf_path = format!("target/x86_64-unknown-none/{}/rustos", profile);
        let esp_dir  = PathBuf::from("target/esp/EFI/BOOT");
        let efi_path = esp_dir.join("BOOTX64.EFI");

        // Create ESP directory tree.
        std::fs::create_dir_all(&esp_dir)
            .unwrap_or_else(|e| eprintln!("build.rs: mkdir esp: {e}"));

        // Locate llvm-objcopy via llvm-tools-preview.
        //   rustc --print sysroot  → e.g. ~/.rustup/toolchains/nightly-.../
        //   then look in lib/rustlib/<host>/bin/llvm-objcopy
        let sysroot = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        // Host triple (e.g. x86_64-unknown-linux-gnu)
        let host_triple = Command::new("rustc")
            .args(["-vV"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.starts_with("host:"))
                    .map(|l| l[5..].trim().to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let llvm_objcopy = PathBuf::from(&sysroot)
            .join("lib/rustlib")
            .join(&host_triple)
            .join("bin/llvm-objcopy");

        // Fall back to system llvm-objcopy if llvm-tools path doesn't exist.
        let objcopy_bin = if llvm_objcopy.exists() {
            llvm_objcopy.to_string_lossy().into_owned()
        } else {
            "llvm-objcopy".to_string()
        };

        // Only run if the ELF exists (it won't on the very first build pass
        // where build.rs runs before rustc produces the binary).  A second
        // `cargo build` invocation will always find it.
        if PathBuf::from(&elf_path).exists() {
            let status = Command::new(&objcopy_bin)
                .args([
                    "--target=efi-app-x86_64",
                    "--subsystem=10",    // EFI_APPLICATION
                    &elf_path,
                    efi_path.to_str().unwrap(),
                ])
                .status();
            match status {
                Ok(s) if s.success() => {
                    println!("cargo:warning=UEFI image: {}", efi_path.display());
                }
                Ok(s) => {
                    println!("cargo:warning=llvm-objcopy exited {s}; .efi not produced");
                }
                Err(e) => {
                    println!("cargo:warning=llvm-objcopy not found ({e}); install llvm-tools-preview");
                }
            }
        } else {
            println!("cargo:warning=ELF not yet built; re-run cargo build to produce BOOTX64.EFI");
        }
    }
}
