use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    // Always compile the freestanding C runtime stubs.
    compile_crt();

    if target_arch == "riscv64" {
        assemble_riscv_uentry(&out);
    }

    if target_arch == "x86_64" && std::env::var("CARGO_FEATURE_UEFI_BOOT").is_ok() {
        produce_uefi_image(&out);
    }
}

// Compile src/init/crt/*.c into a static archive `librustos_crt.a` and
// instruct Cargo to link it into the kernel binary.
//
// Flags:
//   -ffreestanding   — no host libc assumptions
//   -nostdlib        — do not link the standard library
//   -O2              — light optimisation (safe for freestanding)
//   -fno-stack-protector — the stubs *define* __stack_chk_fail; avoid recursion
fn compile_crt() {
    let crt_dir = "src/init/crt";
    let sources = [
        "compiler_rt.c",
        "crt0.c",
        "memcpy.c",
        "memmove.c",
        "memset.c",
    ];

    for src in &sources {
        println!("cargo:rerun-if-changed={crt_dir}/{src}");
    }

    let mut build = cc::Build::new();
    build
        .flag("-ffreestanding")
        .flag("-nostdlib")
        .flag("-O2")
        .flag("-fno-stack-protector")
        .flag("-fno-builtin")
        // Suppress warnings that are expected in freestanding C
        .flag("-Wno-builtin-declaration-mismatch")
        .static_flag(true);

    for src in &sources {
        build.file(format!("{crt_dir}/{src}"));
    }

    build.compile("rustos_crt");
}

// Assemble the RISC-V uentry trampoline and archive it as a static lib.
fn assemble_riscv_uentry(out: &PathBuf) {
    const ASM_SRC: &str = "src/arch/riscv64/uentry.S";
    println!("cargo:rerun-if-changed={ASM_SRC}");

    let obj = out.join("uentry_riscv64.o");
    let status = Command::new("riscv64-unknown-elf-as")
        .args(["-march=rv64gc", "-mabi=lp64d", "-o"])
        .arg(&obj)
        .arg(ASM_SRC)
        .status();

    match status {
        Ok(s) if s.success() => {
            let lib = out.join("libuentry_riscv64.a");
            Command::new("riscv64-unknown-elf-ar")
                .args(["crs"])
                .arg(&lib)
                .arg(&obj)
                .status()
                .expect("riscv64-unknown-elf-ar failed");
            println!("cargo:rustc-link-search=native={}", out.display());
            println!("cargo:rustc-link-lib=static=uentry_riscv64");
        }
        _ => {
            println!("cargo:warning=riscv64-unknown-elf-as not found; skipping uentry assembly");
        }
    }
}

// Convert the ELF kernel to a PE32+ UEFI application (BOOTX64.EFI) using
// llvm-objcopy.  Output lands at target/esp/EFI/BOOT/BOOTX64.EFI, which is
// a valid EFI System Partition root for OVMF or real hardware.
//
// Requires: `rustup component add llvm-tools-preview`
// Falls back to system `llvm-objcopy` if the rustup path is absent.
// On the very first build pass the ELF does not exist yet; re-running
// `cargo build` a second time will always find it.
fn produce_uefi_image(out: &PathBuf) {
    let out_str = out.to_string_lossy();
    let profile = if out_str.contains("/release/") { "release" } else { "debug" };
    let elf_path = format!("target/x86_64-unknown-none/{profile}/rustos");

    println!("cargo:rerun-if-changed={elf_path}");

    let esp_dir = PathBuf::from("target/esp/EFI/BOOT");
    std::fs::create_dir_all(&esp_dir)
        .unwrap_or_else(|e| eprintln!("build.rs: mkdir esp: {e}"));
    let efi_path = esp_dir.join("BOOTX64.EFI");

    let objcopy_bin = locate_llvm_objcopy();

    if !PathBuf::from(&elf_path).exists() {
        println!("cargo:warning=ELF not yet built; re-run `cargo build` to produce BOOTX64.EFI");
        return;
    }

    let status = Command::new(&objcopy_bin)
        .args([
            "--target=efi-app-x86_64",
            "--subsystem=10", // EFI_APPLICATION
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
            println!("cargo:warning=llvm-objcopy not found ({e}); run: rustup component add llvm-tools-preview");
        }
    }
}

// Locate llvm-objcopy from the active rustup toolchain, falling back to PATH.
fn locate_llvm_objcopy() -> String {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

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

    let candidate = PathBuf::from(&sysroot)
        .join("lib/rustlib")
        .join(&host_triple)
        .join("bin/llvm-objcopy");

    if candidate.exists() {
        candidate.to_string_lossy().into_owned()
    } else {
        "llvm-objcopy".to_string()
    }
}
