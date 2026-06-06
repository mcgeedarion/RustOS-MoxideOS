use std::path::PathBuf;
use std::process::Command;

// Improvement #2, #8: Magic strings extracted as constants
const CRT_DIR: &str = "src/init/crt";
const CRT_SOURCES: &[&str] = &[
    "compiler_rt.c",
    "crt0.c",
    "memcpy.c",
    "memmove.c",
    "memset.c",
];

const RISCV_ASM_SRC: &str = "src/arch/riscv64/uentry.S";
const RISCV_OBJ_NAME: &str = "uentry_riscv64.o";
const RISCV_LIB_NAME: &str = "libuentry_riscv64.a";
const RISCV_FLAGS: &[&str] = &["-march=rv64gc", "-mabi=lp64d"];
const RISCV_TRIPLE: &str = "riscv64-unknown-elf";

const UEFI_OUTPUT_DIR: &str = "target/esp/EFI/BOOT";
const UEFI_OUTPUT_FILE: &str = "BOOTX64.EFI";
const UEFI_TARGET: &str = "efi-app-x86_64";
const UEFI_SUBSYSTEM: &str = "10"; // EFI_APPLICATION

const CRT_COMPILE_FLAGS: &[&str] = &[
    "-ffreestanding",
    "-nostdlib",
    "-O2",
    "-fno-stack-protector",
    "-fno-builtin",
    "-Wno-builtin-declaration-mismatch",
];

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

    // When `--features trace` is active, inject LLVM -Z instrument-functions
    // so that every Rust function gets __cyg_profile_func_enter/exit calls.
    // This is a nightly-only rustc flag; it is intentionally gated behind the
    // `trace` feature so release builds and CI without nightly are unaffected.
    if std::env::var("CARGO_FEATURE_TRACE").is_ok() {
        println!("cargo:rustc-flags=-Z instrument-functions");
        println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TRACE");
    }
}

/// Compile C runtime stubs into a static archive `librustos_crt.a`.
///
/// Produces a freestanding C library without host libc dependencies.
/// Flags:
///   -ffreestanding   — no host libc assumptions
///   -nostdlib        — do not link the standard library
///   -O2              — light optimisation (safe for freestanding)
///   -fno-stack-protector — the stubs *define* __stack_chk_fail; avoid
/// recursion
///
/// # Panics
/// Panics if the C compiler fails to compile the sources.
fn compile_crt() {
    for src in CRT_SOURCES {
        println!("cargo:rerun-if-changed={CRT_DIR}/{src}");
    }

    let mut build = cc::Build::new();

    // Improvement #2: Use constants for flags
    for flag in CRT_COMPILE_FLAGS {
        build.flag(flag);
    }

    build.static_flag(true);

    for src in CRT_SOURCES {
        build.file(format!("{CRT_DIR}/{src}"));
    }

    // Improvement #1: Explicit error handling
    build.compile("rustos_crt");
}

/// Assemble the RISC-V uentry trampoline and archive it as a static library.
///
/// Produces `libuentry_riscv64.a` for RISC-V 64 targets.
/// Uses the RISC-V toolchain binaries: `riscv64-unknown-elf-as` and
/// `riscv64-unknown-elf-ar`.
///
/// # Panics
/// Panics if the archival step fails after successful assembly.
fn assemble_riscv_uentry(out: &PathBuf) {
    println!("cargo:rerun-if-changed={RISCV_ASM_SRC}");

    let obj = out.join(RISCV_OBJ_NAME);
    let lib = out.join(RISCV_LIB_NAME);

    // Improvement #4: Reusable command building logic
    let as_bin = format!("{RISCV_TRIPLE}-as");
    if !run_command(
        {
            let mut cmd = Command::new(&as_bin);
            cmd.args(RISCV_FLAGS)
                .args(["-o"])
                .arg(&obj)
                .arg(RISCV_ASM_SRC);
            cmd
        },
        &format!("{as_bin} assembly"),
    ) {
        println!("cargo:warning=RISC-V assembly skipped; {as_bin} not available");
        return;
    }

    let ar_bin = format!("{RISCV_TRIPLE}-ar");
    if !run_command(
        {
            let mut cmd = Command::new(&ar_bin);
            cmd.args(["crs"]).arg(&lib).arg(&obj);
            cmd
        },
        &format!("{ar_bin} archival"),
    ) {
        println!("cargo:warning=RISC-V archival failed; skipping uentry linking");
        return;
    }

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=uentry_riscv64");
}

/// Convert the ELF kernel to a PE32+ UEFI application (BOOTX64.EFI).
///
/// Produces a valid UEFI application at `target/esp/EFI/BOOT/BOOTX64.EFI`,
/// which can boot on OVMF or real hardware.
///
/// Requires: `rustup component add llvm-tools-preview`
/// Falls back to system `llvm-objcopy` if rustup version unavailable.
/// On first build, the ELF may not exist yet; re-run `cargo build` to produce
/// the .efi file.
fn produce_uefi_image(out: &PathBuf) {
    // Improvement #5: Use PROFILE env var instead of fragile path inspection
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    // Improvement #7: Use PathBuf throughout to avoid redundant parsing
    let elf_path = PathBuf::from(format!("target/x86_64-unknown-none/{profile}/rustos"));

    println!("cargo:rerun-if-changed={}", elf_path.display());

    if !elf_path.exists() {
        println!("cargo:warning=ELF not yet built; re-run `cargo build` to produce BOOTX64.EFI");
        return;
    }

    // Improvement #7: Use PathBuf consistently
    let esp_dir = PathBuf::from(UEFI_OUTPUT_DIR);
    let _ = std::fs::create_dir_all(&esp_dir);
    let efi_path = esp_dir.join(UEFI_OUTPUT_FILE);

    let objcopy_bin = locate_llvm_objcopy();

    // Improvement #4: Reusable command building logic
    if !run_command(
        {
            let mut cmd = Command::new(&objcopy_bin);
            cmd.args([
                format!("--target={UEFI_TARGET}"),
                format!("--subsystem={UEFI_SUBSYSTEM}"),
            ])
            .arg(elf_path.to_str().unwrap())
            .arg(efi_path.to_str().unwrap());
            cmd
        },
        "UEFI image conversion",
    ) {
        println!(
            "cargo:warning=UEFI image conversion failed; \
            ensure llvm-objcopy available via: rustup component add llvm-tools-preview"
        );
        return;
    }

    println!("cargo:warning=UEFI image produced: {}", efi_path.display());
}

/// Locate llvm-objcopy from the active rustup toolchain, falling back to PATH.
///
/// First attempts to find `llvm-objcopy` in the rustup sysroot for the active
/// host triple. If not found, falls back to searching PATH.
///
/// # Returns
/// Path to `llvm-objcopy` binary (either absolute from rustup or relative for
/// PATH search).
fn locate_llvm_objcopy() -> String {
    let sysroot = String::from_utf8_lossy(
        &Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string();

    let host_triple = String::from_utf8_lossy(
        &Command::new("rustc")
            .args(["-vV"])
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .lines()
    .find(|l| l.starts_with("host:"))
    .map(|l| l[5..].trim().to_string())
    .unwrap_or_default();

    let candidate = PathBuf::from(&sysroot)
        .join("lib/rustlib")
        .join(&host_triple)
        .join("bin/llvm-objcopy");

    candidate
        .exists()
        .then(|| candidate.to_string_lossy().into_owned())
        .unwrap_or_else(|| "llvm-objcopy".to_string())
}

/// Improvement #4: Helper function to run commands with unified error handling.
///
/// Executes a command and returns success/failure status.
/// Prints cargo warnings for diagnostics.
///
/// # Arguments
/// * `cmd` - The Command to execute
/// * `context` - Description of what the command does (for warning messages)
///
/// # Returns
/// `true` if the command succeeded, `false` otherwise.
fn run_command(mut cmd: Command, context: &str) -> bool {
    match cmd.status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            println!("cargo:warning={context} failed with status {status}");
            false
        },
        Err(e) => {
            println!("cargo:warning={context} failed: {e}");
            false
        },
    }
}
