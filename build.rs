/// build.rs
use std::path::PathBuf;
use std::process::Command;

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
const RISCV_CLANG_TARGET: &str = "riscv64-unknown-elf";
const RISCV_CLANG_FLAGS: &[&str] = &[
    "-c",
    "-x",
    "assembler-with-cpp",
    "-ffreestanding",
    "-march=rv64gc",
    "-mabi=lp64d",
    "-mno-relax",
];

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

    compile_crt(&target_arch);

    if target_arch == "riscv64" {
        assemble_riscv_uentry(&out);
    }

    // UEFI image production is handled by `cargo xtask build/image` after Cargo
    // has produced the final `rustos` ELF. Doing this from build.rs is too early
    // in Cargo's build graph and previously used stale target paths.

    if std::env::var("CARGO_FEATURE_TRACE").is_ok() {
        println!("cargo:rustc-flags=-Z instrument-functions");
        println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TRACE");
    }
}

/// Compile C runtime stubs into a static archive `librustos_crt.a`.
fn compile_crt(target_arch: &str) {
    for src in CRT_SOURCES {
        println!("cargo:rerun-if-changed={CRT_DIR}/{src}");
    }

    let mut build = cc::Build::new();
    configure_crt_compiler(&mut build, target_arch);

    for flag in CRT_COMPILE_FLAGS {
        build.flag(flag);
    }

    for src in CRT_SOURCES {
        build.file(format!("{CRT_DIR}/{src}"));
    }

    build.compile("rustos_crt");
}

/// Select a usable C compiler for freestanding CRT objects when cross-building.
///
/// `cc` will honor explicit `CC_<target>`, `TARGET_CC`, and `CC` environment
/// variables before this helper runs. When none are present for non-host kernel
/// targets, prefer Clang with an explicit target triple so host `cc` is not
/// invoked with incompatible `-march`/`-mabi` flags.
fn configure_crt_compiler(build: &mut cc::Build, target_arch: &str) {
    if explicit_cc_override_is_set(target_arch) {
        return;
    }

    match target_arch {
        "riscv64" if command_exists("clang") => {
            build.compiler("clang");
            build.flag("--target=riscv64-unknown-elf");
        },
        "aarch64" if command_exists("clang") => {
            build.compiler("clang");
            build.flag("--target=aarch64-none-elf");
        },
        _ => {},
    }
}

fn explicit_cc_override_is_set(target_arch: &str) -> bool {
    let target = std::env::var("TARGET").unwrap_or_default();
    let normalized_target = target.replace('-', "_");
    let upper_target = normalized_target.to_ascii_uppercase();

    let mut vars = vec![
        "CC".to_string(),
        "TARGET_CC".to_string(),
        format!("CC_{target_arch}"),
    ];

    if !normalized_target.is_empty() {
        vars.push(format!("CC_{normalized_target}"));
    }
    if !upper_target.is_empty() {
        vars.push(format!("CC_{upper_target}"));
    }

    vars.into_iter().any(|var| std::env::var_os(var).is_some())
}

fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {name} >/dev/null 2>&1")])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn which_first(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find(|name| command_exists(name))
        .map(|name| (*name).to_string())
}

/// Assemble the RISC-V uentry trampoline and archive it as a static library.
///
/// Uses LLVM-provided tooling (`clang` as the assembler driver and `llvm-ar`
/// from `llvm-tools-preview` / a host `llvm` install) rather than the GNU
/// `riscv64-unknown-elf-{as,ar}` binutils. This removes the need for a
/// cross binutils package on CI hosts when only the Rust + LLVM toolchain
/// is available.
fn assemble_riscv_uentry(out: &PathBuf) {
    println!("cargo:rerun-if-changed={RISCV_ASM_SRC}");

    if !std::path::Path::new(RISCV_ASM_SRC).exists() {
        // No user-entry trampoline source in this tree; nothing to assemble.
        return;
    }

    let obj = out.join(RISCV_OBJ_NAME);
    let lib = out.join(RISCV_LIB_NAME);

    // Assembler: prefer clang (with explicit cross target) over a GNU
    // riscv64-unknown-elf-as. clang ships with rustup's `llvm-tools-preview`
    // and is otherwise readily available on CI runners.
    let Some(asm_driver) = which_first(&["clang", "clang-19", "clang-18", "clang-17"]) else {
        println!(
            "cargo:warning=RISC-V assembly skipped; no clang available to assemble {RISCV_ASM_SRC}"
        );
        return;
    };

    if !run_command(
        {
            let mut cmd = Command::new(&asm_driver);
            cmd.args(["--target", RISCV_CLANG_TARGET])
                .args(RISCV_CLANG_FLAGS)
                .arg("-o")
                .arg(&obj)
                .arg(RISCV_ASM_SRC);
            cmd
        },
        &format!("{asm_driver} assembly"),
    ) {
        println!("cargo:warning=RISC-V assembly skipped; {asm_driver} failed on {RISCV_ASM_SRC}");
        return;
    }

    // Archiver: prefer llvm-ar (host install, rustup component, or versioned
    // binary) over the GNU riscv64-unknown-elf-ar. llvm-ar is target-agnostic.
    let Some(ar_bin) = which_first(&["llvm-ar", "llvm-ar-19", "llvm-ar-18", "llvm-ar-17", "ar"])
    else {
        println!("cargo:warning=RISC-V archival skipped; no llvm-ar/ar available");
        return;
    };

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

fn must_run(mut cmd: Command, context: &str) {
    match cmd.status() {
        Ok(status) if status.success() => {},
        Ok(status) => panic!("{context} failed with status {status}"),
        Err(e) => panic!("{context} failed: {e}"),
    }
}

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
