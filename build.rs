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

const X86_BOOT_ASM_SRC: &str = "src/arch/x86_64/boot.s";
const X86_BOOT_OBJ_NAME: &str = "boot_x86_64.o";
const X86_BOOT_LIB_NAME: &str = "libboot_x86_64.a";

const RISCV_ASM_SRC: &str = "src/arch/riscv64/uentry.S";
const RISCV_OBJ_NAME: &str = "uentry_riscv64.o";
const RISCV_LIB_NAME: &str = "libuentry_riscv64.a";
const RISCV_FLAGS: &[&str] = &["-march=rv64gc", "-mabi=lp64d"];
const RISCV_TRIPLE: &str = "riscv64-unknown-elf";

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
    let uefi_boot = std::env::var("CARGO_FEATURE_UEFI_BOOT").is_ok();

    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UEFI_BOOT");

    compile_crt(&target_arch);

    if target_arch == "x86_64" && !uefi_boot {
        assemble_x86_boot(&out);
    }

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
    if std::env::var_os("CC").is_some() || std::env::var_os("TARGET_CC").is_some() {
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

/// Assemble the x86_64 Multiboot2 entry shim and link it into the kernel ELF.
fn assemble_x86_boot(out: &PathBuf) {
    println!("cargo:rerun-if-changed={X86_BOOT_ASM_SRC}");

    let nasm = which_first(&["nasm"]).unwrap_or_else(|| {
        panic!(
            "x86_64 Multiboot/QEMU -kernel builds require nasm; install it with: apt install nasm"
        )
    });
    let ar = which_first(&["llvm-ar", "ar"]).unwrap_or_else(|| {
        panic!(
            "x86_64 Multiboot/QEMU -kernel builds require llvm-ar or ar; install LLVM or binutils"
        )
    });

    let obj = out.join(X86_BOOT_OBJ_NAME);
    let lib = out.join(X86_BOOT_LIB_NAME);

    must_run(
        {
            let mut cmd = Command::new(&nasm);
            cmd.args(["-f", "elf64", "-o"])
                .arg(&obj)
                .arg(X86_BOOT_ASM_SRC);
            cmd
        },
        "x86_64 boot.s assembly",
    );

    must_run(
        {
            let mut cmd = Command::new(&ar);
            cmd.args(["crs"]).arg(&lib).arg(&obj);
            cmd
        },
        "x86_64 boot archive",
    );

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=boot_x86_64");
}

/// Assemble the RISC-V uentry trampoline and archive it as a static library.
fn assemble_riscv_uentry(out: &PathBuf) {
    println!("cargo:rerun-if-changed={RISCV_ASM_SRC}");

    let obj = out.join(RISCV_OBJ_NAME);
    let lib = out.join(RISCV_LIB_NAME);
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
