//! cargo xtask — build automation for RustOS.
//!
//! Usage:
//!   cargo xtask build                            # riscv64, uefi, release (default)
//!   cargo xtask build --arch riscv64 --boot uefi
//!   cargo xtask build --arch riscv64 --boot sbi
//!   cargo xtask build --arch x86_64
//!   cargo xtask build --arch riscv64 --boot sbi --debug
//!   cargo xtask build --arch riscv64 --boot sbi --initrd

use std::{
    env,
    path::PathBuf,
    process::{Command, exit},
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    // xtask lives at <root>/xtask — its parent is the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has no parent directory")
        .to_path_buf()
}

fn cargo() -> Command {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    Command::new(cargo)
}

fn run(mut cmd: Command) {
    eprintln!("[xtask] running: {:?}", cmd);
    let status = cmd.status().expect("failed to spawn command");
    if !status.success() {
        eprintln!("[xtask] command failed with {status}");
        exit(status.code().unwrap_or(1));
    }
}

// ── CLI parsing ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Arch {
    RiscV64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Boot {
    Uefi,
    Sbi,
}

#[derive(Debug)]
struct BuildOpts {
    arch: Arch,
    boot: Boot,
    debug: bool,
    initrd: bool,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            arch: Arch::RiscV64,
            boot: Boot::Uefi,
            debug: false,
            initrd: false,
        }
    }
}

fn parse_build_args(args: &[String]) -> BuildOpts {
    let mut opts = BuildOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--arch" => {
                i += 1;
                match args.get(i).map(String::as_str) {
                    Some("riscv64") => opts.arch = Arch::RiscV64,
                    Some("x86_64")  => opts.arch = Arch::X86_64,
                    other => {
                        eprintln!("[xtask] unknown --arch value: {:?}", other);
                        exit(1);
                    }
                }
            }
            "--boot" => {
                i += 1;
                match args.get(i).map(String::as_str) {
                    Some("uefi") => opts.boot = Boot::Uefi,
                    Some("sbi")  => opts.boot = Boot::Sbi,
                    other => {
                        eprintln!("[xtask] unknown --boot value: {:?}", other);
                        exit(1);
                    }
                }
            }
            "--debug"  => opts.debug  = true,
            "--initrd" => opts.initrd = true,
            other => {
                eprintln!("[xtask] unknown argument: {other}");
                exit(1);
            }
        }
        i += 1;
    }
    opts
}

// ── build actions ────────────────────────────────────────────────────────────

fn build_riscv_uefi(root: &PathBuf, debug: bool) {
    let profile = if debug { "debug" } else { "release" };
    eprintln!("[xtask] Building rustos (RISC-V UEFI, {profile})...");

    let target_json = root.join("riscv64-uefi.json");

    let mut cmd = cargo();
    cmd.current_dir(root)
        .args(["build", "--target"])
        .arg(&target_json)
        .args([
            "--features", "uefi_boot",
            "-Z", "build-std=core,alloc,compiler_builtins",
            "-Z", "build-std-features=compiler-builtins-mem",
        ]);
    if !debug {
        cmd.arg("--release");
    }
    run(cmd);

    // Locate the produced EFI binary (lld-link may or may not append .efi).
    let efi_with    = root.join(format!("target/riscv64-uefi/{profile}/rustos.efi"));
    let efi_without = root.join(format!("target/riscv64-uefi/{profile}/rustos"));
    let kernel_efi = if efi_with.exists() {
        efi_with
    } else if efi_without.exists() {
        efi_without
    } else {
        eprintln!("[xtask] ERROR: could not find EFI binary under target/riscv64-uefi/{profile}/");
        exit(1);
    };

    // Install into ESP layout.
    let esp = root.join("esp/EFI/BOOT");
    std::fs::create_dir_all(&esp).expect("create esp dir");
    let dest = esp.join("BOOTRISCV64.EFI");
    std::fs::copy(&kernel_efi, &dest).expect("copy EFI binary");

    eprintln!("[xtask] Built:     {}", kernel_efi.display());
    eprintln!("[xtask] Installed: {}", dest.display());
    eprintln!("[xtask] Run with:  cargo xtask run --arch riscv64 --boot uefi");
    eprintln!("[xtask] Note: requires EDK2 firmware (qemu-efi-riscv64).");
}

fn build_riscv_sbi(root: &PathBuf, debug: bool, initrd: bool) {
    let profile = if debug { "debug" } else { "release" };
    eprintln!("[xtask] Building rustos (RISC-V SBI, {profile})...");

    let mut cmd = cargo();
    cmd.current_dir(root)
        .args([
            "build",
            "--target", "riscv64gc-unknown-none-elf",
            "--no-default-features",
            "-Z", "build-std=core,alloc,compiler_builtins",
            "-Z", "build-std-features=compiler-builtins-mem",
        ]);
    if !debug {
        cmd.arg("--release");
    }
    run(cmd);

    let kernel_elf = root.join(format!(
        "target/riscv64gc-unknown-none-elf/{profile}/rustos"
    ));
    eprintln!("[xtask] Built: {}", kernel_elf.display());

    // Optional size report.
    for tool in ["llvm-size", "size"] {
        if Command::new(tool).arg(&kernel_elf).status().is_ok() {
            break;
        }
    }

    if initrd {
        eprintln!("[xtask] Building RISC-V userspace + initramfs...");
        let mut cmd = Command::new("bash");
        cmd.current_dir(root)
            .args(["tools/build_userspace.sh", "riscv64"]);
        run(cmd);
        eprintln!("[xtask] Initramfs: {}", root.join("initramfs.cpio").display());
    }

    eprintln!("[xtask] Run with:  cargo xtask run --arch riscv64 --boot sbi");
}

fn build_x86_64(root: &PathBuf, debug: bool) {
    let profile = if debug { "debug" } else { "release" };
    eprintln!("[xtask] Building rustos (x86_64, {profile})...");

    let mut cmd = cargo();
    cmd.current_dir(root)
        .args([
            "build",
            "--target", "x86_64-unknown-none",
            "-Z", "build-std=core,alloc,compiler_builtins",
            "-Z", "build-std-features=compiler-builtins-mem",
        ]);
    if !debug {
        cmd.arg("--release");
    }
    run(cmd);

    let elf = root.join(format!("target/x86_64-unknown-none/{profile}/rustos"));
    let bin = root.join("kernel.bin");

    let mut objcopy = Command::new("objcopy");
    objcopy.args(["-O", "binary"]).arg(&elf).arg(&bin);
    run(objcopy);

    eprintln!("[xtask] Built: {}", bin.display());
    eprintln!("[xtask] Run with:  cargo xtask run --arch x86_64");
}

// ── entrypoint ────────────────────────────────────────────────────────────────

fn main() {
    let mut args = env::args().skip(1); // skip binary name
    let subcommand = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();

    let root = workspace_root();

    match subcommand.as_str() {
        "build" => {
            let opts = parse_build_args(&rest);
            match (opts.arch, opts.boot) {
                (Arch::RiscV64, Boot::Uefi) => build_riscv_uefi(&root, opts.debug),
                (Arch::RiscV64, Boot::Sbi)  => build_riscv_sbi(&root, opts.debug, opts.initrd),
                (Arch::X86_64,  _)          => build_x86_64(&root, opts.debug),
            }
        }
        "help" | "--help" | "-h" | "" => {
            println!(concat!(
                "cargo xtask <subcommand> [options]\n",
                "\n",
                "Subcommands:\n",
                "  build    Compile the kernel\n",
                "\n",
                "Build options:\n",
                "  --arch <riscv64|x86_64>   Target architecture  (default: riscv64)\n",
                "  --boot <uefi|sbi>         Boot mode (riscv64)  (default: uefi)\n",
                "  --debug                   Debug build          (default: release)\n",
                "  --initrd                  Build initramfs      (SBI only)\n",
                "\n",
                "Examples:\n",
                "  cargo xtask build                            # riscv64 uefi release\n",
                "  cargo xtask build --arch riscv64 --boot sbi  # riscv64 sbi release\n",
                "  cargo xtask build --arch riscv64 --boot sbi --debug --initrd\n",
                "  cargo xtask build --arch x86_64\n"
            ));
        }
        other => {
            eprintln!("[xtask] unknown subcommand: {other:?}. Try `cargo xtask help`.");
            exit(1);
        }
    }
}
