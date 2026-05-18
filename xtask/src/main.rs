//! cargo xtask — build automation for RustOS.
//!
//! Usage:
//!   cargo xtask build                              # riscv64, uefi, release (default)
//!   cargo xtask build --arch riscv64 --boot uefi
//!   cargo xtask build --arch riscv64 --boot sbi
//!   cargo xtask build --arch x86_64               # x86_64 kernel (ELF, no UEFI wrapper)
//!   cargo xtask build --arch x86_64 --boot uefi   # x86_64 UEFI loader (PE32+)
//!   cargo xtask build --arch riscv64 --boot sbi --debug
//!   cargo xtask build --arch riscv64 --boot sbi --initrd
//!
//!   cargo xtask image                              # x86_64 release ESP image
//!   cargo xtask image --arch riscv64               # riscv64 release ESP image
//!   cargo xtask image --arch x86_64 --debug        # x86_64 debug ESP image
//!   cargo xtask image --arch x86_64 --initrd       # include initramfs.cpio
//!
//! The `image` subcommand requires mtools (mformat, mmd, mcopy) and
//! objcopy (binutils / llvm-objcopy).  Install hint is printed if missing.

use std::{
    env,
    path::PathBuf,
    process::{Command, exit},
};

// ─── target JSON paths ───────────────────────────────────────────────────────────

/// All custom target specs live under targets/ in the workspace root.
/// Kernel targets produce ELF via ld.lld + linker script.
/// UEFI loader targets produce PE32+ via lld-link.
fn target_json(root: &PathBuf, arch: Arch, boot: Boot) -> PathBuf {
    let name = match (arch, boot) {
        (Arch::X86_64,  Boot::Uefi) => "x86_64-uefi-loader.json",
        (Arch::X86_64,  Boot::Sbi)  => "x86_64-kernel.json",
        (Arch::RiscV64, Boot::Uefi) => "riscv64-uefi-loader.json",
        (Arch::RiscV64, Boot::Sbi)  => "riscv64-kernel.json",
    };
    root.join("targets").join(name)
}

/// The cargo target/ output directory name matches the JSON stem.
fn target_dir_name(arch: Arch, boot: Boot) -> &'static str {
    match (arch, boot) {
        (Arch::X86_64,  Boot::Uefi) => "x86_64-uefi-loader",
        (Arch::X86_64,  Boot::Sbi)  => "x86_64-kernel",
        (Arch::RiscV64, Boot::Uefi) => "riscv64-uefi-loader",
        (Arch::RiscV64, Boot::Sbi)  => "riscv64gc-unknown-none-elf",  // uses built-in triple
    }
}

/// UEFI default boot binary name per arch (UEFI spec §3.4).
fn efi_boot_filename(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64  => "BOOTx64.EFI",
        Arch::RiscV64 => "BOOTRISCV64.EFI",
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
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

fn which_first(names: &[&str]) -> Option<String> {
    for name in names {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {name}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if found {
            return Some((*name).into());
        }
    }
    None
}

fn require_tool(names: &[&str], install_hint: &str) -> String {
    match which_first(names) {
        Some(t) => t,
        None => {
            eprintln!("[xtask] ERROR: none of {:?} found on PATH.", names);
            eprintln!("[xtask] Install with: {install_hint}");
            exit(1);
        }
    }
}

// ─── CLI parsing ─────────────────────────────────────────────────────────────────

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
    arch:   Arch,
    boot:   Boot,
    debug:  bool,
    initrd: bool,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            arch:   Arch::RiscV64,
            boot:   Boot::Uefi,
            debug:  false,
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

// ─── build actions ───────────────────────────────────────────────────────────────

/// Shared cargo build invocation for any custom-target JSON build.
/// For UEFI targets the output is already a PE32+ .efi; no objcopy needed.
fn build_with_target_json(root: &PathBuf, opts: &BuildOpts, features: &[&str]) {
    let profile     = if opts.debug { "debug" } else { "release" };
    let target_path = target_json(root, opts.arch, opts.boot);
    let target_dir  = target_dir_name(opts.arch, opts.boot);

    eprintln!(
        "[xtask] Building rustos ({:?}/{:?}, {profile}) → target/{target_dir}/",
        opts.arch, opts.boot
    );

    let mut cmd = cargo();
    cmd.current_dir(root)
        .args(["build", "--target"])
        .arg(&target_path)
        .args([
            "-Z", "build-std=core,alloc,compiler_builtins",
            "-Z", "build-std-features=compiler-builtins-mem",
        ]);
    if !features.is_empty() {
        cmd.arg("--features");
        cmd.arg(features.join(","));
    } else {
        cmd.arg("--no-default-features");
    }
    if !opts.debug { cmd.arg("--release"); }
    run(cmd);

    // For UEFI targets, copy the PE binary into esp/EFI/BOOT/
    if opts.boot == Boot::Uefi {
        let bin_name = efi_boot_filename(opts.arch);
        let src = root.join(format!("target/{target_dir}/{profile}/rustos.efi"));
        let src = if src.exists() { src }
                  else { root.join(format!("target/{target_dir}/{profile}/rustos")) };
        if !src.exists() {
            eprintln!("[xtask] ERROR: EFI binary not found under target/{target_dir}/{profile}/");
            exit(1);
        }
        let esp = root.join("esp/EFI/BOOT");
        std::fs::create_dir_all(&esp).expect("create esp dir");
        let dest = esp.join(bin_name);
        std::fs::copy(&src, &dest).expect("copy EFI binary");
        eprintln!("[xtask] Built:     {}", src.display());
        eprintln!("[xtask] Installed: {}", dest.display());
    } else {
        let elf = root.join(format!("target/{target_dir}/{profile}/rustos"));
        eprintln!("[xtask] Built: {}", elf.display());
    }
}

fn build_riscv_uefi(root: &PathBuf, debug: bool) {
    build_with_target_json(
        root,
        &BuildOpts { arch: Arch::RiscV64, boot: Boot::Uefi, debug, initrd: false },
        &["uefi_boot"],
    );
}

fn build_riscv_sbi(root: &PathBuf, debug: bool, initrd: bool) {
    // SBI uses the built-in riscv64gc triple, not a custom JSON.
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
    if !debug { cmd.arg("--release"); }
    run(cmd);

    let kernel_elf = root.join(format!(
        "target/riscv64gc-unknown-none-elf/{profile}/rustos"
    ));
    eprintln!("[xtask] Built: {}", kernel_elf.display());

    if initrd {
        eprintln!("[xtask] Building RISC-V userspace + initramfs...");
        run(Command::new("bash")
            .current_dir(root)
            .args(["tools/build_userspace.sh", "riscv64"]));
        eprintln!("[xtask] Initramfs: {}", root.join("initramfs.cpio").display());
    }
}

fn build_x86_64_kernel(root: &PathBuf, debug: bool, initrd: bool) {
    if initrd {
        eprintln!("[xtask] WARNING: --initrd is not supported for x86_64 builds.");
    }
    build_with_target_json(
        root,
        &BuildOpts { arch: Arch::X86_64, boot: Boot::Sbi, debug, initrd: false },
        &[],
    );
    // The kernel target produces an ELF; strip to flat binary for legacy use.
    let profile = if debug { "debug" } else { "release" };
    let elf = root.join(format!("target/x86_64-kernel/{profile}/rustos"));
    let bin = root.join("kernel.bin");
    let objcopy = require_tool(&["llvm-objcopy", "objcopy"], "apt install llvm binutils");
    run(Command::new(&objcopy).args(["-O", "binary"]).arg(&elf).arg(&bin));
    eprintln!("[xtask] Flat binary: {}", bin.display());
}

fn build_x86_64_uefi(root: &PathBuf, debug: bool) {
    // Produces a native PE32+ UEFI application via lld-link — no objcopy needed.
    build_with_target_json(
        root,
        &BuildOpts { arch: Arch::X86_64, boot: Boot::Uefi, debug, initrd: false },
        &["uefi_boot"],
    );
}

// ─── image action ─────────────────────────────────────────────────────────────────

fn image(root: &PathBuf, opts: &BuildOpts) {
    require_tool(
        &["mformat"],
        "apt install mtools   # Debian/Ubuntu\nbrew install mtools  # macOS",
    );
    require_tool(&["mmd"],   "apt install mtools");
    require_tool(&["mcopy"], "apt install mtools");
    let objcopy = require_tool(
        &["llvm-objcopy", "objcopy"],
        "apt install llvm binutils",
    );

    eprintln!("[xtask] image: building kernel...");
    match (opts.arch, opts.boot) {
        (Arch::RiscV64, Boot::Uefi) => build_riscv_uefi(root, opts.debug),
        (Arch::RiscV64, Boot::Sbi)  => build_riscv_sbi(root, opts.debug, opts.initrd),
        (Arch::X86_64,  Boot::Uefi) => build_x86_64_uefi(root, opts.debug),
        (Arch::X86_64,  Boot::Sbi)  => build_x86_64_kernel(root, opts.debug, opts.initrd),
    }

    let profile   = if opts.debug { "debug" } else { "release" };
    let efi_name  = efi_boot_filename(opts.arch);
    let img_name  = match opts.arch {
        Arch::X86_64  => "boot.img",
        Arch::RiscV64 => "boot-riscv64.img",
    };
    let efi_path  = root.join("esp/EFI/BOOT").join(efi_name);

    // x86_64 kernel (non-UEFI) path: convert ELF → PE via objcopy
    if opts.arch == Arch::X86_64 && opts.boot == Boot::Sbi {
        let elf = root.join(format!("target/x86_64-kernel/{profile}/rustos"));
        if !elf.exists() {
            eprintln!("[xtask] ERROR: kernel ELF not found at {}", elf.display());
            exit(1);
        }
        let esp_dir = root.join("esp/EFI/BOOT");
        std::fs::create_dir_all(&esp_dir).expect("create esp dir");
        run(Command::new(&objcopy)
            .args(["--target", "efi-app-x86-64", "--subsystem", "10"])
            .arg(&elf)
            .arg(&efi_path));
    }

    if !efi_path.exists() {
        eprintln!("[xtask] ERROR: EFI binary not found at {}", efi_path.display());
        eprintln!("[xtask]        Did the build step succeed?");
        exit(1);
    }

    let img_path = root.join(img_name);

    run(Command::new("mformat")
        .args(["-C", "-F", "-h", "64", "-s", "32", "-t", "64", "-i"])
        .arg(&img_path)
        .arg("::"));
    run(Command::new("mmd").args(["-i"]).arg(&img_path).args(["|::/EFI", "::/EFI/BOOT"]));
    run(Command::new("mcopy")
        .args(["-i"]).arg(&img_path)
        .arg(&efi_path)
        .arg(format!("::/EFI/BOOT/{efi_name}")));

    if opts.initrd {
        let cpio = root.join("initramfs.cpio");
        if cpio.exists() {
            run(Command::new("mcopy")
                .args(["-i"]).arg(&img_path)
                .arg(&cpio)
                .arg("::/initramfs.cpio"));
            eprintln!("[xtask] Embedded initramfs: {}", cpio.display());
        } else {
            eprintln!("[xtask] WARNING: --initrd specified but initramfs.cpio not found.");
        }
    }

    eprintln!("\n[xtask] ✓ Image ready: {}", img_path.display());
    eprintln!("\n  Flash to USB:");
    eprintln!("    sudo dd if={} of=/dev/sdX bs=4M status=progress && sync", img_path.display());
    match opts.arch {
        Arch::X86_64 => {
            eprintln!("\n  Smoke-test in QEMU:");
            eprintln!("    qemu-system-x86_64 \\");
            eprintln!("      -bios /usr/share/ovmf/OVMF.fd \\");
            eprintln!("      -drive format=raw,file={} \\", img_path.display());
            eprintln!("      -serial stdio -nographic -m 512M");
        }
        Arch::RiscV64 => {
            eprintln!("\n  Smoke-test in QEMU:");
            eprintln!("    qemu-system-riscv64 \\");
            eprintln!("      -machine virt \\");
            eprintln!("      -bios /usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin \\");
            eprintln!("      -drive if=pflash,format=raw,file=/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \\");
            eprintln!("      -drive format=raw,file={} \\", img_path.display());
            eprintln!("      -serial stdio -nographic -m 512M");
        }
    }
    eprintln!();
}

// ─── entrypoint ───────────────────────────────────────────────────────────────────

fn main() {
    let mut args = env::args().skip(1);
    let subcommand = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();

    let root = workspace_root();

    match subcommand.as_str() {
        "build" => {
            let opts = parse_build_args(&rest);
            match (opts.arch, opts.boot) {
                (Arch::RiscV64, Boot::Uefi) => build_riscv_uefi(&root, opts.debug),
                (Arch::RiscV64, Boot::Sbi)  => build_riscv_sbi(&root, opts.debug, opts.initrd),
                (Arch::X86_64,  Boot::Uefi) => build_x86_64_uefi(&root, opts.debug),
                (Arch::X86_64,  Boot::Sbi)  => build_x86_64_kernel(&root, opts.debug, opts.initrd),
            }
        }
        "image" => {
            let mut opts = parse_build_args(&rest);
            if rest.iter().all(|a| a != "--arch") {
                opts.arch = Arch::X86_64;
            }
            image(&root, &opts);
        }
        "help" | "--help" | "-h" | "" => {
            println!(concat!(
                "cargo xtask <subcommand> [options]\n",
                "\n",
                "Subcommands:\n",
                "  build    Compile the kernel\n",
                "  image    Build a flashable FAT32 ESP disk image\n",
                "\n",
                "Build / image options:\n",
                "  --arch <riscv64|x86_64>   Target architecture  (image default: x86_64)\n",
                "  --boot <uefi|sbi>         Boot mode            (default: uefi)\n",
                "                             x86_64+uefi → PE32+ UEFI app via lld-link\n",
                "                             x86_64+sbi  → ELF kernel via ld.lld\n",
                "                             riscv64+uefi → PE32+ UEFI app via lld-link\n",
                "                             riscv64+sbi  → ELF via built-in triple\n",
                "  --debug                   Debug build          (default: release)\n",
                "  --initrd                  Build/include initramfs (RISC-V SBI only)\n",
                "\n",
                "Target JSON files (in targets/):\n",
                "  x86_64-uefi-loader.json   PE32+ UEFI app, lld-link, os=uefi\n",
                "  x86_64-kernel.json        ELF kernel, ld.lld, os=none\n",
                "  riscv64-uefi-loader.json  PE32+ UEFI app, lld-link, os=uefi\n",
                "  riscv64-kernel.json       ELF kernel, ld.lld, os=none\n",
                "\n",
                "image requires:\n",
                "  mtools   (mformat, mmd, mcopy)  →  apt install mtools\n",
                "  objcopy  (binutils/llvm)        →  apt install binutils\n",
                "\n",
                "Examples:\n",
                "  cargo xtask build                                   # riscv64 uefi release\n",
                "  cargo xtask build --arch x86_64 --boot uefi        # x86_64 UEFI loader\n",
                "  cargo xtask build --arch x86_64                    # x86_64 ELF kernel\n",
                "  cargo xtask image                                   # x86_64 boot.img\n",
                "  cargo xtask image --arch riscv64                    # riscv64 boot-riscv64.img\n",
                "  cargo xtask image --arch x86_64 --boot uefi --debug\n"
            ));
        }
        other => {
            eprintln!("[xtask] unknown subcommand: {other:?}. Try `cargo xtask help`.");
            exit(1);
        }
    }
}
