//! cargo xtask — build automation for RustOS.
//!
//! Usage:
//!   cargo xtask build                            # riscv64, uefi, release (default)
//!   cargo xtask build --arch riscv64 --boot uefi
//!   cargo xtask build --arch riscv64 --boot sbi
//!   cargo xtask build --arch x86_64
//!   cargo xtask build --arch riscv64 --boot sbi --debug
//!   cargo xtask build --arch riscv64 --boot sbi --initrd
//!   cargo xtask image                            # x86_64 ESP image (default)
//!   cargo xtask image --arch x86_64              # produces boot.img
//!   cargo xtask image --arch riscv64             # produces boot-riscv64.img

use std::{
    env,
    path::PathBuf,
    process::{Command, exit},
};

// ── helpers ──────────────────────────────────────────────────────────────────

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

fn require_tool(tool: &str) {
    if Command::new(tool).arg("--version").output().is_err() {
        eprintln!("[xtask] ERROR: `{tool}` not found in PATH.");
        eprintln!("[xtask] Install with: apt install mtools dosfstools  OR  brew install mtools");
        exit(1);
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
    arch:  Arch,
    boot:  Boot,
    debug: bool,
    initrd: bool,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self { arch: Arch::RiscV64, boot: Boot::Uefi, debug: false, initrd: false }
    }
}

#[derive(Debug)]
struct ImageOpts {
    arch:  Arch,
    debug: bool,
}

impl Default for ImageOpts {
    fn default() -> Self {
        Self { arch: Arch::X86_64, debug: false }
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
                    other => { eprintln!("[xtask] unknown --arch: {:?}", other); exit(1); }
                }
            }
            "--boot" => {
                i += 1;
                match args.get(i).map(String::as_str) {
                    Some("uefi") => opts.boot = Boot::Uefi,
                    Some("sbi")  => opts.boot = Boot::Sbi,
                    other => { eprintln!("[xtask] unknown --boot: {:?}", other); exit(1); }
                }
            }
            "--debug"  => opts.debug  = true,
            "--initrd" => opts.initrd = true,
            other => { eprintln!("[xtask] unknown arg: {other}"); exit(1); }
        }
        i += 1;
    }
    opts
}

fn parse_image_args(args: &[String]) -> ImageOpts {
    let mut opts = ImageOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--arch" => {
                i += 1;
                match args.get(i).map(String::as_str) {
                    Some("x86_64")  => opts.arch = Arch::X86_64,
                    Some("riscv64") => opts.arch = Arch::RiscV64,
                    other => { eprintln!("[xtask] unknown --arch: {:?}", other); exit(1); }
                }
            }
            "--debug" => opts.debug = true,
            other => { eprintln!("[xtask] unknown arg: {other}"); exit(1); }
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
        .args(["build", "--target"]).arg(&target_json)
        .args(["--features", "uefi_boot",
               "-Z", "build-std=core,alloc,compiler_builtins",
               "-Z", "build-std-features=compiler-builtins-mem"]);
    if !debug { cmd.arg("--release"); }
    run(cmd);

    let efi_with    = root.join(format!("target/riscv64-uefi/{profile}/rustos.efi"));
    let efi_without = root.join(format!("target/riscv64-uefi/{profile}/rustos"));
    let kernel_efi = if efi_with.exists() { efi_with }
        else if efi_without.exists() { efi_without }
        else { eprintln!("[xtask] ERROR: EFI binary not found"); exit(1); };

    let esp = root.join("esp/EFI/BOOT");
    std::fs::create_dir_all(&esp).expect("create esp dir");
    let dest = esp.join("BOOTRISCV64.EFI");
    std::fs::copy(&kernel_efi, &dest).expect("copy EFI binary");
    eprintln!("[xtask] Built:     {}", kernel_efi.display());
    eprintln!("[xtask] Installed: {}", dest.display());
}

fn build_riscv_sbi(root: &PathBuf, debug: bool, initrd: bool) {
    let profile = if debug { "debug" } else { "release" };
    eprintln!("[xtask] Building rustos (RISC-V SBI, {profile})...");
    let mut cmd = cargo();
    cmd.current_dir(root)
        .args(["build",
               "--target", "riscv64gc-unknown-none-elf",
               "--no-default-features",
               "-Z", "build-std=core,alloc,compiler_builtins",
               "-Z", "build-std-features=compiler-builtins-mem"]);
    if !debug { cmd.arg("--release"); }
    run(cmd);
    let kernel_elf = root.join(format!("target/riscv64gc-unknown-none-elf/{profile}/rustos"));
    eprintln!("[xtask] Built: {}", kernel_elf.display());
    for tool in ["llvm-size", "size"] {
        if Command::new(tool).arg(&kernel_elf).status().is_ok() { break; }
    }
    if initrd {
        eprintln!("[xtask] Building RISC-V userspace + initramfs...");
        let mut cmd = Command::new("bash");
        cmd.current_dir(root).args(["tools/build_userspace.sh", "riscv64"]);
        run(cmd);
    }
}

fn build_x86_64(root: &PathBuf, debug: bool) {
    let profile = if debug { "debug" } else { "release" };
    eprintln!("[xtask] Building rustos (x86_64, {profile})...");
    let mut cmd = cargo();
    cmd.current_dir(root)
        .args(["build",
               "--target", "x86_64-unknown-none",
               "-Z", "build-std=core,alloc,compiler_builtins",
               "-Z", "build-std-features=compiler-builtins-mem"]);
    if !debug { cmd.arg("--release"); }
    run(cmd);
    let elf = root.join(format!("target/x86_64-unknown-none/{profile}/rustos"));
    let bin = root.join("kernel.bin");
    let mut objcopy = Command::new("objcopy");
    objcopy.args(["-O", "binary"]).arg(&elf).arg(&bin);
    run(objcopy);
    eprintln!("[xtask] Built: {}", bin.display());
}

// ── image action ─────────────────────────────────────────────────────────────

/// Build a bootable FAT32 ESP disk image using mtools (no root/loopback needed).
///
/// Layout:
///   Sector 0       : MBR with one FAT32 partition covering the whole image
///   Partition 1    : FAT32 ESP
///     EFI/BOOT/BOOTX64.EFI     (or BOOTRISCV64.EFI)
///     initramfs.cpio            (if present in workspace root)
///
/// The image is written to `<root>/boot.img` (x86_64) or
/// `<root>/boot-riscv64.img` (riscv64).
///
/// To flash to a USB drive:
///   sudo dd if=boot.img of=/dev/sdX bs=4M status=progress && sync
fn cmd_image(root: &PathBuf, opts: &ImageOpts) {
    require_tool("mformat");
    require_tool("mmd");
    require_tool("mcopy");

    // 1. Build the kernel first.
    let profile = if opts.debug { "debug" } else { "release" };
    match opts.arch {
        Arch::X86_64  => build_x86_64(root, opts.debug),
        Arch::RiscV64 => build_riscv_uefi(root, opts.debug),
    }

    // 2. Locate the EFI binary.
    let (efi_src, efi_dst_path, img_name) = match opts.arch {
        Arch::X86_64 => {
            // x86_64 build produces a raw ELF; we need the UEFI PE/EFI.
            // If the user has a separate UEFI build output, use that;
            // otherwise look for the objcopy'd kernel.bin and warn.
            //
            // Preferred: build with --target x86_64-unknown-uefi if available.
            // For now we look for rustos.efi produced by a UEFI-mode build.
            let candidates = [
                root.join(format!("target/x86_64-unknown-none/{profile}/rustos.efi")),
                root.join(format!("target/x86_64-unknown-none/{profile}/rustos")),
                root.join("esp/EFI/BOOT/BOOTX64.EFI"),
            ];
            let src = candidates.iter().find(|p| p.exists()).cloned().unwrap_or_else(|| {
                eprintln!("[xtask] ERROR: no x86_64 EFI binary found.");
                eprintln!("[xtask] Build with `--target x86_64-unknown-uefi` or copy");
                eprintln!("[xtask] your .efi to esp/EFI/BOOT/BOOTX64.EFI manually.");
                exit(1);
            });
            (src, "EFI/BOOT/BOOTX64.EFI", "boot.img")
        }
        Arch::RiscV64 => {
            let src = root.join("esp/EFI/BOOT/BOOTRISCV64.EFI");
            if !src.exists() {
                eprintln!("[xtask] ERROR: esp/EFI/BOOT/BOOTRISCV64.EFI not found.");
                exit(1);
            }
            (src, "EFI/BOOT/BOOTRISCV64.EFI", "boot-riscv64.img")
        }
    };

    let img_path = root.join(img_name);

    // 3. Create a blank 64 MiB image file.
    // 64 MiB is enough for the kernel + initramfs with room to spare.
    const IMG_SECTORS: u64 = 64 * 1024 * 1024 / 512; // 131072
    eprintln!("[xtask] Creating {img_name} ({} MiB)...", IMG_SECTORS * 512 / 1024 / 1024);

    // Truncate/create the image.
    let img_file = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(&img_path)
        .expect("create image file");
    img_file.set_len(IMG_SECTORS * 512).expect("set image size");
    drop(img_file);

    // 4. Format as FAT32 with mformat.
    // -i <img>  : operate on image file
    // -F        : force FAT32
    // -v RUSTOS : volume label
    // ::        : mtools drive letter (image file)
    let mut mformat = Command::new("mformat");
    mformat.args(["-i"]).arg(&img_path)
        .args(["-F", "-v", "RUSTOS", "::"]);
    run(mformat);

    // 5. Create EFI/BOOT directory.
    let mut mmd = Command::new("mmd");
    mmd.arg("-i").arg(&img_path)
        .args(["-s", "::EFI", "::EFI/BOOT"]);
    run(mmd);

    // 6. Copy kernel EFI.
    let dst = format!("::{}", efi_dst_path);
    let mut mcopy = Command::new("mcopy");
    mcopy.arg("-i").arg(&img_path)
        .arg(&efi_src).arg(&dst);
    run(mcopy);
    eprintln!("[xtask] Copied kernel → {efi_dst_path}");

    // 7. Copy initramfs if present.
    let initrd = root.join("initramfs.cpio");
    if initrd.exists() {
        let mut mcopy = Command::new("mcopy");
        mcopy.arg("-i").arg(&img_path)
            .arg(&initrd).arg("::initramfs.cpio");
        run(mcopy);
        eprintln!("[xtask] Copied initramfs.cpio → ::initramfs.cpio");
    } else {
        eprintln!("[xtask] Note: initramfs.cpio not found — image has no initrd.");
        eprintln!("[xtask]       Build with `cargo xtask build --initrd` first.");
    }

    eprintln!("");
    eprintln!("[xtask] ✓ Image ready: {}", img_path.display());
    eprintln!("");
    eprintln!("[xtask] Flash to USB:  sudo dd if={img_name} of=/dev/sdX bs=4M status=progress && sync");
    eprintln!("[xtask] Test in QEMU:  qemu-system-x86_64 -bios /usr/share/ovmf/OVMF.fd \\");
    eprintln!("[xtask]                  -drive format=raw,file={img_name} -serial stdio");
}

// ── entrypoint ────────────────────────────────────────────────────────────────

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
                (Arch::X86_64,  _)          => build_x86_64(&root, opts.debug),
            }
        }
        "image" => {
            let opts = parse_image_args(&rest);
            cmd_image(&root, &opts);
        }
        "help" | "--help" | "-h" | "" => {
            println!(concat!(
                "cargo xtask <subcommand> [options]\n",
                "\n",
                "Subcommands:\n",
                "  build    Compile the kernel\n",
                "  image    Build a bootable FAT32 ESP disk image (requires mtools)\n",
                "\n",
                "Build options:\n",
                "  --arch <riscv64|x86_64>   Target architecture  (default: riscv64)\n",
                "  --boot <uefi|sbi>         Boot mode (riscv64)  (default: uefi)\n",
                "  --debug                   Debug build          (default: release)\n",
                "  --initrd                  Build initramfs      (SBI only)\n",
                "\n",
                "Image options:\n",
                "  --arch <x86_64|riscv64>   Architecture to image (default: x86_64)\n",
                "  --debug                   Use debug build\n",
                "\n",
                "Examples:\n",
                "  cargo xtask build                            # riscv64 uefi release\n",
                "  cargo xtask build --arch x86_64\n",
                "  cargo xtask image                            # x86_64 boot.img\n",
                "  cargo xtask image --arch riscv64             # riscv64 boot-riscv64.img\n",
                "\n",
                "Flash to USB:\n",
                "  sudo dd if=boot.img of=/dev/sdX bs=4M status=progress && sync\n"
            ));
        }
        other => {
            eprintln!("[xtask] unknown subcommand: {other:?}. Try `cargo xtask help`.");
            exit(1);
        }
    }
}
