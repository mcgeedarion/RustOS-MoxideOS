//! cargo xtask — build automation for RustOS.
//!
//! Usage:
//!   cargo xtask build                            # riscv64, uefi, release (default)
//!   cargo xtask build --arch riscv64 --boot uefi
//!   cargo xtask build --arch riscv64 --boot sbi
//!   cargo xtask build --arch x86_64
//!   cargo xtask build --arch riscv64 --boot sbi --debug
//!   cargo xtask build --arch riscv64 --boot sbi --initrd
//!
//!   cargo xtask image                            # x86_64 release ESP image
//!   cargo xtask image --arch riscv64             # riscv64 release ESP image
//!   cargo xtask image --arch x86_64 --debug      # x86_64 debug ESP image
//!   cargo xtask image --arch x86_64 --initrd     # include initramfs.cpio
//!
//! The `image` subcommand requires mtools (mformat, mmd, mcopy) and
//! objcopy (binutils / llvm-objcopy).  Install hint is printed if missing.

use std::{
    env,
    path::PathBuf,
    process::{Command, exit},
};

// ─── helpers ──────────────────────────────────────────────────────────────────

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

/// Return the first binary name from the list that exists somewhere on PATH.
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

/// Abort with a friendly message if a required tool is not on PATH.
fn require_tool(names: &[&str], install_hint: &str) -> String {
    match which_first(names) {
        Some(t) => t,
        None => {
            eprintln!(
                "[xtask] ERROR: none of {:?} found on PATH.",
                names
            );
            eprintln!("[xtask] Install with: {install_hint}");
            exit(1);
        }
    }
}

// ─── CLI parsing ──────────────────────────────────────────────────────────────

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

// ─── build actions ────────────────────────────────────────────────────────────

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
    if !debug { cmd.arg("--release"); }
    run(cmd);

    let efi_with    = root.join(format!("target/riscv64-uefi/{profile}/rustos.efi"));
    let efi_without = root.join(format!("target/riscv64-uefi/{profile}/rustos"));
    let kernel_efi = if efi_with.exists() { efi_with }
                     else if efi_without.exists() { efi_without }
                     else {
                         eprintln!("[xtask] ERROR: could not find EFI binary under target/riscv64-uefi/{profile}/");
                         exit(1);
                     };

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

    for tool in ["llvm-size", "size"] {
        if Command::new(tool).arg(&kernel_elf).status().is_ok() { break; }
    }

    if initrd {
        eprintln!("[xtask] Building RISC-V userspace + initramfs...");
        run(Command::new("bash")
            .current_dir(root)
            .args(["tools/build_userspace.sh", "riscv64"]));
        eprintln!("[xtask] Initramfs: {}", root.join("initramfs.cpio").display());
    }
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
    if !debug { cmd.arg("--release"); }
    run(cmd);

    let elf = root.join(format!("target/x86_64-unknown-none/{profile}/rustos"));
    let bin = root.join("kernel.bin");
    run(Command::new("objcopy").args(["-O", "binary"]).arg(&elf).arg(&bin));
    eprintln!("[xtask] Built: {}", bin.display());
}

// ─── image action ─────────────────────────────────────────────────────────────

/// `cargo xtask image [--arch <x86_64|riscv64>] [--debug] [--initrd]`
///
/// Produces `boot.img` (x86_64) or `boot-riscv64.img` (riscv64) in the
/// workspace root.  The image is a raw FAT32 ESP you can `dd` directly to
/// a USB drive or pass to QEMU with `-drive format=raw,file=boot.img`.
///
/// Requires: mtools (mformat, mmd, mcopy) + objcopy / llvm-objcopy.
fn image(root: &PathBuf, opts: &BuildOpts) {
    // ── pre-flight tool checks ──────────────────────────────────────────────
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

    // ── build the kernel first ──────────────────────────────────────────────
    eprintln!("[xtask] image: building kernel...");
    match (opts.arch, opts.boot) {
        (Arch::RiscV64, Boot::Uefi) => build_riscv_uefi(root, opts.debug),
        (Arch::RiscV64, Boot::Sbi)  => build_riscv_sbi(root, opts.debug, opts.initrd),
        (Arch::X86_64,  _)          => build_x86_64(root, opts.debug),
    }

    // ── locate the EFI / ELF output ────────────────────────────────────────
    let profile = if opts.debug { "debug" } else { "release" };

    let (efi_name, img_name) = match opts.arch {
        Arch::X86_64  => ("BOOTx64.EFI",      "boot.img"),
        Arch::RiscV64 => ("BOOTRISCV64.EFI",  "boot-riscv64.img"),
    };

    // For x86_64 we need to produce the PE EFI file from the ELF.
    // For riscv64/uefi the EFI binary is already in esp/EFI/BOOT/.
    let efi_path = root.join("esp/EFI/BOOT").join(efi_name);

    if opts.arch == Arch::X86_64 {
        let elf = root.join(format!("target/x86_64-unknown-none/{profile}/rustos"));
        if !elf.exists() {
            eprintln!("[xtask] ERROR: kernel ELF not found at {}", elf.display());
            exit(1);
        }
        let esp_dir = root.join("esp/EFI/BOOT");
        std::fs::create_dir_all(&esp_dir).expect("create esp dir");
        // Strip to a flat binary then convert to PE EFI.
        // objcopy can emit PE-COFF directly with --target efi-app-x86-64.
        run(Command::new(&objcopy)
            .args(["--target", "efi-app-x86-64",
                   "--subsystem", "10"]) // EFI application
            .arg(&elf)
            .arg(&efi_path));
    }

    if !efi_path.exists() {
        eprintln!("[xtask] ERROR: EFI binary not found at {}", efi_path.display());
        eprintln!("[xtask]        Did the build step succeed?");
        exit(1);
    }

    // ── create the FAT32 disk image ─────────────────────────────────────────
    let img_path = root.join(img_name);

    // mformat: create a 64 MiB FAT32 image.
    // -C = create image file, -F = FAT32, -h 64 -s 32 = 64 sectors/track * 32
    // tracks = 2048 sectors * 512 bytes = 1 MiB clusters; -S 512 = sector size.
    // Total size: 131072 sectors * 512 = 64 MiB.
    run(Command::new("mformat")
        .args(["-C", "-F",
               "-h", "64",
               "-s", "32",
               "-t", "64",    // 64 cylinders → 64*64*32*512 = 64 MiB
               "-i"])
        .arg(&img_path)
        .arg("::"));

    // mmd: create the EFI/BOOT directory tree inside the image.
    run(Command::new("mmd")
        .args(["-i"])
        .arg(&img_path)
        .args(["::/EFI", "::/EFI/BOOT"]));

    // mcopy: copy the EFI binary into the image.
    run(Command::new("mcopy")
        .args(["-i"])
        .arg(&img_path)
        .arg(&efi_path)
        .arg(format!("::/EFI/BOOT/{efi_name}")));

    // Optionally embed the initramfs on the ESP root.
    if opts.initrd {
        let cpio = root.join("initramfs.cpio");
        if cpio.exists() {
            run(Command::new("mcopy")
                .args(["-i"])
                .arg(&img_path)
                .arg(&cpio)
                .arg("::/initramfs.cpio"));
            eprintln!("[xtask] Embedded initramfs: {}", cpio.display());
        } else {
            eprintln!("[xtask] WARNING: --initrd specified but initramfs.cpio not found.");
            eprintln!("[xtask]          Run `cargo xtask build --arch riscv64 --boot sbi --initrd` first.");
        }
    }

    // ── success banner ─────────────────────────────────────────────────────
    eprintln!("\n[xtask] ✓ Image ready: {}", img_path.display());
    eprintln!("\n  Flash to USB:");
    eprintln!("    sudo dd if={} of=/dev/sdX bs=4M status=progress && sync",
        img_path.display());
    match opts.arch {
        Arch::X86_64 => {
            eprintln!("\n  Smoke-test in QEMU (before flashing):");
            eprintln!("    qemu-system-x86_64 \\");
            eprintln!("      -bios /usr/share/ovmf/OVMF.fd \\");
            eprintln!("      -drive format=raw,file={} \\", img_path.display());
            eprintln!("      -serial stdio -nographic -m 512M");
        }
        Arch::RiscV64 => {
            eprintln!("\n  Smoke-test in QEMU (before flashing):");
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

// ─── entrypoint ───────────────────────────────────────────────────────────────

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
            // Default arch for `image` is x86_64 (most common real-hardware target).
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
                "  --boot <uefi|sbi>         Boot mode (riscv64)  (default: uefi)\n",
                "  --debug                   Debug build          (default: release)\n",
                "  --initrd                  Build/include initramfs\n",
                "\n",
                "image requires:\n",
                "  mtools   (mformat, mmd, mcopy)  →  apt install mtools\n",
                "  objcopy  (binutils/llvm)        →  apt install binutils\n",
                "\n",
                "Examples:\n",
                "  cargo xtask build                              # riscv64 uefi release\n",
                "  cargo xtask build --arch x86_64               # x86_64 release\n",
                "  cargo xtask image                             # x86_64 boot.img\n",
                "  cargo xtask image --arch riscv64              # riscv64 boot-riscv64.img\n",
                "  cargo xtask image --arch x86_64 --initrd      # with initramfs.cpio\n",
                "  cargo xtask image --arch x86_64 --debug       # debug build image\n"
            ));
        }
        other => {
            eprintln!("[xtask] unknown subcommand: {other:?}. Try `cargo xtask help`.");
            exit(1);
        }
    }
}
