//! cargo xtask — build automation for RustOS.
//!
//! Canonical build/run contract:
//!   aarch64: uefi | baremetal
//!   riscv64: uefi | sbi
//!   x86_64:  uefi
//!
//! Canonical ESP staging path:
//!   target/esp/<arch>/EFI/BOOT/BOOT*.EFI

use anyhow::{bail, Context, Result};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{exit, Command},
};

const OS_RELEASE_CONTENT: &[u8] =
    b"NAME=RustOS\nID=rustos\nVERSION=0.1.0\nPRETTY_NAME=\"RustOS 0.1.0\"\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    AArch64,
    RiscV64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boot {
    Uefi,
    Sbi,
    Baremetal,
}

#[derive(Debug, Clone)]
struct BuildOpts {
    arch: Arch,
    boot: Boot,
    debug: bool,
    initrd: bool,
    features: Option<String>,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            boot: Boot::Uefi,
            debug: false,
            initrd: false,
            features: None,
        }
    }
}

fn log(msg: impl AsRef<str>) {
    eprintln!("[xtask] {}", msg.as_ref());
}

fn arch_str(arch: Arch) -> &'static str {
    match arch {
        Arch::AArch64 => "aarch64",
        Arch::RiscV64 => "riscv64",
        Arch::X86_64 => "x86_64",
    }
}

fn boot_str(boot: Boot) -> &'static str {
    match boot {
        Boot::Uefi => "uefi",
        Boot::Sbi => "sbi",
        Boot::Baremetal => "baremetal",
    }
}

fn validate_contract(arch: Arch, boot: Boot) -> Result<()> {
    match (arch, boot) {
        (Arch::AArch64, Boot::Uefi | Boot::Baremetal) => Ok(()),
        (Arch::RiscV64, Boot::Uefi | Boot::Sbi) => Ok(()),
        (Arch::X86_64, Boot::Uefi) => Ok(()),
        _ => bail!(
            "unsupported build contract: {} --boot {}",
            arch_str(arch),
            boot_str(boot)
        ),
    }
}

fn target_json(root: &Path, arch: Arch, boot: Boot) -> PathBuf {
    match (arch, boot) {
        (Arch::AArch64, Boot::Uefi) => root.join("targets/aarch64-uefi-loader.json"),
        (Arch::AArch64, Boot::Baremetal) => root.join("targets/aarch64-kernel.json"),
        (Arch::RiscV64, Boot::Uefi) => root.join("targets/riscv64-uefi-loader.json"),
        (Arch::RiscV64, Boot::Sbi) => PathBuf::from("riscv64gc-unknown-none-elf"),
        // Use the upstream built-in target. The custom JSON spec (with
        // `is-like-windows`/`is-like-msvc`) triggers `compiler_builtins`
        // assembly errors under current nightly.
        (Arch::X86_64, Boot::Uefi) => PathBuf::from("x86_64-unknown-uefi"),
        _ => unreachable!("validate_contract must run before target_json"),
    }
}

fn target_dir_name(arch: Arch, boot: Boot) -> &'static str {
    match (arch, boot) {
        (Arch::AArch64, Boot::Uefi) => "aarch64-uefi-loader",
        (Arch::AArch64, Boot::Baremetal) => "aarch64-kernel",
        (Arch::RiscV64, Boot::Uefi) => "riscv64-uefi-loader",
        (Arch::RiscV64, Boot::Sbi) => "riscv64gc-unknown-none-elf",
        (Arch::X86_64, Boot::Uefi) => "x86_64-unknown-uefi",
        _ => unreachable!("validate_contract must run before target_dir_name"),
    }
}

fn efi_boot_filename(arch: Arch) -> &'static str {
    match arch {
        Arch::AArch64 => "BOOTAA64.EFI",
        Arch::RiscV64 => "BOOTRISCV64.EFI",
        Arch::X86_64 => "BOOTX64.EFI",
    }
}

fn image_name(arch: Arch) -> &'static str {
    match arch {
        Arch::AArch64 => "boot-aarch64.img",
        Arch::RiscV64 => "boot-riscv64.img",
        Arch::X86_64 => "boot-x86_64.img",
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has no parent directory")
        .to_path_buf()
}

fn profile(opts: &BuildOpts) -> &'static str {
    if opts.debug {
        "debug"
    } else {
        "release"
    }
}

fn build_output_path(root: &Path, opts: &BuildOpts) -> PathBuf {
    root.join("target")
        .join(target_dir_name(opts.arch, opts.boot))
        .join(profile(opts))
}

fn artifact_path(root: &Path, opts: &BuildOpts) -> Option<PathBuf> {
    let base = build_output_path(root, opts).join("rustos");
    let efi = base.with_extension("efi");
    if opts.boot == Boot::Uefi && efi.exists() {
        Some(efi)
    } else if base.exists() {
        Some(base)
    } else {
        None
    }
}

fn esp_boot_dir(root: &Path, arch: Arch) -> PathBuf {
    root.join("target/esp")
        .join(arch_str(arch))
        .join("EFI/BOOT")
}

fn cargo() -> Command {
    Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
}

fn run(cmd: &mut Command) -> Result<()> {
    log(format!("running: {:?}", cmd));
    let status = cmd.status().context("failed to spawn command")?;
    if !status.success() {
        bail!("command failed with {status}");
    }
    Ok(())
}

fn which_first(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        Command::new("sh")
            .args(["-c", &format!("command -v {name} >/dev/null 2>&1")])
            .status()
            .ok()
            .filter(|status| status.success())
            .map(|_| (*name).to_string())
    })
}

fn require_tool(names: &[&str], install_hint: &str) {
    if which_first(names).is_none() {
        eprintln!("[xtask] ERROR: none of {:?} found on PATH", names);
        eprintln!("[xtask] Install with: {install_hint}");
        exit(1);
    }
}

fn parse_build_args(args: &[String]) -> BuildOpts {
    let mut opts = BuildOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--arch" => {
                i += 1;
                opts.arch = match args.get(i).map(String::as_str) {
                    Some("aarch64") => Arch::AArch64,
                    Some("riscv64") => Arch::RiscV64,
                    Some("x86_64") => Arch::X86_64,
                    other => {
                        eprintln!("[xtask] unknown --arch: {:?}", other);
                        exit(1);
                    },
                };
            },
            "--boot" => {
                i += 1;
                opts.boot = match args.get(i).map(String::as_str) {
                    Some("uefi") => Boot::Uefi,
                    Some("sbi") => Boot::Sbi,
                    Some("baremetal") | Some("bare-metal") => Boot::Baremetal,
                    other => {
                        eprintln!("[xtask] unknown --boot: {:?}", other);
                        exit(1);
                    },
                };
            },
            "--features" => {
                i += 1;
                opts.features = args.get(i).cloned();
            },
            "--debug" => opts.debug = true,
            "--initrd" => opts.initrd = true,
            other => {
                eprintln!("[xtask] unknown argument: {other}");
                exit(1);
            },
        }
        i += 1;
    }
    opts
}

fn add_build_std_flags(cmd: &mut Command) {
    cmd.args([
        "-Z",
        "build-std=core,alloc,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
        "-Z",
        "json-target-spec",
    ]);
}

fn build_kernel(root: &Path, opts: &BuildOpts) -> Result<()> {
    validate_contract(opts.arch, opts.boot)?;

    let mut cmd = cargo();
    cmd.current_dir(root)
        .args(["build", "--target"])
        .arg(target_json(root, opts.arch, opts.boot));
    add_build_std_flags(&mut cmd);
    if !opts.debug {
        cmd.arg("--release");
    }
    match &opts.features {
        Some(features) => {
            cmd.arg("--features").arg(features);
        },
        None if opts.boot == Boot::Uefi => {
            cmd.arg("--features").arg("uefi_boot");
        },
        None => {},
    }
    run(&mut cmd)?;

    if opts.boot == Boot::Uefi {
        install_efi(root, opts)?;
    }
    if opts.initrd {
        mkinitramfs(root, opts.arch)?;
    }
    log(format!(
        "built {} {} {}",
        arch_str(opts.arch),
        boot_str(opts.boot),
        profile(opts)
    ));
    Ok(())
}

fn install_efi(root: &Path, opts: &BuildOpts) -> Result<()> {
    let src = artifact_path(root, opts).with_context(|| {
        format!(
            "UEFI artifact not found under {}",
            build_output_path(root, opts).display()
        )
    })?;
    let dest_dir = esp_boot_dir(root, opts.arch);
    fs::create_dir_all(&dest_dir).context("create ESP boot directory")?;
    let dest = dest_dir.join(efi_boot_filename(opts.arch));
    fs::copy(&src, &dest).context("copy EFI artifact into ESP")?;
    log(format!("installed EFI: {}", dest.display()));
    Ok(())
}

fn require_initramfs_tools(arch: Arch) -> Result<()> {
    match arch {
        Arch::X86_64 => require_tool(&["musl-gcc"], "apt install musl-tools"),
        Arch::RiscV64 => require_tool(
            &["riscv64-linux-musl-gcc", "riscv64-unknown-linux-musl-gcc"],
            "install a riscv64 musl cross compiler",
        ),
        Arch::AArch64 => {
            bail!("aarch64 initramfs is disabled until userspace/Makefile supports ARCH=aarch64")
        },
    }
    require_tool(&["cpio"], "apt install cpio");
    require_tool(&["find"], "coreutils should provide find");
    Ok(())
}

fn mkinitramfs(root: &Path, arch: Arch) -> Result<()> {
    require_initramfs_tools(arch)?;
    let arch_name = arch_str(arch);
    let staging = root.join(format!("target/initramfs-staging-{arch_name}"));
    if staging.exists() {
        fs::remove_dir_all(&staging).context("remove old initramfs staging dir")?;
    }
    for dir in [
        "", "bin", "sbin", "usr/bin", "usr/sbin", "lib", "etc", "dev", "proc", "sys", "tmp", "run",
    ] {
        fs::create_dir_all(staging.join(dir)).context("create initramfs subdir")?;
    }
    run(Command::new("make")
        .current_dir(root.join("userspace"))
        .args([
            "-j4",
            &format!("ARCH={arch_name}"),
            &format!("DESTDIR={}", staging.display()),
            "install",
        ]))?;
    fs::write(staging.join("etc/os-release"), OS_RELEASE_CONTENT).context("write os-release")?;
    let cpio_out = root.join("initramfs.cpio");
    run(Command::new("sh").current_dir(&staging).args([
        "-c",
        &format!(
            "find . | sort | cpio --create --format=newc --quiet > {}",
            cpio_out.display()
        ),
    ]))?;
    Ok(())
}

fn image(root: &Path, opts: &BuildOpts) -> Result<()> {
    validate_contract(opts.arch, opts.boot)?;
    if opts.boot != Boot::Uefi {
        bail!("image is only supported for UEFI boots; use `cargo xtask build` for non-UEFI");
    }
    for tool in ["mformat", "mmd", "mcopy"] {
        require_tool(&[tool], "apt install mtools");
    }
    build_kernel(root, opts)?;
    let efi_name = efi_boot_filename(opts.arch);
    let efi_path = esp_boot_dir(root, opts.arch).join(efi_name);
    if !efi_path.exists() {
        bail!("EFI binary not found at {}", efi_path.display());
    }
    let img_path = root.join(image_name(opts.arch));
    run(Command::new("mformat")
        .args(["-C", "-F", "-h", "64", "-s", "32", "-t", "64", "-i"])
        .arg(&img_path)
        .arg("::"))?;
    run(Command::new("mmd")
        .args(["-i"])
        .arg(&img_path)
        .args(["::/EFI", "::/EFI/BOOT"]))?;
    run(Command::new("mcopy")
        .args(["-i"])
        .arg(&img_path)
        .arg(&efi_path)
        .arg(format!("::/EFI/BOOT/{efi_name}")))?;
    log(format!("image ready: {}", img_path.display()));
    Ok(())
}

fn smoke(root: &Path) -> Result<()> {
    let script = root.join("scripts/ci/run_qemu.sh");
    if !script.exists() {
        bail!("QEMU runner not found at {}", script.display());
    }
    run(Command::new(&script)
        .current_dir(root)
        .env("ARCH", "x86_64")
        .arg("--boot")
        .arg("uefi"))
}

fn print_help() {
    println!(
        "cargo xtask <subcommand> [options]\n\n\
Subcommands:\n\
  build         Compile the kernel\n\
  mkinitramfs   Build userspace and pack initramfs.cpio\n\
  image         Build a FAT ESP disk image for UEFI\n\
  smoke         Run x86_64 UEFI under QEMU\n\
  help          Show this help\n\n\
Build options:\n\
  --arch <aarch64|riscv64|x86_64>\n\
  --boot <uefi|sbi|baremetal>\n\
  --features <features>\n\
  --debug\n\
  --initrd"
    );
}

fn main() {
    let mut args = env::args().skip(1);
    let subcommand = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();
    let root = workspace_root();
    let result = match subcommand.as_str() {
        "build" => build_kernel(&root, &parse_build_args(&rest)),
        "mkinitramfs" => {
            let opts = parse_build_args(&rest);
            mkinitramfs(&root, opts.arch)
        },
        "image" => image(&root, &parse_build_args(&rest)),
        "smoke" => smoke(&root),
        "help" | "--help" | "-h" | "" => {
            print_help();
            Ok(())
        },
        other => bail!("unknown subcommand: {other:?}. Try `cargo xtask help`."),
    };
    if let Err(error) = result {
        eprintln!("[xtask] ERROR: {error:#}");
        exit(1);
    }
}
