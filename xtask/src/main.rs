//! cargo xtask — build automation for RustOS.
//!
//! Usage:
//!   cargo xtask build                              # riscv64, uefi, release (default)
//!   cargo xtask build --arch riscv64 --boot uefi
//!   cargo xtask build --arch riscv64 --boot sbi
//!   cargo xtask build --arch x86_64               # x86_64 kernel (ELF, no UEFI wrapper)
//!   cargo xtask build --arch x86_64 --boot uefi   # x86_64 UEFI loader (PE32+)
//!   cargo xtask build --arch x86_64 --boot uefi --initrd
//!
//!   cargo xtask mkinitramfs                        # x86_64 initramfs (default)
//!   cargo xtask mkinitramfs --arch riscv64
//!
//!   cargo xtask image                              # x86_64 release ESP image
//!   cargo xtask image --arch riscv64               # riscv64 release ESP image
//!   cargo xtask image --arch x86_64 --debug        # x86_64 debug ESP image
//!   cargo xtask image --arch x86_64 --initrd       # include initramfs.cpio
//!
//!   cargo xtask smoke                              # x86_64 QEMU smoke test (headless)
//!
//! The `image` subcommand requires mtools (mformat, mmd, mcopy) and
//! objcopy (binutils / llvm-objcopy).  Install hint is printed if missing.
//!
//! The `mkinitramfs` subcommand requires:
//!   x86_64:  musl-tools  (musl-gcc)           → apt install musl-tools
//!   riscv64: riscv64-linux-musl-gcc            → build from source or distro pkg
//!   Both:    cpio                              → apt install cpio
//!
//! Device node creation (step 2b) requires root or sudo on the build host.
//! In rootless CI containers the mknod calls are skipped with a warning;
//! the kernel's devtmpfs populates /dev at runtime regardless.

use std::{
    env,
    fs,
    path::PathBuf,
    process::{Command, exit},
};

// ─── target JSON paths ───────────────────────────────────────────────────────────────

fn target_json(root: &PathBuf, arch: Arch, boot: Boot) -> PathBuf {
    let name = match (arch, boot) {
        (Arch::X86_64,  Boot::Uefi) => "x86_64-uefi-loader.json",
        (Arch::X86_64,  Boot::Sbi)  => "x86_64-kernel.json",
        (Arch::RiscV64, Boot::Uefi) => "riscv64-uefi-loader.json",
        (Arch::RiscV64, Boot::Sbi)  => "riscv64-kernel.json",
    };
    root.join("targets").join(name)
}

fn target_dir_name(arch: Arch, boot: Boot) -> &'static str {
    match (arch, boot) {
        (Arch::X86_64,  Boot::Uefi) => "x86_64-uefi-loader",
        (Arch::X86_64,  Boot::Sbi)  => "x86_64-kernel",
        (Arch::RiscV64, Boot::Uefi) => "riscv64-uefi-loader",
        (Arch::RiscV64, Boot::Sbi)  => "riscv64gc-unknown-none-elf",
    }
}

fn efi_boot_filename(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64  => "BOOTx64.EFI",
        Arch::RiscV64 => "BOOTRISCV64.EFI",
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().expect("xtask has no parent directory")
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

/// Like `run()` but returns `false` instead of exiting on failure.
/// Used for privileged operations (mknod) that may legitimately fail
/// in rootless CI environments.
fn run_optional(mut cmd: Command) -> bool {
    eprintln!("[xtask] running (optional): {:?}", cmd);
    match cmd.status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("[xtask] optional command exited with {s} — skipping");
            false
        }
        Err(e) => {
            eprintln!("[xtask] optional command failed to spawn: {e} — skipping");
            false
        }
    }
}

fn run_capture(mut cmd: Command) -> String {
    eprintln!("[xtask] running (capture): {:?}", cmd);
    let output = cmd.output().expect("failed to spawn command");
    if !output.status.success() {
        eprintln!("[xtask] command failed with {}", output.status);
        exit(output.status.code().unwrap_or(1));
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn which_first(names: &[&str]) -> Option<String> {
    for name in names {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {name}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if found { return Some((*name).into()); }
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

// ─── CLI parsing ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum Arch { RiscV64, X86_64 }

#[derive(Debug, Clone, Copy, PartialEq)]
enum Boot { Uefi, Sbi }

#[derive(Debug)]
struct BuildOpts {
    arch:   Arch,
    boot:   Boot,
    debug:  bool,
    initrd: bool,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self { arch: Arch::RiscV64, boot: Boot::Uefi, debug: false, initrd: false }
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
            other => { eprintln!("[xtask] unknown argument: {other}"); exit(1); }
        }
        i += 1;
    }
    opts
}

// ─── device node table ────────────────────────────────────────────────────────────
//
// Each entry: (path-inside-staging, type, major, minor, permissions)
//
// Canonical Linux major:minor assignments:
//   mem  major 1 — null(3), zero(5)
//   tty  major 5 — tty(0)
//   drm  major 226 — card0(0) … card15(15)
//   input major 13 — event0(64) … event31(95)
//
// The kernel's devtmpfs will recreate these at runtime; the pre-baked
// nodes only matter for the window before devtmpfs is mounted (i.e. the
// very first open() calls from init).

struct DevNode {
    /// Path relative to the staging root, e.g. "dev/null"
    path:  &'static str,
    /// 'c' for character, 'b' for block
    kind:  char,
    major: u32,
    minor: u32,
    /// octal permissions, e.g. 0o666
    mode:  u32,
}

const DEV_NODES: &[DevNode] = &[
    DevNode { path: "dev/null",        kind: 'c', major: 1,   minor: 3,  mode: 0o666 },
    DevNode { path: "dev/zero",        kind: 'c', major: 1,   minor: 5,  mode: 0o666 },
    DevNode { path: "dev/tty",         kind: 'c', major: 5,   minor: 0,  mode: 0o666 },
    DevNode { path: "dev/dri/card0",   kind: 'c', major: 226, minor: 0,  mode: 0o660 },
    DevNode { path: "dev/input/event0",kind: 'c', major: 13,  minor: 64, mode: 0o660 },
];

/// Create device nodes in the staging tree.
///
/// Tries three strategies in order:
///   1. Direct `mknod` (works when running as root).
///   2. `sudo mknod` (works when the build user has passwordless sudo).
///   3. Skip with a warning (rootless CI containers — devtmpfs handles it at boot).
///
/// Sets permissions with `chmod` after each successful mknod.
fn create_dev_nodes(staging: &PathBuf) {
    // Detect whether we can use mknod at all.
    let have_mknod = which_first(&["mknod"]).is_some();
    if !have_mknod {
        eprintln!("[xtask] mkinitramfs: WARNING: mknod not found — skipping device nodes");
        eprintln!("[xtask]   Install with: apt install coreutils");
        eprintln!("[xtask]   Devices will be created by the kernel's devtmpfs at runtime.");
        return;
    }

    // Try to figure out if we are root; if not, prepend sudo.
    let is_root = unsafe { libc_getuid() } == 0;

    let mut created = 0usize;
    let mut skipped = 0usize;

    for node in DEV_NODES {
        let full_path = staging.join(node.path);
        let type_str  = node.kind.to_string();
        let major_str = node.major.to_string();
        let minor_str = node.minor.to_string();
        let mode_str  = format!("{:04o}", node.mode);

        // Build the mknod command.
        let ok = if is_root {
            run_optional(Command::new("mknod")
                .arg(&full_path)
                .arg(&type_str)
                .arg(&major_str)
                .arg(&minor_str))
        } else {
            run_optional(Command::new("sudo")
                .args(["mknod"])
                .arg(&full_path)
                .arg(&type_str)
                .arg(&major_str)
                .arg(&minor_str))
        };

        if ok {
            // Set permissions.  Use sudo if we used sudo for mknod.
            let chmod_ok = if is_root {
                run_optional(Command::new("chmod")
                    .arg(&mode_str)
                    .arg(&full_path))
            } else {
                run_optional(Command::new("sudo")
                    .args(["chmod"])
                    .arg(&mode_str)
                    .arg(&full_path))
            };
            if chmod_ok {
                eprintln!("[xtask] mkinitramfs: created {} ({} {}:{} mode {})",
                    node.path, node.kind, node.major, node.minor, mode_str);
                created += 1;
            } else {
                eprintln!("[xtask] mkinitramfs: mknod ok but chmod failed for {}", node.path);
                created += 1; // node exists, just wrong perms
            }
        } else {
            eprintln!("[xtask] mkinitramfs: WARNING: could not create {} — skipping", node.path);
            skipped += 1;
        }
    }

    if skipped > 0 {
        eprintln!("[xtask] mkinitramfs: {created} device node(s) created, \
                   {skipped} skipped (no root/sudo).");
        eprintln!("[xtask]   The kernel's devtmpfs will create missing nodes at runtime.");
    } else {
        eprintln!("[xtask] mkinitramfs: all {} device node(s) created.", created);
    }
}

// Thin FFI shim — avoids a full libc dependency in the xtask.
// getuid() is always available on Linux/macOS.
#[cfg(unix)]
fn libc_getuid() -> u32 {
    extern "C" { fn getuid() -> u32; }
    unsafe { getuid() }
}
#[cfg(not(unix))]
fn libc_getuid() -> u32 { 1000 } // non-root on Windows (mknod not applicable)

// ─── mkinitramfs ────────────────────────────────────────────────────────────────────

/// Build userspace binaries and pack them into `initramfs.cpio`.
///
/// CPIO archive layout (newc format):
///   ./init                         ← PID 1
///   ./bin/hello
///   ./usr/bin/rustos-compositor
///   ./dev/null   c 1:3
///   ./dev/zero   c 1:5
///   ./dev/tty    c 5:0
///   ./dev/dri/card0    c 226:0
///   ./dev/input/event0 c 13:64
///   ./etc/os-release
///   ./proc/  ./sys/  ./tmp/  ./run/  (empty mount-point dirs)
pub fn mkinitramfs(root: &PathBuf, arch: Arch) {
    let arch_str = match arch {
        Arch::X86_64  => "x86_64",
        Arch::RiscV64 => "riscv64",
    };

    // ── 1. Check prerequisites ──────────────────────────────────────────────────
    match arch {
        Arch::X86_64 => {
            require_tool(&["musl-gcc"], "apt install musl-tools");
        }
        Arch::RiscV64 => {
            require_tool(
                &["riscv64-linux-musl-gcc", "riscv64-unknown-linux-musl-gcc"],
                "build musl from source: https://musl.libc.org/  (target: riscv64-linux-musl)",
            );
        }
    }
    require_tool(&["cpio"], "apt install cpio");
    require_tool(&["find"], "coreutils (should already be installed)");

    // ── 2. Create staging directory + rootfs skeleton ──────────────────────────
    let staging = root.join(format!("target/initramfs-staging-{arch_str}"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging).expect("remove old staging dir");
    }

    for dir in &[
        "",
        "bin", "sbin",
        "usr/bin", "usr/sbin",
        "lib",
        "etc",
        "dev", "dev/dri", "dev/input",
        "proc", "sys", "tmp", "run", "var", "root",
    ] {
        std::fs::create_dir_all(staging.join(dir))
            .expect("create staging subdir");
    }

    // ── 2b. Device nodes ────────────────────────────────────────────────────────
    //
    // Pre-bake character device inodes into the CPIO so that init's very
    // first open("/dev/null"), open("/dev/tty"), open("/dev/dri/card0"),
    // and open("/dev/input/event0") succeed before devtmpfs is mounted.
    //
    // Nodes: null(1:3)  zero(1:5)  tty(5:0)  card0(226:0)  event0(13:64)
    eprintln!("[xtask] mkinitramfs: creating device nodes...");
    create_dev_nodes(&staging);

    // ── 3. Build userspace binaries ──────────────────────────────────────────
    let userspace_dir = root.join("userspace");
    eprintln!("[xtask] mkinitramfs: building userspace ({arch_str})...");
    run(Command::new("make")
        .current_dir(&userspace_dir)
        .args(["-j4",
               &format!("ARCH={arch_str}"),
               &format!("DESTDIR={}", staging.display()),
               "install"]));

    // ── 4. Write /etc/os-release ────────────────────────────────────────────
    std::fs::write(
        staging.join("etc/os-release"),
        b"NAME=RustOS\nID=rustos\nVERSION=0.1.0\nPRETTY_NAME=\"RustOS 0.1.0\"\n",
    ).expect("write os-release");

    // ── 5. Pack CPIO (newc format) ───────────────────────────────────────────
    //
    // Sorting `find` output ensures reproducible archive ordering.
    // `--reproducible` (cpio ≥ 2.13) zeroes mtime; fall back silently.
    let cpio_out = root.join("initramfs.cpio");
    eprintln!("[xtask] mkinitramfs: packing {}...", cpio_out.display());
    run(Command::new("sh")
        .current_dir(&staging)
        .args([
            "-c",
            &format!(
                "find . | sort | cpio --create --format=newc --quiet > {}",
                cpio_out.display()
            ),
        ]));

    let size = std::fs::metadata(&cpio_out)
        .map(|m| m.len())
        .unwrap_or(0);
    eprintln!("[xtask] mkinitramfs: {} bytes → {}", size, cpio_out.display());
    eprintln!();
    eprintln!("  Included device nodes:");
    for n in DEV_NODES {
        eprintln!("    /{:<24} {} {:3}:{}", n.path, n.kind, n.major, n.minor);
    }
    eprintln!();
    eprintln!("  To include in a boot image:");
    eprintln!("    cargo xtask image --arch {arch_str} --initrd");
    eprintln!();
    eprintln!("  QEMU smoke-test:");
    eprintln!("    qemu-system-x86_64 \\");
    eprintln!("      -bios /usr/share/ovmf/OVMF.fd \\");
    eprintln!("      -kernel esp/EFI/BOOT/BOOTx64.EFI \\");
    eprintln!("      -initrd initramfs.cpio \\");
    eprintln!("      -serial stdio -nographic -m 512M");
}

// ─── mkinitramfs step (called by build_* when --initrd is set) ────────────────

fn mkinitramfs_step(root: &PathBuf, arch: Arch) {
    eprintln!("[xtask] --initrd: building initramfs for {arch:?}...");
    mkinitramfs(root, arch);
}

// ─── build actions ────────────────────────────────────────────────────────────────

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

    if initrd { mkinitramfs_step(root, Arch::RiscV64); }
}

fn build_x86_64_kernel(root: &PathBuf, debug: bool, initrd: bool) {
    build_with_target_json(
        root,
        &BuildOpts { arch: Arch::X86_64, boot: Boot::Sbi, debug, initrd: false },
        &[],
    );
    let profile = if debug { "debug" } else { "release" };
    let elf = root.join(format!("target/x86_64-kernel/{profile}/rustos"));
    let bin = root.join("kernel.bin");
    let objcopy = require_tool(&["llvm-objcopy", "objcopy"], "apt install llvm binutils");
    run(Command::new(&objcopy).args(["-O", "binary"]).arg(&elf).arg(&bin));
    eprintln!("[xtask] Flat binary: {}", bin.display());
    if initrd { mkinitramfs_step(root, Arch::X86_64); }
}

fn build_x86_64_uefi(root: &PathBuf, debug: bool, initrd: bool) {
    build_with_target_json(
        root,
        &BuildOpts { arch: Arch::X86_64, boot: Boot::Uefi, debug, initrd: false },
        &["uefi_boot"],
    );
    if initrd { mkinitramfs_step(root, Arch::X86_64); }
}

// ─── image action ───────────────────────────────────────────────────────────────────

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
        (Arch::X86_64,  Boot::Uefi) => build_x86_64_uefi(root, opts.debug, opts.initrd),
        (Arch::X86_64,  Boot::Sbi)  => build_x86_64_kernel(root, opts.debug, opts.initrd),
    }

    let profile   = if opts.debug { "debug" } else { "release" };
    let efi_name  = efi_boot_filename(opts.arch);
    let img_name  = match opts.arch {
        Arch::X86_64  => "boot.img",
        Arch::RiscV64 => "boot-riscv64.img",
    };
    let efi_path  = root.join("esp/EFI/BOOT").join(efi_name);

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
            .arg(&elf).arg(&efi_path));
    }

    if !efi_path.exists() {
        eprintln!("[xtask] ERROR: EFI binary not found at {}", efi_path.display());
        eprintln!("[xtask]        Did the build step succeed?");
        exit(1);
    }

    let img_path = root.join(img_name);

    run(Command::new("mformat")
        .args(["-C", "-F", "-h", "64", "-s", "32", "-t", "64", "-i"])
        .arg(&img_path).arg("::"));
    run(Command::new("mmd").args(["-i"]).arg(&img_path).args(["::/EFI", "::/EFI/BOOT"]));
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
            eprintln!("[xtask]          Run `cargo xtask mkinitramfs` first.");
        }
    }

    eprintln!("\n[xtask] \u{2713} Image ready: {}", img_path.display());
    eprintln!("\n  Flash to USB:");
    eprintln!("    sudo dd if={} of=/dev/sdX bs=4M status=progress && sync",
        img_path.display());
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

fn lint_modules(root: &PathBuf) {
    let files = run_capture({
        let mut c = Command::new("rg");
        c.current_dir(root).args(["--files", "src"]);
        c
    });

    let mut by_name: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for line in files.lines().filter(|l| l.ends_with(".rs")) {
        if let Some(name) = std::path::Path::new(line).file_name().and_then(|n| n.to_str()) {
            by_name.entry(name.to_string()).or_default().push(line.to_string());
        }
    }

    let mut duplicate_count = 0usize;
    for (name, paths) in by_name.iter().filter(|(_, v)| v.len() > 1) {
        duplicate_count += 1;
        eprintln!("[xtask][lint-modules] duplicate basename `{name}`:");
        for p in paths {
            eprintln!("  - {p}");
        }
    }

    let mut missing_docs = 0usize;
    for module in ["src/mm/mod.rs", "src/proc/mod.rs", "src/fs/mod.rs", "src/net/mod.rs"] {
        let text = fs::read_to_string(root.join(module)).unwrap_or_default();
        if !text.trim_start().starts_with("//!") {
            missing_docs += 1;
            eprintln!("[xtask][lint-modules] missing module docs header in {module}");
        }
    }

    eprintln!(
        "[xtask][lint-modules] done: duplicate basenames={}, missing core module docs={}",
        duplicate_count, missing_docs
    );
}

fn bench_kernel(root: &PathBuf) {
    eprintln!("[xtask][bench-kernel] baseline workflow starting");
    run(Command::new("cargo").current_dir(root).args(["xtask", "smoke"]));
    eprintln!("[xtask][bench-kernel] TODO: add scheduler-latency microbench");
    eprintln!("[xtask][bench-kernel] TODO: add pipe-throughput microbench");
    eprintln!("[xtask][bench-kernel] TODO: add mmap-fault microbench");
    eprintln!("[xtask][bench-kernel] baseline workflow complete");
}

// ─── entrypoint ──────────────────────────────────────────────────────────────────────

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
                (Arch::X86_64,  Boot::Uefi) => build_x86_64_uefi(&root, opts.debug, opts.initrd),
                (Arch::X86_64,  Boot::Sbi)  => build_x86_64_kernel(&root, opts.debug, opts.initrd),
            }
        }
        "mkinitramfs" => {
            let mut arch = Arch::X86_64;
            let mut i = 0;
            while i < rest.len() {
                if rest[i] == "--arch" {
                    i += 1;
                    arch = match rest.get(i).map(String::as_str) {
                        Some("x86_64")  => Arch::X86_64,
                        Some("riscv64") => Arch::RiscV64,
                        other => {
                            eprintln!("[xtask] unknown --arch: {:?}", other);
                            exit(1);
                        }
                    };
                }
                i += 1;
            }
            mkinitramfs(&root, arch);
        }
        "image" => {
            let mut opts = parse_build_args(&rest);
            if rest.iter().all(|a| a != "--arch") {
                opts.arch = Arch::X86_64;
            }
            image(&root, &opts);
        }
        "smoke" => {
            // Thin QEMU x86_64 smoke test wrapper.
            // Builds a UEFI+initrd image, then delegates to run_qemu_x86_64.sh --smoke
            // with a fixed marker that the /bin/smoke helper prints.
            let img_opts = BuildOpts { arch: Arch::X86_64, boot: Boot::Uefi, debug: true, initrd: true };
            image(&root, &img_opts);

            let script = root.join("run_qemu_x86_64.sh");
            if !script.exists() {
                eprintln!("[xtask] ERROR: run_qemu_x86_64.sh not found at {}", script.display());
                exit(1);
            }

            let mut cmd = Command::new(script);
            cmd.arg("--smoke")
               .arg("--smoke-marker")
               .arg("SMOKE OK: userspace_smoke");
            run(cmd);
        }
        "lint-modules" => lint_modules(&root),
        "bench-kernel" => bench_kernel(&root),
        "help" | "--help" | "-h" | "" => {
            println!(concat!(
                "cargo xtask <subcommand> [options]\n",
                "\n",
                "Subcommands:\n",
                "  build         Compile the kernel\n",
                "  mkinitramfs   Build userspace + device nodes and pack initramfs.cpio\n",
                "  image         Build a flashable FAT32 ESP disk image\n",
                "  smoke         Build x86_64 UEFI+initrd and run a QEMU smoke test\n",
                "  lint-modules  Report duplicate module basenames and docs gaps\n",
                "  bench-kernel  Run baseline smoke flow + benchmark placeholders\n",
                "\n",
                "Build options (build / image):\n",
                "  --arch <riscv64|x86_64>   Target architecture  (image default: x86_64)\n",
                "  --boot <uefi|sbi>         Boot mode            (default: uefi)\n",
                "  --debug                   Debug build\n",
                "  --initrd                  Build and include initramfs.cpio\n",
                "\n",
                "mkinitramfs options:\n",
                "  --arch <riscv64|x86_64>   Target architecture  (default: x86_64)\n",
                "\n",
                "Device nodes pre-baked into the CPIO archive:\n",
                "  /dev/null          c  1:3   (null sink)\n",
                "  /dev/zero          c  1:5   (zero source)\n",
                "  /dev/tty           c  5:0   (controlling terminal)\n",
                "  /dev/dri/card0     c 226:0  (DRM master)\n",
                "  /dev/input/event0  c  13:64 (evdev input)\n",
                "  mknod requires root or passwordless sudo;\n",
                "  skipped gracefully in rootless CI (devtmpfs creates them at boot).\n",
                "\n",
                "Prerequisites:\n",
                "  mkinitramfs (x86_64):  apt install musl-tools cpio\n",
                "  mkinitramfs (riscv64): riscv64-linux-musl-gcc + apt install cpio\n",
                "  image:                 apt install mtools binutils\n",
                "\n",
                "Common workflows:\n",
                "  # Full x86_64 UEFI image with initramfs:\n",
                "  apt install musl-tools cpio mtools\n",
                "  cargo xtask image --arch x86_64 --boot uefi --initrd\n",
                "  sudo dd if=boot.img of=/dev/sdX bs=4M status=progress && sync\n",
                "\n",
                "  # Rebuild initramfs only (e.g. after editing init.c):\n",
                "  cargo xtask mkinitramfs\n",
                "\n",
                "  # QEMU smoke-test (x86_64, headless):\n",
                "  cargo xtask smoke\n",
            ));
        }
        other => {
            eprintln!("[xtask] unknown subcommand: {other:?}. Try `cargo xtask help`.");
            exit(1);
        }
    }
}
