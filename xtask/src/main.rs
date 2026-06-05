//! cargo xtask — build automation for RustOS.
//!
//! Usage:
//!   cargo xtask build                               # riscv64, uefi, release (default)
//!   cargo xtask build --arch riscv64 --boot uefi
//!   cargo xtask build --arch riscv64 --boot sbi
//!   cargo xtask build --arch x86_64                # x86_64 kernel (ELF, no UEFI wrapper)
//!   cargo xtask build --arch x86_64 --boot uefi    # x86_64 UEFI loader (PE32+)
//!   cargo xtask build --arch x86_64 --boot uefi --initrd
//!   cargo xtask build --arch aarch64               # AArch64 UEFI loader (default)
//!   cargo xtask build --arch aarch64 --boot sbi    # AArch64 bare-metal ELF
//!
//!   cargo xtask mkinitramfs                         # x86_64 initramfs (default)
//!   cargo xtask mkinitramfs --arch riscv64
//!   cargo xtask mkinitramfs --arch aarch64
//!
//!   cargo xtask image                               # x86_64 release ESP image
//!   cargo xtask image --arch riscv64                # riscv64 release ESP image
//!   cargo xtask image --arch aarch64                # aarch64 UEFI ESP image
//!   cargo xtask image --arch x86_64 --debug         # x86_64 debug ESP image
//!   cargo xtask image --arch x86_64 --initrd        # include initramfs.cpio
//!
//!   cargo xtask smoke                               # x86_64 QEMU smoke test (headless)
//!
//! The `image` subcommand requires mtools (mformat, mmd, mcopy) and
//! objcopy (binutils / llvm-objcopy).  Install hint is printed if missing.
//!
//! The `mkinitramfs` subcommand requires:
//!   x86_64:  musl-tools  (musl-gcc)           → apt install musl-tools
//!   riscv64: riscv64-linux-musl-gcc            → build from source or distro pkg
//!   aarch64: aarch64-linux-musl-gcc            → build from source or distro pkg
//!   Both:    cpio                              → apt install cpio
//!
//! Device node creation (step 2b) requires root or sudo on the build host.
//! In rootless CI containers the mknod calls are skipped with a warning;
//! the kernel's devtmpfs populates /dev at runtime regardless.

use std::{
    env, fs,
    collections::BTreeMap,
    path::PathBuf,
    process::{Command, exit},
};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_ARCH: Arch = Arch::RiscV64;
const DEFAULT_BOOT: Boot = Boot::Uefi;
const DEFAULT_IMAGE_ARCH: Arch = Arch::X86_64;

const MAX_MODULE_LOC: usize = 600;
const SMOKE_MARKER: &str = "SMOKE OK: userspace_smoke";
const OS_RELEASE_CONTENT: &[u8] = b"NAME=RustOS\nID=rustos\nVERSION=0.1.0\nPRETTY_NAME=\"RustOS 0.1.0\"\n";

const CORE_MODULES: &[&str] = &["src/mm/mod.rs", "src/proc/mod.rs", "src/fs/mod.rs", "src/net/mod.rs"];
const INITRAMFS_DIRS: &[&str] = &["", "bin", "sbin", "usr/bin", "usr/sbin", "lib", "etc",
                                   "dev", "dev/dri", "dev/input", "proc", "sys", "tmp", "run", "var", "root"];

struct DevNode {
    path:  &'static str,
    kind:  char,
    major: u32,
    minor: u32,
    mode:  u32,
}

const DEV_NODES: &[DevNode] = &[
    DevNode { path: "dev/null",        kind: 'c', major: 1,   minor: 3,  mode: 0o666 },
    DevNode { path: "dev/zero",        kind: 'c', major: 1,   minor: 5,  mode: 0o666 },
    DevNode { path: "dev/tty",         kind: 'c', major: 5,   minor: 0,  mode: 0o666 },
    DevNode { path: "dev/dri/card0",   kind: 'c', major: 226, minor: 0,  mode: 0o660 },
    DevNode { path: "dev/input/event0",kind: 'c', major: 13,  minor: 64, mode: 0o660 },
];

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch { RiscV64, X86_64, AArch64 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boot { Uefi, Sbi }

#[derive(Debug, Clone)]
struct BuildOpts {
    arch:     Arch,
    boot:     Boot,
    debug:    bool,
    initrd:   bool,
    features: Option<String>,
}

impl Default for BuildOpts {
    fn default() -> Self {
        Self {
            arch: DEFAULT_ARCH,
            boot: DEFAULT_BOOT,
            debug: false,
            initrd: false,
            features: None,
        }
    }
}

// ============================================================================
// Error and Result types
// ============================================================================

type TaskResult = Result<(), String>;

fn err(msg: impl Into<String>) -> TaskResult {
    Err(msg.into())
}

fn fatal(msg: impl Into<String>) -> ! {
    eprintln!("[xtask] ERROR: {}", msg.into());
    exit(1);
}

// ============================================================================
// Logging helpers
// ============================================================================

fn log(msg: impl AsRef<str>) {
    eprintln!("[xtask] {}", msg.as_ref());
}

fn log_success(msg: impl AsRef<str>) {
    eprintln!("[xtask] ✓ {}", msg.as_ref());
}

fn log_warn(msg: impl AsRef<str>) {
    eprintln!("[xtask] WARNING: {}", msg.as_ref());
}

fn log_section(tag: &str, msg: impl AsRef<str>) {
    eprintln!("[xtask][{tag}] {}", msg.as_ref());
}

// ============================================================================
// Architecture/Boot mode query helpers
// ============================================================================

fn arch_str(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64  => "x86_64",
        Arch::RiscV64 => "riscv64",
        Arch::AArch64 => "aarch64",
    }
}

fn target_json(root: &PathBuf, arch: Arch, boot: Boot) -> PathBuf {
    let name = match (arch, boot) {
        (Arch::X86_64,  Boot::Uefi) => "x86_64-uefi-loader.json",
        (Arch::X86_64,  Boot::Sbi)  => "x86_64-kernel.json",
        (Arch::RiscV64, Boot::Uefi) => "riscv64-uefi-loader.json",
        (Arch::RiscV64, Boot::Sbi)  => "riscv64-kernel.json",
        (Arch::AArch64, Boot::Uefi) => "aarch64-uefi-loader.json",
        (Arch::AArch64, Boot::Sbi)  => "aarch64-kernel.json",
    };
    root.join("targets").join(name)
}

fn target_dir_name(arch: Arch, boot: Boot) -> &'static str {
    match (arch, boot) {
        (Arch::X86_64,  Boot::Uefi) => "x86_64-uefi-loader",
        (Arch::X86_64,  Boot::Sbi)  => "x86_64-kernel",
        (Arch::RiscV64, Boot::Uefi) => "riscv64-uefi-loader",
        (Arch::RiscV64, Boot::Sbi)  => "riscv64gc-unknown-none-elf",
        (Arch::AArch64, Boot::Uefi) => "aarch64-uefi-loader",
        (Arch::AArch64, Boot::Sbi)  => "aarch64-kernel",
    }
}

fn efi_boot_filename(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64  => "BOOTx64.EFI",
        Arch::RiscV64 => "BOOTRISCV64.EFI",
        Arch::AArch64 => "BOOTAA64.EFI",
    }
}

fn image_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64  => "boot.img",
        Arch::RiscV64 => "boot-riscv64.img",
        Arch::AArch64 => "boot-aarch64.img",
    }
}

// ============================================================================
// Path building helpers
// ============================================================================

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().expect("xtask has no parent directory")
        .to_path_buf()
}

fn build_output_path(root: &PathBuf, arch: Arch, boot: Boot, profile: &str) -> PathBuf {
    root.join(format!("target/{}/{}", target_dir_name(arch, boot), profile))
}

fn binary_path(root: &PathBuf, arch: Arch, boot: Boot, profile: &str, name: &str) -> PathBuf {
    build_output_path(root, arch, boot, profile).join(name)
}

fn esp_boot_dir(root: &PathBuf) -> PathBuf {
    root.join("esp/EFI/BOOT")
}

// ============================================================================
// Process execution helpers
// ============================================================================

fn cargo() -> Command {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    Command::new(cargo)
}

fn run(mut cmd: Command) {
    log(format!("running: {:?}", cmd));
    let status = cmd.status().expect("failed to spawn command");
    if !status.success() {
        log(format!("command failed with {status}"));
        exit(status.code().unwrap_or(1));
    }
}

fn run_optional(mut cmd: Command) -> bool {
    log(format!("running (optional): {:?}", cmd));
    match cmd.status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            log(format!("optional command exited with {s} — skipping"));
            false
        }
        Err(e) => {
            log(format!("optional command failed to spawn: {e} — skipping"));
            false
        }
    }
}

fn run_capture(mut cmd: Command) -> String {
    log(format!("running (capture): {:?}", cmd));
    let output = cmd.output().expect("failed to spawn command");
    if !output.status.success() {
        log(format!("command failed with {}", output.status));
        exit(output.status.code().unwrap_or(1));
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

// ============================================================================
// Tool discovery
// ============================================================================

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
            log(format!("ERROR: none of {:?} found on PATH", names));
            log(format!("Install with: {install_hint}"));
            exit(1);
        }
    }
}

// ============================================================================
// Build tool requirements
// ============================================================================

fn require_build_tools(arch: Arch) -> TaskResult {
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
        Arch::AArch64 => {
            require_tool(
                &["aarch64-linux-musl-gcc", "aarch64-unknown-linux-musl-gcc"],
                "build musl from source: https://musl.libc.org/  (target: aarch64-linux-musl)",
            );
        }
    }
    require_tool(&["cpio"], "apt install cpio");
    require_tool(&["find"], "coreutils (should already be installed)");
    Ok(())
}

// ============================================================================
// Argument parsing
// ============================================================================

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
                    Some("aarch64") => opts.arch = Arch::AArch64,
                    other => {
                        log(format!("unknown --arch: {:?}", other));
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
                        log(format!("unknown --boot: {:?}", other));
                        exit(1);
                    }
                }
            }
            "--features" => {
                i += 1;
                opts.features = args.get(i).cloned();
            }
            "--debug"  => opts.debug  = true,
            "--initrd" => opts.initrd = true,
            other => {
                log(format!("unknown argument: {other}"));
                exit(1);
            }
        }
        i += 1;
    }
    opts
}

// ============================================================================
// Device node creation
// ============================================================================

fn create_single_dev_node(staging: &PathBuf, node: &DevNode, is_root: bool) -> bool {
    let full_path = staging.join(node.path);
    let type_str  = node.kind.to_string();
    let major_str = node.major.to_string();
    let minor_str = node.minor.to_string();
    let mode_str  = format!("{:04o}", node.mode);

    let ok = if is_root {
        run_optional(Command::new("mknod")
            .arg(&full_path).arg(&type_str).arg(&major_str).arg(&minor_str))
    } else {
        run_optional(Command::new("sudo")
            .args(["mknod"]).arg(&full_path).arg(&type_str).arg(&major_str).arg(&minor_str))
    };

    if !ok {
        log_warn(format!("could not create {} — skipping", node.path));
        return false;
    }

    let chmod_ok = if is_root {
        run_optional(Command::new("chmod").arg(&mode_str).arg(&full_path))
    } else {
        run_optional(Command::new("sudo").args(["chmod"]).arg(&mode_str).arg(&full_path))
    };

    if chmod_ok {
        log_section("mkinitramfs",
            format!("created {} ({} {}:{} mode {})", node.path, node.kind, node.major, node.minor, mode_str));
    }
    chmod_ok
}

fn create_dev_nodes(staging: &PathBuf) {
    if which_first(&["mknod"]).is_none() {
        log_warn("mknod not found — skipping device nodes");
        log_warn("Install with: apt install coreutils");
        log_warn("Devices will be created by the kernel's devtmpfs at runtime.");
        return;
    }

    let is_root = unsafe { libc_getuid() } == 0;
    let mut created = 0usize;
    let mut skipped = 0usize;

    for node in DEV_NODES {
        if create_single_dev_node(staging, node, is_root) {
            created += 1;
        } else {
            skipped += 1;
        }
    }

    if skipped > 0 {
        log_section("mkinitramfs",
            format!("{created} device node(s) created, {skipped} skipped (no root/sudo)."));
        log_section("mkinitramfs", "The kernel's devtmpfs will create missing nodes at runtime.");
    } else {
        log_section("mkinitramfs", format!("all {created} device node(s) created."));
    }
}

#[cfg(unix)]
fn libc_getuid() -> u32 {
    extern "C" { fn getuid() -> u32; }
    unsafe { getuid() }
}
#[cfg(not(unix))]
fn libc_getuid() -> u32 { 1000 }

// ============================================================================
// Build functions
// ============================================================================

fn mkinitramfs(root: &PathBuf, arch: Arch) -> TaskResult {
    require_build_tools(arch)?;

    let arch_str = arch_str(arch);
    let staging = root.join(format!("target/initramfs-staging-{arch_str}"));

    if staging.exists() {
        fs::remove_dir_all(&staging).expect("remove old staging dir");
    }

    for dir in INITRAMFS_DIRS {
        fs::create_dir_all(staging.join(dir)).expect("create staging subdir");
    }

    log_section("mkinitramfs", "creating device nodes...");
    create_dev_nodes(&staging);

    log_section("mkinitramfs", format!("building userspace ({arch_str})..."));
    run(Command::new("make")
        .current_dir(root.join("userspace"))
        .args(["-j4", &format!("ARCH={arch_str}"),
               &format!("DESTDIR={}", staging.display()), "install"]));

    fs::write(staging.join("etc/os-release"), OS_RELEASE_CONTENT)
        .expect("write os-release");

    let cpio_out = root.join("initramfs.cpio");
    log_section("mkinitramfs", format!("packing {}...", cpio_out.display()));
    run(Command::new("sh").current_dir(&staging).args([
        "-c",
        &format!("find . | sort | cpio --create --format=newc --quiet > {}", cpio_out.display()),
    ]));

    let size = fs::metadata(&cpio_out).map(|m| m.len()).unwrap_or(0);
    log_section("mkinitramfs", format!("{} bytes → {}", size, cpio_out.display()));
    Ok(())
}

// ============================================================================
// Consolidated build logic
// ============================================================================

fn build_with_target_json(root: &PathBuf, opts: &BuildOpts) -> TaskResult {
    let profile     = if opts.debug { "debug" } else { "release" };
    let target_path = target_json(root, opts.arch, opts.boot);
    let target_dir  = target_dir_name(opts.arch, opts.boot);

    log(format!("Building rustos ({:?}/{:?}, {profile}) → target/{target_dir}/",
        opts.arch, opts.boot));

    let mut cmd = cargo();
    cmd.current_dir(root)
        .args(["build", "--target"]).arg(&target_path)
        .args(["-Z", "build-std=core,alloc,compiler_builtins",
               "-Z", "build-std-features=compiler-builtins-mem"]);

    if let Some(ref feats) = opts.features {
        cmd.arg("--features").arg(feats);
    } else {
        cmd.arg("--no-default-features");
    }

    if !opts.debug { cmd.arg("--release"); }
    run(cmd);

    if opts.boot == Boot::Uefi {
        let bin_name = efi_boot_filename(opts.arch);
        let src_efi = binary_path(root, opts.arch, opts.boot, profile, "rustos.efi");
        let src_elf = binary_path(root, opts.arch, opts.boot, profile, "rustos");
        let src = if src_efi.exists() { src_efi } else { src_elf };

        if !src.exists() {
            return err(format!("EFI binary not found under target/{target_dir}/{profile}/"));
        }

        let esp = esp_boot_dir(root);
        fs::create_dir_all(&esp).expect("create esp dir");
        let dest = esp.join(bin_name);
        fs::copy(&src, &dest).expect("copy EFI binary");
        log(format!("Built:     {}", src.display()));
        log(format!("Installed: {}", dest.display()));
    } else {
        let elf = binary_path(root, opts.arch, opts.boot, profile, "rustos");
        log(format!("Built: {}", elf.display()));
    }

    Ok(())
}

fn build_kernel(root: &PathBuf, opts: &BuildOpts) -> TaskResult {
    build_with_target_json(root, opts)?;

    match (opts.arch, opts.boot) {
        (Arch::X86_64, Boot::Sbi) => {
            let profile = if opts.debug { "debug" } else { "release" };
            let elf = binary_path(root, opts.arch, opts.boot, profile, "rustos");
            let bin = root.join("kernel.bin");
            let objcopy = require_tool(&["llvm-objcopy", "objcopy"], "apt install llvm binutils");
            run(Command::new(&objcopy).args(["-O", "binary"]).arg(&elf).arg(&bin));
            log(format!("Flat binary: {}", bin.display()));
        }
        _ => {}
    }

    if opts.initrd {
        mkinitramfs(root, opts.arch)?;
    }

    Ok(())
}

// ============================================================================
// Image building
// ============================================================================

fn image(root: &PathBuf, opts: &BuildOpts) -> TaskResult {
    for tool in &["mformat", "mmd", "mcopy"] {
        require_tool(&[tool], "apt install mtools   # Debian/Ubuntu\nbrew install mtools  # macOS");
    }
    let objcopy = require_tool(&["llvm-objcopy", "objcopy"], "apt install llvm binutils");

    log("image: building kernel...");
    build_kernel(root, opts)?;

    let profile  = if opts.debug { "debug" } else { "release" };
    let efi_name = efi_boot_filename(opts.arch);
    let img_name = image_name(opts.arch);
    let efi_path = esp_boot_dir(root).join(efi_name);

    // Handle x86_64 bare-metal (SBI) case: wrap ELF as EFI
    if opts.arch == Arch::X86_64 && opts.boot == Boot::Sbi {
        let elf = binary_path(root, opts.arch, opts.boot, profile, "rustos");
        if !elf.exists() {
            return err(format!("kernel ELF not found at {}", elf.display()));
        }
        fs::create_dir_all(esp_boot_dir(root)).expect("create esp dir");
        run(Command::new(&objcopy)
            .args(["--target", "efi-app-x86-64", "--subsystem", "10"])
            .arg(&elf).arg(&efi_path));
    }

    // AArch64 bare-metal: image subcommand only makes sense for UEFI.
    // For bare-metal ELF, users load rustos directly via U-Boot/TFTP.
    if opts.arch == Arch::AArch64 && opts.boot == Boot::Sbi {
        let elf = binary_path(root, opts.arch, opts.boot, profile, "rustos");
        log(format!("AArch64 bare-metal ELF: {}", elf.display()));
        log("Load via U-Boot: tftp $loadaddr rustos; bootelf $loadaddr");
        return Ok(());
    }

    if !efi_path.exists() {
        return err(format!("EFI binary not found at {}\nDid the build step succeed?", efi_path.display()));
    }

    let img_path = root.join(img_name);
    run(Command::new("mformat")
        .args(["-C", "-F", "-h", "64", "-s", "32", "-t", "64", "-i"])
        .arg(&img_path).arg("::"));
    run(Command::new("mmd").args(["-i"]).arg(&img_path).args(["::/EFI", "::/EFI/BOOT"]));
    run(Command::new("mcopy")
        .args(["-i"]).arg(&img_path).arg(&efi_path)
        .arg(format!("::/EFI/BOOT/{efi_name}")));

    if opts.initrd {
        let cpio = root.join("initramfs.cpio");
        if cpio.exists() {
            run(Command::new("mcopy")
                .args(["-i"]).arg(&img_path).arg(&cpio).arg("::/initramfs.cpio"));
            log(format!("Embedded initramfs: {}", cpio.display()));
        } else {
            log_warn("--initrd specified but initramfs.cpio not found.");
            log_warn("Run `cargo xtask mkinitramfs` first.");
        }
    }

    log_success(format!("Image ready: {}", img_path.display()));
    log(format!("    sudo dd if={} of=/dev/sdX bs=4M status=progress && sync", img_path.display()));
    Ok(())
}

// ============================================================================
// Linting
// ============================================================================

struct LintRule {
    name: &'static str,
    check: fn(&PathBuf, &[String]) -> usize,
}

fn check_duplicates(root: &PathBuf, files: &[String]) -> usize {
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in files.iter().filter(|l| l.ends_with(".rs")) {
        if let Some(name) = std::path::Path::new(line).file_name().and_then(|n| n.to_str()) {
            by_name.entry(name.to_string()).or_default().push(line.to_string());
        }
    }
    let mut count = 0usize;
    for (name, paths) in by_name.iter().filter(|(_, v)| v.len() > 1) {
        count += 1;
        log_section("lint-modules", format!("duplicate basename `{name}`"));
        for p in paths { log_section("lint-modules", format!("  - {p}")); }
    }
    count
}

fn check_missing_docs(_root: &PathBuf, _files: &[String]) -> usize {
    let mut count = 0usize;
    for module in CORE_MODULES {
        let text = fs::read_to_string(module).unwrap_or_default();
        if !text.trim_start().starts_with("//!") {
            count += 1;
            log_section("lint-modules", format!("missing module docs header in {module}"));
        }
    }
    count
}

fn check_oversized_modules(root: &PathBuf, files: &[String]) -> usize {
    let mut count = 0usize;
    for line in files.iter().filter(|l| l.ends_with(".rs")) {
        let text = fs::read_to_string(root.join(line)).unwrap_or_default();
        let loc = text.lines().filter(|l| !l.trim().is_empty()).count();
        if loc > MAX_MODULE_LOC {
            count += 1;
            log_section("lint-modules",
                format!("oversized module ({loc} LOC > {MAX_MODULE_LOC}): {line}"));
        }
    }
    count
}

fn check_undocumented_pub_items(root: &PathBuf, files: &[String]) -> usize {
    let mut count = 0usize;
    for line in files.iter().filter(|l| l.ends_with(".rs")) {
        let text = fs::read_to_string(root.join(line)).unwrap_or_default();
        if text.trim_start().starts_with("//!") { continue; }
        for (idx, raw) in text.lines().enumerate() {
            let t = raw.trim_start();
            if (t.starts_with("pub fn ") || t.starts_with("pub struct ")
                || t.starts_with("pub enum ") || t.starts_with("pub trait "))
                && !t.starts_with("pub(") {
                count += 1;
                log_section("lint-modules",
                    format!("public item in undocumented module: {}:{}", line, idx + 1));
            }
        }
    }
    count
}

fn lint_modules(root: &PathBuf) -> TaskResult {
    let files_output = run_capture({
        let mut c = Command::new("rg");
        c.current_dir(root).args(["--files", "src"]);
        c
    });
    let files: Vec<String> = files_output.lines().map(|s| s.to_string()).collect();

    let rules = vec![
        ("duplicate basenames", check_duplicates(root, &files)),
        ("missing core module docs", check_missing_docs(root, &files)),
        ("oversized modules", check_oversized_modules(root, &files)),
        ("public items in undocumented modules", check_undocumented_pub_items(root, &files)),
    ];

    log_section("lint-modules", "done:");
    for (name, count) in rules {
        log_section("lint-modules", format!("  {name}={}", count));
    }
    Ok(())
}

// ============================================================================
// Benchmarking
// ============================================================================

fn bench_kernel(root: &PathBuf) -> TaskResult {
    log_section("bench-kernel", "baseline workflow starting");
    run(Command::new("cargo").current_dir(root).args(["xtask", "smoke"]));
    log_section("bench-kernel", "TODO: add scheduler-latency microbench");
    log_section("bench-kernel", "TODO: add pipe-throughput microbench");
    log_section("bench-kernel", "TODO: add mmap-fault microbench");
    log_section("bench-kernel", "baseline workflow complete");
    Ok(())
}

// ============================================================================
// Smoke test
// ============================================================================

fn smoke(root: &PathBuf) -> TaskResult {
    let img_opts = BuildOpts {
        arch: Arch::X86_64,
        boot: Boot::Uefi,
        debug: true,
        initrd: true,
        features: None,
    };
    image(root, &img_opts)?;
    let script = root.join("run_qemu_x86_64.sh");
    if !script.exists() {
        return err(format!("run_qemu_x86_64.sh not found at {}", script.display()));
    }
    run(Command::new(script)
        .arg("--smoke").arg("--smoke-marker").arg(SMOKE_MARKER));
    Ok(())
}

// ============================================================================
// Main entry point
// ============================================================================

fn main() {
    let mut args = env::args().skip(1);
    let subcommand = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();
    let root = workspace_root();

    let result = match subcommand.as_str() {
        "build" => {
            let opts = parse_build_args(&rest);
            build_kernel(&root, &opts)
        }
        "mkinitramfs" => {
            let opts = parse_build_args(&rest);
            mkinitramfs(&root, opts.arch)
        }
        "image" => {
            let mut opts = parse_build_args(&rest);
            if rest.iter().all(|a| a != "--arch") { opts.arch = DEFAULT_IMAGE_ARCH; }
            image(&root, &opts)
        }
        "smoke" => smoke(&root),
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
                "  --arch <riscv64|x86_64|aarch64>  Target architecture  (image default: x86_64)\n",
                "  --boot <uefi|sbi>                Boot mode            (default: uefi)\n",
                "                                   aarch64+sbi = bare-metal ELF via _start\n",
                "  --features <feat>                Cargo features to enable\n",
                "  --debug                          Debug build\n",
                "  --initrd                         Build and include initramfs.cpio\n",
                "\n",
                "mkinitramfs options:\n",
                "  --arch <riscv64|x86_64|aarch64>  Target architecture  (default: x86_64)\n",
            ));
            Ok(())
        }
        other => {
            log(format!("unknown subcommand: {other:?}. Try `cargo xtask help`."));
            exit(1);
        }
    };

    if let Err(e) = result {
        fatal(e);
    }
}
