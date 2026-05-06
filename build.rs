use std::process::Command;
use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // ── C runtime (crt0.c) ───────────────────────────────────────────────
    let mut build = cc::Build::new();
    build
        .file("src/crt/crt0.c")
        .flag("-ffreestanding")
        .flag("-nostdlib")
        .flag("-nostartfiles")
        .flag("-fno-stack-protector")
        .flag("-fno-builtin")
        .opt_level(2);

    if target.contains("x86_64") {
        build.flag("--target=x86_64-unknown-none");
    } else if target.contains("riscv64") {
        build.flag("--target=riscv64-unknown-none-elf");
        build.flag("-march=rv64gc");
        build.flag("-mabi=lp64d");
    }

    build.compile("kcrt");

    // ── Multiboot2 entry stub (x86_64 only) ────────────────────────────
    if target.contains("x86_64") {
        let boot_obj = PathBuf::from(&out_dir).join("boot.o");
        let status = Command::new("nasm")
            .args([
                "-f", "elf64",
                "-o", boot_obj.to_str().unwrap(),
                "src/arch/x86_64/boot.s",
            ])
            .status()
            .expect("nasm not found — install nasm");
        assert!(status.success(), "nasm failed to assemble boot.s");

        // Tell rustc to link boot.o directly
        println!("cargo:rustc-link-arg={}", boot_obj.display());
        println!("cargo:rerun-if-changed=src/arch/x86_64/boot.s");
    }

    println!("cargo:rerun-if-changed=src/crt/crt0.c");
    println!("cargo:rerun-if-changed=build.rs");
}
