use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Only attempt to assemble the RISC-V user-space entry trampoline when
    // we are actually targeting RISC-V.  On x86_64 builds this block is
    // skipped entirely, avoiding a spurious "riscv64-unknown-elf-as not
    // found" cargo warning in every x86_64 CI run.
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    if target_arch == "riscv64" {
        let asm_src = "src/arch/riscv64/uentry.S";
        println!("cargo:rerun-if-changed={asm_src}");
        let obj = out.join("uentry_riscv64.o");
        let status = Command::new("riscv64-unknown-elf-as")
            .args(["-march=rv64gc", "-mabi=lp64d", "-o"])
            .arg(&obj)
            .arg(asm_src)
            .status();
        match status {
            Ok(s) if s.success() => {
                let lib = out.join("libuentry_riscv64.a");
                Command::new("riscv64-unknown-elf-ar")
                    .args(["crs"])
                    .arg(&lib)
                    .arg(&obj)
                    .status()
                    .expect("ar failed");
                println!("cargo:rustc-link-search=native={}", out.display());
                println!("cargo:rustc-link-lib=static=uentry_riscv64");
            }
            _ => {
                println!("cargo:warning=riscv64-unknown-elf-as not found; skipping uentry assembly");
            }
        }
    }
}
