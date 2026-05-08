use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Compile the RISC-V user-space entry trampoline.
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
