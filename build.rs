fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .file("src/crt/crt0.c")
        .flag("-ffreestanding")
        .flag("-nostdlib")
        .flag("-nostartfiles")
        .flag("-fno-stack-protector")
        .flag("-fno-builtin")
        .opt_level(2);

    // Set the correct cross-compilation target triple for clang
    if target.contains("x86_64") {
        build.flag("--target=x86_64-unknown-none");
    } else if target.contains("riscv64") {
        build.flag("--target=riscv64-unknown-none-elf");
        build.flag("-march=rv64gc");
        build.flag("-mabi=lp64d");
    }

    build.compile("kcrt");

    println!("cargo:rerun-if-changed=src/crt/crt0.c");
    println!("cargo:rerun-if-changed=build.rs");
}
