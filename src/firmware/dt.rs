//! Devicetree blob parser stub.
//!
//! On RISC-V, delegate to the architecture FDT walker.
#[allow(dead_code)]
pub fn parse(dtb: *const u8) {
    #[cfg(target_arch = "riscv64")]
    {
        if !dtb.is_null() {
            crate::arch::riscv64::fdt::fdt_phase1(dtb as usize);
        }
    }
}
