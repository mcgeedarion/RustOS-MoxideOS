//! RISC-V CSR read/write macros and helpers.

#[macro_export]
macro_rules! csrr {
    ($csr:literal) => {{ let v: usize; unsafe { core::arch::asm!(concat!("csrr {}, ", $csr), out(reg) v); } v }}
}
#[macro_export]
macro_rules! csrw {
    ($csr:literal, $val:expr) => {{ unsafe { core::arch::asm!(concat!("csrw ", $csr, ", {}"), in(reg) $val); } }}
}

pub fn get_mhartid() -> usize {
    csrr!("mhartid")
}
pub fn get_mstatus() -> usize {
    csrr!("mstatus")
}
pub fn set_mstatus(v: usize) {
    csrw!("mstatus", v);
}
pub fn get_satp() -> usize {
    csrr!("satp")
}
pub fn set_satp(v: usize) {
    csrw!("satp", v);
}
pub fn get_stvec() -> usize {
    csrr!("stvec")
}
pub fn set_stvec(v: usize) {
    csrw!("stvec", v);
}
pub fn get_scause() -> usize {
    csrr!("scause")
}
pub fn get_sepc() -> usize {
    csrr!("sepc")
}
pub fn set_sepc(v: usize) {
    csrw!("sepc", v);
}
