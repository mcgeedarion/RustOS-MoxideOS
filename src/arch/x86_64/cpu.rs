//! CPU feature detection and MSR helpers.

pub const MSR_IA32_APIC_BASE: u32 = 0x1B;
pub const MSR_EFER:           u32 = 0xC000_0080;
pub const MSR_STAR:           u32 = 0xC000_0081;
pub const MSR_LSTAR:          u32 = 0xC000_0082;
pub const MSR_FMASK:          u32 = 0xC000_0084;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub const MSR_FS_BASE:        u32 = 0xC000_0100;

#[inline(always)]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32; let hi: u32;
    core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack));
    (hi as u64) << 32 | lo as u64
}

#[inline(always)]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    core::arch::asm!("wrmsr",
        in("ecx") msr, in("eax") val as u32, in("edx") (val >> 32) as u32,
        options(nostack));
}

#[inline(always)]
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx);
    unsafe {
        core::arch::asm!("cpuid",
            inout("eax") leaf => eax, out("ebx") ebx,
            out("ecx") ecx,  out("edx") edx, options(nostack));
    }
    (eax, ebx, ecx, edx)
}

pub fn has_xsave() -> bool { cpuid(1).2 & (1 << 26) != 0 }
pub fn has_avx()   -> bool { cpuid(1).2 & (1 << 28) != 0 }
