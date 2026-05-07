//! RISC-V SMP: SBI HSM hart bringup + CLINT software IPI.
//!
//! Uses SBI extension `HSM` (extension id 0x48534D) to start secondary harts.
//! Each hart's entry point is `ap_entry` in `src/smp/mod.rs`.

use core::sync::atomic::{AtomicUsize, Ordering};

/// SBI HSM extension id.
const SBI_EXT_HSM: usize = 0x4853_4D;
const SBI_HSM_HART_START: usize = 0;

/// CLINT base (QEMU virt machine)
const CLINT_BASE: usize = 0x0200_0000;
const CLINT_MSIP_BASE: usize = CLINT_BASE; // 4 bytes per hart

/// Physical address of the AP entry trampoline.  Must be within the first
/// 4 GiB for HSM (priv spec allows full PA but QEMU HSM needs < 4G in
/// some versions).
///
/// We reuse the same assembly stub concept: `ap_entry` is a Rust `extern C`
/// function so its address is directly usable as the start address.
extern "C" { fn ap_entry(cpu_id: u32) -> !; }

/// Issue SBI call via `ecall`.
#[inline]
unsafe fn sbi_call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    core::arch::asm!(
        "ecall",
        in("a7") ext,
        in("a6") fid,
        in("a0") a0,
        in("a1") a1,
        in("a2") a2,
        lateout("a0") ret,
        options(nostack)
    );
    ret
}

/// Start all non-boot harts using SBI HSM.
pub fn start_all_harts() {
    let n = crate::smp::num_cpus();
    for cpu in 0..n {
        if let Some(info) = crate::smp::cpu_info(cpu) {
            if !info.is_bsp {
                start_hart(info.hw_id, cpu);
            }
        }
    }
}

/// Start hart `hw_id` at `ap_entry` with opaque = `cpu_id`.
fn start_hart(hw_id: u32, cpu_id: u32) {
    let entry_fn = ap_entry as usize;
    let ret = unsafe {
        sbi_call(
            SBI_EXT_HSM,
            SBI_HSM_HART_START,
            hw_id as usize,
            entry_fn,
            cpu_id as usize, // opaque → a1 on hart entry, passed as cpu_id
        )
    };
    if ret != 0 {
        log::error!("smp: SBI hart start failed: hw_id={} ret={}", hw_id, ret);
    } else {
        log::debug!("smp: started hart hw_id={} cpu_id={}", hw_id, cpu_id);
    }
}

/// Send a software IPI to `hw_id` via CLINT MSIP register.
/// Note: in S-mode we use SBI `IPI` extension (0x735049) for portability.
#[inline]
pub fn send_ipi(hw_id: u32) {
    // SBI IPI extension, sbi_send_ipi(hart_mask, hart_mask_base)
    const SBI_EXT_IPI: usize = 0x73_5049;
    const SBI_IPI_SEND: usize = 0;
    let mask: usize = 1 << hw_id;
    unsafe { sbi_call(SBI_EXT_IPI, SBI_IPI_SEND, mask, 0, 0); }
}

/// Initialise this hart's PLIC context (claim/complete threshold = 0,
/// enable the set of interrupt sources this hart services).
/// Called from `ap_entry` on each AP hart.
pub fn ap_init_plic() {
    // Hart 0 (BSP) already configured PLIC during `drivers::plic::init()`.
    // Each AP only needs its own S-mode context's threshold register set to 0
    // to allow all priority > 0 interrupts through.
    let hart = crate::smp::percpu::current_cpu_id() as usize;
    // S-mode context for hart N on QEMU virt = 2*N+1.
    let ctx = 2 * hart + 1;
    // PLIC base (QEMU virt)
    const PLIC_BASE: usize = 0x0C00_0000;
    const PLIC_THRESHOLD_OFFSET: usize = 0x0020_0000;
    const CTX_STRIDE: usize = 0x1000;
    let threshold_addr = (PLIC_BASE + PLIC_THRESHOLD_OFFSET + ctx * CTX_STRIDE) as *mut u32;
    unsafe { core::ptr::write_volatile(threshold_addr, 0); }
}
