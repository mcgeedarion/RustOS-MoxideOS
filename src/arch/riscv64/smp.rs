//! RISC-V SMP bringup via SBI HSM extension + IPI via SBI sPI extension.
//!
//! All SBI Extension IDs, Function IDs, and per-AP stack constants are
//! imported from [`crate::arch::riscv64::mem_layout`].

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::mm::pmm;
use crate::arch::riscv64::mem_layout::sbi as SBI;
use crate::arch::riscv64::mem_layout::smp as SMP;

const MAX_APS: usize = crate::smp::MAX_CPUS - 1;

static AP_STACKS: [AtomicUsize; MAX_APS] = {
    const ZERO: AtomicUsize = AtomicUsize::new(0);
    [ZERO; MAX_APS]
};

#[inline]
unsafe fn sbi_call(eid: usize, fid: usize, a0: usize, a1: usize, a2: usize)
    -> (isize, usize)
{
    let err: isize;
    let val: usize;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0 => err,
        inlateout("a1") a1 => val,
        in("a2") a2,
        in("a6") fid,
        in("a7") eid,
        options(nostack)
    );
    (err, val)
}

pub fn sbi_hart_start(hart_id: usize, entry: usize, opaque: usize) -> isize {
    unsafe {
        sbi_call(SBI::EID_HSM, SBI::FID_HSM_HART_START, hart_id, entry, opaque).0
    }
}

pub fn sbi_hart_status(hart_id: usize) -> isize {
    unsafe { sbi_call(SBI::EID_HSM, SBI::FID_HSM_HART_STATUS, hart_id, 0, 0).0 }
}

/// Send a software interrupt to `target_hw_id` via SBI IPI extension.
///
/// hart_mask = 1, hart_mask_base = target_hw_id so exactly one bit maps
/// to the target.  OpenSBI sets SIP.SSIP; the target takes scause
/// `INT_S_SOFTWARE` at the next interrupt window.
pub fn send_ipi(target_hw_id: usize) {
    unsafe {
        let (rc, _) = sbi_call(
            SBI::EID_IPI, SBI::FID_IPI_SEND,
            1,             // hart_mask = 0b1
            target_hw_id,  // hart_mask_base
            0,
        );
        if rc != SBI::ERR_SUCCESS as isize {
            crate::println!("smp: send_ipi to hart {} failed, SBI error {}", target_hw_id, rc);
        }
    }
}

extern "C" { fn ap_entry(cpu_id: u32) -> !; }

#[naked]
#[no_mangle]
pub unsafe extern "C" fn ap_entry_riscv() -> ! {
    core::arch::asm!(
        "addi  t0, a1, -1",
        "li    t1, 8",
        "mul   t0, t0, t1",
        "la    t2, {stacks}",
        "add   t2, t2, t0",
        "ld    sp, 0(t2)",
        "mv    a0, a1",
        "tail  {ap_entry}",
        stacks   = sym AP_STACKS,
        ap_entry = sym ap_entry,
        options(noreturn)
    );
}

pub fn start_all_harts() {
    let total = crate::smp::num_cpus();
    for cpu_id in 1..total {
        let info = match crate::smp::cpu_info(cpu_id) {
            Some(i) => i,
            None    => continue,
        };
        let hw_id     = info.hw_id as usize;
        let stack_pa  = alloc_ap_stack();
        let stack_top = stack_pa + SMP::AP_STACK_SIZE;
        let idx = (cpu_id - 1) as usize;
        if idx < MAX_APS {
            AP_STACKS[idx].store(stack_top, Ordering::Release);
        }
        let rc = sbi_hart_start(hw_id, ap_entry_riscv as usize, cpu_id as usize);
        if rc == SBI::ERR_SUCCESS as isize {
            crate::println!("smp: hart {} (logical {}) start requested", hw_id, cpu_id);
        } else {
            crate::println!("smp: hart {} start failed, SBI error {}", hw_id, rc);
        }
    }
}

fn alloc_ap_stack() -> usize {
    let first = pmm::alloc_page().expect("smp: OOM allocating AP stack");
    for _ in 1..SMP::AP_STACK_PAGES { pmm::alloc_page().expect("smp: OOM"); }
    unsafe { core::ptr::write_bytes(first as *mut u8, 0, SMP::AP_STACK_SIZE); }
    first
}

pub unsafe fn ap_init_plic() {
    use crate::arch::riscv64::mem_layout::plic;
    let cpu_id = crate::smp::percpu::current_cpu_id();
    let hw_id  = crate::smp::cpu_info(cpu_id)
        .map(|i| i.hw_id as usize)
        .unwrap_or(cpu_id as usize);
    let ctx = plic::s_mode_context(hw_id);
    crate::drivers::plic::init_context(ctx);
}

pub unsafe fn init_hart() {
    crate::arch::riscv64::trap::trap_init();
    let now  = crate::arch::api::Timer::read_ticks();
    let next = now + 10_000_000;
    core::arch::asm!(
        "li a7, {eid}",
        "li a6, {fid}",
        "mv a0, {t}",
        "ecall",
        eid = const SBI::EID_TIMER,
        fid = const SBI::FID_TIMER_SET,
        t   = in(reg) next,
        options(nostack)
    );
}
