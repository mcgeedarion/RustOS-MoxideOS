//! RISC-V 64 HAL implementation — `arch::api` trait impls.

use crate::arch::api::{
    ArchInit, Interrupts, Cpu, Timer, Paging, PageFlags,
    ContextSwitch, TrapFrame, Syscall, Serial, FpState, Tlb,
};
use crate::arch::riscv64::{
    paging as rv_paging,
    csr,
};

pub struct ArchImpl;

// ─── ArchInit ────────────────────────────────────────────────────────────

impl ArchInit for ArchImpl {
    fn early_init() {
        // RISC-V: delegate exceptions/interrupts from M to S mode.
        // This is usually done by the SBI firmware; confirm stvec is set.
        unsafe {
            // Set stvec to our trap entry (defined in trap.rs).
            extern "C" { fn riscv_trap_entry(); }
            csr::write_stvec(riscv_trap_entry as usize);
            // Enable supervisor interrupts in sstatus: SIE bit = 1.
            // (We unmask specific causes via sie register in late_init.)
        }
    }

    fn late_init() {
        unsafe {
            // Enable software timer interrupt (STIE) and software interrupt (SSIE).
            let sie = csr::read_sie();
            csr::write_sie(sie | (1 << 5) | (1 << 1));
            // Enable global supervisor interrupt (SIE bit in sstatus).
            let ss = csr::read_sstatus();
            csr::write_sstatus(ss | (1 << 1));
        }
    }
}

// ─── Interrupts ──────────────────────────────────────────────────────────

impl Interrupts for ArchImpl {
    #[inline]
    fn enable() {
        unsafe {
            let ss = csr::read_sstatus();
            csr::write_sstatus(ss | (1 << 1)); // SIE bit
        }
    }
    #[inline]
    fn disable() {
        unsafe {
            let ss = crate::arch::riscv64::csr::read_sstatus();
            crate::arch::riscv64::csr::write_sstatus(ss & !(1 << 1));
        }
    }
    #[inline]
    fn are_enabled() -> bool {
        unsafe { csr::read_sstatus() & (1 << 1) != 0 }
    }
}

// ─── Cpu ─────────────────────────────────────────────────────────────────

impl Cpu for ArchImpl {
    #[inline]
    fn halt() {
        unsafe { core::arch::asm!("wfi", options(nostack, nomem)); }
    }
    #[inline]
    fn spin_hint() {
        unsafe { core::arch::asm!("nop", options(nostack, nomem)); }
    }
    fn id() -> u32 {
        // Read mhartid via SBI ecall (SBI extension 0x4, FID 0).
        // On most systems the hart ID is in mscratch or passed by SBI.
        // Fall back to 0 for single-hart.
        let id: u64;
        unsafe {
            core::arch::asm!(
                "li a7, 0x4",
                "li a6, 0",
                "li a0, 0",
                "ecall",
                out("a0") id,
                options(nostack)
            );
        }
        id as u32
    }
    fn flags() -> usize {
        unsafe { csr::read_sstatus() }
    }
}

// ─── Timer ───────────────────────────────────────────────────────────────

impl Timer for ArchImpl {
    fn init_timer() {
        // Program SBI timer extension (SBI_EXT_TIME = 0x54494D45, FID 0).
        // Set the next timer event 10 ms from now.
        let now = Self::read_ticks();
        let next = now + 10_000_000; // ~10 ms at 1 GHz
        unsafe {
            core::arch::asm!(
                "li a7, 0x54494D45",  // SBI_EXT_TIME
                "li a6, 0",           // FID 0 = set_timer
                "mv a0, {t}",
                "ecall",
                t = in(reg) next,
                options(nostack)
            );
        }
    }
    fn ticks_per_sec() -> u64 { 100 }
    fn read_ticks() -> u64 {
        let v: u64;
        unsafe { core::arch::asm!("rdtime {}", out(reg) v, options(nostack, nomem)); }
        v
    }
}

// ─── Paging ──────────────────────────────────────────────────────────────

impl Paging for ArchImpl {
    fn map_page(cr3: usize, va: usize, pa: usize, flags: PageFlags) -> bool {
        // Translate HAL flags → Sv39 PTE flags.
        let mut pte: u64 = 1; // Valid bit
        if flags.contains(PageFlags::WRITE) { pte |= 1 << 2; } // W
        if flags.contains(PageFlags::EXEC)  { pte |= 1 << 3; } // X
        if flags.contains(PageFlags::USER)  { pte |= 1 << 4; } // U
        if flags.contains(PageFlags::PRESENT) {
            pte |= (1 << 1); // R — readable at minimum
        }
        rv_paging::map_page(cr3, va, pa, pte);
        true
    }
    fn unmap_page(cr3: usize, va: usize) -> Option<usize> {
        rv_paging::unmap_page(cr3, va)
    }
    fn virt_to_phys(cr3: usize, va: usize) -> Option<usize> {
        rv_paging::virt_to_phys(cr3, va)
    }
    fn kernel_cr3() -> usize {
        rv_paging::kernel_satp()
    }
    fn load_cr3(cr3: usize) {
        rv_paging::load_satp(cr3);
    }
    fn flush_va(va: usize) {
        unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) va, options(nostack)); }
    }
    fn flush_all() {
        unsafe { core::arch::asm!("sfence.vma zero, zero", options(nostack)); }
    }
    fn clone_address_space(src_cr3: usize) -> Option<usize> {
        rv_paging::clone_sv39_cow(src_cr3)
    }
    fn new_user_address_space() -> Option<usize> {
        rv_paging::new_user_sv39()
    }
}

// ─── Tlb ─────────────────────────────────────────────────────────────────

impl Tlb for ArchImpl {
    fn flush_va(va: usize) {
        unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) va, options(nostack)); }
    }
    fn flush_all() {
        unsafe { core::arch::asm!("sfence.vma zero, zero", options(nostack)); }
    }
    fn flush_asid(asid: u16) {
        unsafe {
            core::arch::asm!("sfence.vma zero, {a}", a = in(reg) asid as usize, options(nostack));
        }
    }
}

// ─── ContextSwitch ───────────────────────────────────────────────────────

impl ContextSwitch for ArchImpl {
    unsafe fn switch_to(
        current_frame: *mut TrapFrame,
        next_frame:    *const TrapFrame,
        next_cr3:      usize,
    ) {
        // Save callee-saved registers (s0-s11, sp) into current_frame.
        let f = &mut *current_frame;
        core::arch::asm!(
            "sd sp,   [{f}  + 8]",   // regs[1] = sp
            "sd s0,   [{f}  + 64]",  // regs[8]
            "sd s1,   [{f}  + 72]",
            "sd s2,   [{f}  + 128]",
            "sd s3,   [{f}  + 136]",
            "sd s4,   [{f}  + 144]",
            "sd s5,   [{f}  + 152]",
            "sd s6,   [{f}  + 160]",
            "sd s7,   [{f}  + 168]",
            "sd s8,   [{f}  + 176]",
            "sd s9,   [{f}  + 184]",
            "sd s10,  [{f}  + 192]",
            "sd s11,  [{f}  + 200]",
            f = in(reg) f as *mut TrapFrame,
            options(nostack)
        );
        // Switch address space.
        if next_cr3 != rv_paging::kernel_satp() {
            rv_paging::load_satp(next_cr3);
        }
        // Restore callee-saved regs from next_frame.
        let nf = &*next_frame;
        core::arch::asm!(
            "ld sp,  [{f}  + 8]",
            "ld s0,  [{f}  + 64]",
            "ld s1,  [{f}  + 72]",
            "ld s2,  [{f}  + 128]",
            "ld s3,  [{f}  + 136]",
            "ld s4,  [{f}  + 144]",
            "ld s5,  [{f}  + 152]",
            "ld s6,  [{f}  + 160]",
            "ld s7,  [{f}  + 168]",
            "ld s8,  [{f}  + 176]",
            "ld s9,  [{f}  + 184]",
            "ld s10, [{f}  + 192]",
            "ld s11, [{f}  + 200]",
            f = in(reg) nf as *const TrapFrame,
            options(nostack)
        );
    }

    fn make_user_frame(entry: u64, user_sp: u64) -> TrapFrame {
        let mut f = TrapFrame::zeroed();
        f.pc      = entry;
        f.user_sp = user_sp;
        // sstatus: SPP=0 (user), SPIE=1 (enable interrupts on sret)
        f.flags   = 1 << 5; // SPIE
        f
    }

    fn current_sp() -> usize {
        let sp: usize;
        unsafe { core::arch::asm!("mv {}, sp", out(reg) sp, options(nostack, nomem)); }
        sp
    }
}

// ─── Syscall ─────────────────────────────────────────────────────────────

impl Syscall for ArchImpl {
    fn syscall_setup() {
        // stvec is set in early_init; nothing extra needed.
    }
    unsafe fn syscall_return(frame: *const TrapFrame) -> ! {
        let f = &*frame;
        core::arch::asm!(
            "mv a0, {ret}",   // return value
            "csrw sepc, {pc}",
            "sret",
            ret = in(reg) f.regs[0],
            pc  = in(reg) f.pc,
            options(noreturn)
        );
    }
}

// ─── Serial ──────────────────────────────────────────────────────────────
// RISC-V QEMU virt machine UART is NS16550A at 0x1000_0000.

const UART_BASE: usize = 0x1000_0000;

impl Serial for ArchImpl {
    fn serial_init() {
        // NS16550A: set DLAB, write divisor for 115200 @ 1.8432 MHz,
        // then 8N1 LCR, FIFO enable, MCR loop-off.
        unsafe {
            let b = UART_BASE;
            (b as *mut u8).write_volatile(0x00); // IER = 0
            ((b+3) as *mut u8).write_volatile(0x80); // LCR DLAB
            (b as *mut u8).write_volatile(0x01); // DLL
            ((b+1) as *mut u8).write_volatile(0x00); // DLH
            ((b+3) as *mut u8).write_volatile(0x03); // 8N1, clear DLAB
            ((b+2) as *mut u8).write_volatile(0xC7); // FIFO enable
            ((b+4) as *mut u8).write_volatile(0x0B); // MCR
        }
    }
    fn serial_putc(byte: u8) {
        unsafe {
            // Spin on TX holding register empty (LSR bit 5).
            loop {
                let lsr = ((UART_BASE + 5) as *const u8).read_volatile();
                if lsr & 0x20 != 0 { break; }
            }
            (UART_BASE as *mut u8).write_volatile(byte);
        }
    }
    fn serial_getc() -> Option<u8> {
        unsafe {
            let lsr = ((UART_BASE + 5) as *const u8).read_volatile();
            if lsr & 0x01 != 0 {
                Some((UART_BASE as *const u8).read_volatile())
            } else {
                None
            }
        }
    }
}

// ─── FpState ─────────────────────────────────────────────────────────────
// RISC-V D-extension: 32 × 64-bit FP registers + fcsr (1×32).

const RISCV_FP_AREA: usize = 32 * 8 + 8; // 264 bytes

impl FpState for ArchImpl {
    fn fp_init() {
        unsafe {
            // Enable FS in sstatus (bits [14:13] = 01 → Initial).
            let ss = csr::read_sstatus();
            csr::write_sstatus(ss | (1 << 13));
        }
    }
    unsafe fn fp_save(dst: *mut u8) {
        // Store f0-f31 then fcsr.
        let ptr = dst as *mut u64;
        core::arch::asm!(
            "fsd f0,  0({p})",  "fsd f1,  8({p})",  "fsd f2,  16({p})",
            "fsd f3,  24({p})", "fsd f4,  32({p})", "fsd f5,  40({p})",
            "fsd f6,  48({p})", "fsd f7,  56({p})", "fsd f8,  64({p})",
            "fsd f9,  72({p})", "fsd f10, 80({p})", "fsd f11, 88({p})",
            "fsd f12, 96({p})", "fsd f13, 104({p})","fsd f14, 112({p})",
            "fsd f15, 120({p})","fsd f16, 128({p})","fsd f17, 136({p})",
            "fsd f18, 144({p})","fsd f19, 152({p})","fsd f20, 160({p})",
            "fsd f21, 168({p})","fsd f22, 176({p})","fsd f23, 184({p})",
            "fsd f24, 192({p})","fsd f25, 200({p})","fsd f26, 208({p})",
            "fsd f27, 216({p})","fsd f28, 224({p})","fsd f29, 232({p})",
            "fsd f30, 240({p})","fsd f31, 248({p})",
            p = in(reg) ptr,
            options(nostack)
        );
        let fcsr: u32;
        core::arch::asm!("frcsr {}", out(reg) fcsr, options(nostack, nomem));
        *(dst.add(256) as *mut u32) = fcsr;
    }
    unsafe fn fp_restore(src: *const u8) {
        let ptr = src as *const u64;
        core::arch::asm!(
            "fld f0,  0({p})",  "fld f1,  8({p})",  "fld f2,  16({p})",
            "fld f3,  24({p})", "fld f4,  32({p})", "fld f5,  40({p})",
            "fld f6,  48({p})", "fld f7,  56({p})", "fld f8,  64({p})",
            "fld f9,  72({p})", "fld f10, 80({p})", "fld f11, 88({p})",
            "fld f12, 96({p})", "fld f13, 104({p})","fld f14, 112({p})",
            "fld f15, 120({p})","fld f16, 128({p})","fld f17, 136({p})",
            "fld f18, 144({p})","fld f19, 152({p})","fld f20, 160({p})",
            "fld f21, 168({p})","fld f22, 176({p})","fld f23, 184({p})",
            "fld f24, 192({p})","fld f25, 200({p})","fld f26, 208({p})",
            "fld f27, 216({p})","fld f28, 224({p})","fld f29, 232({p})",
            "fld f30, 240({p})","fld f31, 248({p})",
            p = in(reg) ptr,
            options(nostack)
        );
        let fcsr = *(src.add(256) as *const u32);
        core::arch::asm!("fscsr {}", in(reg) fcsr, options(nostack, nomem));
    }
    fn fp_area_size() -> usize { RISCV_FP_AREA }
}
