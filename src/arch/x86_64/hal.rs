//! x86-64 HAL implementation — `arch::api` trait impls.

use crate::arch::api::{
    ArchInit, ContextSwitch, Cpu, FpState, Interrupts, PageFlags, Paging, Serial, Syscall, Timer,
    Tlb, TrapFrame,
};
use crate::arch::x86_64::{
    apic, cpu as x86_cpu, gdt::gdt_init, idt::idt_init, paging as x86_paging, serial as x86_serial,
    syscall::syscall_setup as x86_syscall_setup, xsave,
};

pub struct ArchImpl;

impl ArchInit for ArchImpl {
    fn early_init() {
        gdt_init();
        idt_init();
        x86_syscall_setup();
        x86_serial::init();
    }

    fn late_init() {
        xsave::xsave_init();
        apic::apic_init(); // enables interrupts (STI)
    }
}

impl Interrupts for ArchImpl {
    #[inline]
    fn enable() {
        unsafe {
            core::arch::asm!("sti", options(nostack));
        }
    }
    #[inline]
    fn disable() {
        unsafe {
            core::arch::asm!("cli", options(nostack));
        }
    }
    #[inline]
    fn are_enabled() -> bool {
        let rflags: u64;
        unsafe {
            core::arch::asm!("pushfq; pop {f}", f = out(reg) rflags, options(nostack));
        }
        rflags & (1 << 9) != 0 // IF bit
    }
}

impl Cpu for ArchImpl {
    #[inline]
    fn halt() {
        unsafe {
            core::arch::asm!("hlt", options(nostack, nomem));
        }
    }
    #[inline]
    fn spin_hint() {
        unsafe {
            core::arch::asm!("pause", options(nostack, nomem));
        }
    }
    fn id() -> u32 {
        // LAPIC ID from MSR IA32_TSC_AUX (set by gdt_init on each CPU)
        // Fall back to CPUID leaf 1 EBX[31:24] on BSP.
        let cpuid1 = unsafe { core::arch::x86_64::__cpuid(1) };
        cpuid1.ebx >> 24
    }
    fn flags() -> usize {
        let rflags: usize;
        unsafe {
            core::arch::asm!("pushfq; pop {f}", f = out(reg) rflags, options(nostack));
        }
        rflags
    }
}

impl Timer for ArchImpl {
    fn init_timer() {
        apic::apic_init(); // programs LAPIC timer + issues STI
    }
    fn ticks_per_sec() -> u64 {
        100 // 10 ms period at current LAPIC calibration
    }
    fn read_ticks() -> u64 {
        // Use RDTSC as a cheap monotonic source.
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
        }
        ((hi as u64) << 32) | lo as u64
    }
}

impl Paging for ArchImpl {
    fn map_page(cr3: usize, va: usize, pa: usize, flags: PageFlags) -> bool {
        // Translate HAL flags → native x86 PTE flags.
        let mut pte_flags: u64 = x86_paging::PTE_PRESENT;
        if flags.contains(PageFlags::WRITE) {
            pte_flags |= x86_paging::PTE_WRITABLE;
        }
        if flags.contains(PageFlags::USER) {
            pte_flags |= x86_paging::PTE_USER;
        }
        if flags.contains(PageFlags::NX) {
            pte_flags |= x86_paging::PTE_NX;
        }
        if flags.contains(PageFlags::COW) {
            pte_flags |= x86_paging::PTE_COW;
        }
        x86_paging::map_page(cr3, va, pa, pte_flags);
        true
    }
    fn unmap_page(cr3: usize, va: usize) -> Option<usize> {
        // Current unmap_page uses current CR3; we load cr3 first if needed.
        let cur = x86_paging::current_cr3();
        if cur != cr3 {
            x86_paging::load_cr3(cr3);
        }
        let r = x86_paging::unmap_page(va);
        if cur != cr3 {
            x86_paging::load_cr3(cur);
        }
        r
    }
    fn virt_to_phys(cr3: usize, va: usize) -> Option<usize> {
        x86_paging::virt_to_phys(cr3, va)
    }
    fn kernel_cr3() -> usize {
        x86_paging::kernel_cr3()
    }
    fn load_cr3(cr3: usize) {
        x86_paging::load_cr3(cr3);
    }
    fn flush_va(va: usize) {
        x86_paging::invlpg(va);
    }
    fn flush_all() {
        // Reload CR3 to flush all non-global entries.
        let cr3 = x86_paging::current_cr3();
        x86_paging::load_cr3(cr3);
    }
    fn clone_address_space(src_cr3: usize) -> Option<usize> {
        Some(x86_paging::clone_pml4_cow(src_cr3))
    }
    fn new_user_address_space() -> Option<usize> {
        use crate::mm::pmm::alloc_page;
        let cr3 = alloc_page()?;
        unsafe {
            core::ptr::write_bytes(cr3 as *mut u8, 0, 4096);
        }
        // Copy kernel PML4 entries (high half: indices 256-511).
        let kc3 = x86_paging::kernel_cr3();
        unsafe {
            let src = (kc3 + 256 * 8) as *const u64;
            let dst = (cr3 + 256 * 8) as *mut u64;
            core::ptr::copy_nonoverlapping(src, dst, 256);
        }
        Some(cr3)
    }
}

impl Tlb for ArchImpl {
    fn flush_va(va: usize) {
        x86_paging::invlpg(va);
    }
    fn flush_all() {
        let cr3 = x86_paging::current_cr3();
        x86_paging::load_cr3(cr3);
    }
    fn flush_asid(_asid: u16) {
        // x86-64 without PCID: flush all TLB entries.
        <ArchImpl as Tlb>::flush_all();
    }
}

impl ContextSwitch for ArchImpl {
    unsafe fn switch_to(
        current_frame: *mut TrapFrame,
        next_frame: *const TrapFrame,
        next_cr3: usize,
    ) {
        // Save callee-saved registers into current_frame.
        // (Caller-saved regs were saved by the interrupt/syscall entry asm.)
        let frame = &mut *current_frame;
        // regs[6]  = rbx  (index matches Linux kernel convention)
        // regs[7]  = rbp
        // regs[8..13] = r12..r15
        core::arch::asm!(
            "mov [{f} + 48], rbx",
            "mov [{f} + 56], rbp",
            "mov [{f} + 64], r12",
            "mov [{f} + 72], r13",
            "mov [{f} + 80], r14",
            "mov [{f} + 88], r15",
            f = in(reg) frame as *mut TrapFrame,
            options(nostack)
        );
        // Switch address space if needed.
        if next_cr3 != x86_paging::current_cr3() {
            x86_paging::load_cr3(next_cr3);
        }
        // Restore callee-saved registers from next_frame.
        let nf = &*next_frame;
        core::arch::asm!(
            "mov rbx, [{f} + 48]",
            "mov rbp, [{f} + 56]",
            "mov r12, [{f} + 64]",
            "mov r13, [{f} + 72]",
            "mov r14, [{f} + 80]",
            "mov r15, [{f} + 88]",
            f = in(reg) nf as *const TrapFrame,
            options(nostack)
        );
    }

    fn make_user_frame(entry: u64, user_sp: u64) -> TrapFrame {
        let mut f = TrapFrame::zeroed();
        f.pc = entry;
        f.user_sp = user_sp;
        // RFLAGS: IF=1 (enable interrupts in user mode), IOPL=0
        f.flags = 0x0000_0202;
        f
    }

    fn current_sp() -> usize {
        let rsp: usize;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem));
        }
        rsp
    }
}

impl Syscall for ArchImpl {
    fn syscall_setup() {
        x86_syscall_setup();
    }
    unsafe fn syscall_return(frame: *const TrapFrame) -> ! {
        let f = &*frame;
        // Restore user registers and SYSRET to user space.
        // rax = return value, rcx = saved RIP, r11 = saved RFLAGS.
        core::arch::asm!(
            "mov rsp, {usp}",
            "mov rcx, {pc}",
            "mov r11, {flags}",
            "mov rax, {ret}",
            "sysretq",
            usp   = in(reg) f.user_sp,
            pc    = in(reg) f.pc,
            flags = in(reg) f.flags,
            ret   = in(reg) f.regs[0],
            options(noreturn)
        );
    }
}

impl Serial for ArchImpl {
    fn serial_init() {
        x86_serial::init();
    }
    fn serial_putc(byte: u8) {
        x86_serial::putc(byte);
    }
    fn serial_getc() -> Option<u8> {
        x86_serial::getc()
    }
}

impl FpState for ArchImpl {
    fn fp_init() {
        xsave::xsave_init();
    }
    unsafe fn fp_save(dst: *mut u8) {
        xsave::xsave_to(dst);
    }
    unsafe fn fp_restore(src: *const u8) {
        xsave::xrstor_from(src);
    }
    fn fp_area_size() -> usize {
        xsave::xsave_area_size()
    }
}

// ====================================================================
// HAL free functions (consumed by `crate::arch::api::*` wrappers).
//
// These are the surface that `arch::api::name`, `arch::api::cpu_relax`,
// `arch::api::tlb_flush_all`, etc. forward to. Keeping them as plain
// free fns rather than trait methods preserves the existing
// `crate::arch::hal::<fn>` import path used by `arch::api`.
// ====================================================================

use core::ops::Range;

/// Canonical kernel virtual address range on x86_64 (higher half).
#[inline]
pub fn kernel_va_range() -> Range<usize> {
    0xFFFF_8000_0000_0000usize..0xFFFF_FFFF_FFFF_FFFFusize
}

/// `true` if `addr` is in the canonical user-space half of the AS.
#[inline]
pub fn is_user_addr(addr: usize) -> bool {
    addr < 0x0000_8000_0000_0000
}

/// `true` if `addr` is canonical (top 16 bits are sign-extension of bit 47).
#[inline]
pub fn is_valid_addr(addr: usize) -> bool {
    let hi = addr >> 47;
    hi == 0 || hi == 0x1_FFFF
}

/// Flush the entire local TLB by writing CR3.
#[inline]
pub unsafe fn tlb_flush_all() {
    let cr3: u64;
    core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    core::arch::asm!("mov cr3, {0}", in(reg) cr3, options(nostack, preserves_flags));
}

/// Invalidate a single page TLB entry.
#[inline]
pub unsafe fn tlb_flush_page(va: usize) {
    core::arch::asm!("invlpg [{0}]", in(reg) va, options(nostack, preserves_flags));
}

/// SMT-friendly pause hint.
#[inline]
pub fn cpu_relax() {
    unsafe { core::arch::asm!("pause", options(nostack, nomem, preserves_flags)) }
}

/// Halt until the next interrupt is delivered.
#[inline]
pub fn wait_for_interrupt() {
    unsafe { core::arch::asm!("hlt", options(nostack, nomem, preserves_flags)) }
}

/// Read the TSC.
#[inline]
pub fn time_now_cycles() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Emit `int3` for the debugger.
#[inline]
pub fn debug_break() {
    unsafe { core::arch::asm!("int3", options(nostack, nomem, preserves_flags)) }
}

/// Local APIC ID via CPUID.1.EBX[31:24]. Falls back to 0 if CPUID is
/// unavailable (which never happens on real x86_64 hardware but keeps
/// this safe in odd test environments).
#[inline]
pub fn cpu_id() -> usize {
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            inout("eax") 1u32 => _,
            ebx = out(reg) ebx,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
    ((ebx >> 24) & 0xff) as usize
}

/// Enable interrupts on the local CPU (`STI`).
#[inline]
pub unsafe fn interrupts_enable() {
    core::arch::asm!("sti", options(nostack, nomem));
}

/// Disable interrupts on the local CPU (`CLI`).
#[inline]
pub unsafe fn interrupts_disable() {
    core::arch::asm!("cli", options(nostack, nomem));
}

/// Returns `true` if the IF flag in RFLAGS is set.
#[inline]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {0}", out(reg) flags, options(nomem, preserves_flags));
    }
    (flags & (1 << 9)) != 0
}
