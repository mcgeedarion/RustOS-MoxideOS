//! RISC-V rv64 physical memory layout and hardware constants.
//!
//! **Single source of truth** for every magic number used by the kernel on
//! RISC-V.  No other file should embed raw hex constants for the items listed
//! here.
//!
//! ## Sections
//!
//!   - [`page`]         — page size / alignment helpers (Sv39)
//!   - [`sv39`]         — Sv39 paging mode constants and PTE field helpers
//!   - [`higher_half`]  — kernel higher-half VA offset (dynamic, linker-symbol)
//!   - [`satp`]         — SATP register mode field values
//!   - [`sstatus`]      — sstatus CSR bits used in trap/signal setup
//!   - [`sie`]          — sie/sip CSR interrupt-enable bit positions
//!   - [`scause`]       — scause interrupt and exception codes
//!   - [`trap`]         — trap-frame layout constants
//!   - [`sbi`]          — SBI Extension IDs and Function IDs
//!   - [`clint`]        — CLINT MMIO base and register offsets
//!   - [`plic`]         — PLIC MMIO base and context layout
//!   - [`uart`]         — NS16550-compatible UART (QEMU virt default)
//!   - [`smp`]          — AP stack and hart limits

pub mod page {
    pub const SIZE:          usize = 4096;
    pub const SHIFT:         usize = 12;
    pub const MASK:          usize = SIZE - 1;
    /// Entries per page table level (9-bit VPN indices).
    pub const TABLE_ENTRIES: usize = 512;
    /// 1 GiB superpage size used for the identity-map in `paging_init`.
    pub const SUPERPAGE_1G:  usize = 1 << 30;
    /// Page-align `n` upward.
    #[inline] pub const fn align_up(n: usize)   -> usize { (n + MASK) & !MASK }
    /// Page-align `n` downward.
    #[inline] pub const fn align_down(n: usize) -> usize { n & !MASK }
}

pub mod sv39 {
    /// PTE Valid bit.
    pub const PTE_V: usize = 1 << 0;
    /// PTE Readable.
    pub const PTE_R: usize = 1 << 1;
    /// PTE Writable.
    pub const PTE_W: usize = 1 << 2;
    /// PTE eXecutable.
    pub const PTE_X: usize = 1 << 3;
    /// PTE User-accessible.
    pub const PTE_U: usize = 1 << 4;
    /// PTE Global (not flushed on ASID switch).
    pub const PTE_G: usize = 1 << 5;
    /// PTE Accessed.
    pub const PTE_A: usize = 1 << 6;
    /// PTE Dirty.
    pub const PTE_D: usize = 1 << 7;

    /// PPN is stored in PTE bits [53:10].  Shift left 10 to get PTE value.
    pub const PPN_SHIFT: usize = 10;

    /// Extract the physical address from a leaf PTE.
    #[inline]
    pub const fn pte_to_pa(pte: usize) -> usize {
        (pte >> PPN_SHIFT) << super::page::SHIFT
    }

    /// Build a leaf PTE from a physical address and flag bits.
    #[inline]
    pub const fn pa_to_pte(pa: usize, flags: usize) -> usize {
        ((pa >> super::page::SHIFT) << PPN_SHIFT) | flags | PTE_V
    }

    /// Extract VPN[0] (PT index, bits [20:12]).
    #[inline] pub const fn vpn0(va: usize) -> usize { (va >> 12) & 0x1FF }
    /// Extract VPN[1] (PD index, bits [29:21]).
    #[inline] pub const fn vpn1(va: usize) -> usize { (va >> 21) & 0x1FF }
    /// Extract VPN[2] (root index, bits [38:30]).
    #[inline] pub const fn vpn2(va: usize) -> usize { (va >> 30) & 0x1FF }

    /// SATP mask covering all Sv39 PPN bits [43:0].
    pub const SATP_PPN_MASK: usize = 0x0FFF_FFFF_FFFF;
}

pub mod satp {
    /// Bare mode: no address translation.
    pub const MODE_BARE: usize = 0 << 60;
    /// Sv39 three-level page table (MODE field = 8).
    pub const MODE_SV39: usize = 8 << 60;
    /// Sv48 four-level page table (MODE field = 9).
    pub const MODE_SV48: usize = 9 << 60;
}

pub mod sstatus {
    /// SIE: Supervisor Interrupt Enable (bit 1).
    pub const SIE:  usize = 1 << 1;
    /// SPIE: Supervisor Previous Interrupt Enable (bit 5).
    /// Set this so interrupts are re-enabled on sret.
    pub const SPIE: usize = 1 << 5;
    /// SPP: Supervisor Previous Privilege (bit 8).
    /// 1 = returning to S-mode, 0 = returning to U-mode.
    pub const SPP:  usize = 1 << 8;
    /// MXR: Make eXecutable Readable (bit 19).
    pub const MXR:  usize = 1 << 19;
    /// SUM: Supervisor User Memory access (bit 18).
    pub const SUM:  usize = 1 << 18;
    /// Mask of bits cleared by `sret_trampoline` before entering userspace.
    /// Clears SPP (→ U-mode) and SPIE (handled explicitly).
    pub const SRET_CLEAR_MASK: usize = SPP | SPIE;
}

pub mod sie {
    /// SSIE: Supervisor Software Interrupt Enable (bit 1).
    /// Also the bit to clear in `sip` to acknowledge an S-mode software interrupt.
    pub const SSIE: usize = 1 << 1;
    /// STIE: Supervisor Timer Interrupt Enable (bit 5).
    pub const STIE: usize = 1 << 5;
    /// SEIE: Supervisor External Interrupt Enable (bit 9).
    pub const SEIE: usize = 1 << 9;
    /// Bitmask enabling all three supervisor interrupt sources at once.
    pub const ALL:  usize = SSIE | STIE | SEIE;
}

pub mod scause {
    /// Bit 63 set in scause means it is an interrupt, not an exception.
    pub const INTERRUPT_BIT: usize = 1 << 63;

    /// Supervisor software interrupt (IPI via SBI).
    pub const INT_S_SOFTWARE:  usize = 1;
    /// Supervisor timer interrupt.
    pub const INT_S_TIMER:     usize = 5;
    /// Supervisor external interrupt (PLIC).
    pub const INT_S_EXTERNAL:  usize = 9;

    /// Instruction address misaligned.
    pub const EXC_INSN_MISALIGN:   usize = 0;
    /// Instruction access fault.
    pub const EXC_INSN_FAULT:      usize = 1;
    /// Illegal instruction.
    pub const EXC_ILLEGAL_INSN:    usize = 2;
    /// Breakpoint.
    pub const EXC_BREAKPOINT:      usize = 3;
    /// Load address misaligned.
    pub const EXC_LOAD_MISALIGN:   usize = 4;
    /// Load access fault.
    pub const EXC_LOAD_FAULT:      usize = 5;
    /// Store/AMO address misaligned.
    pub const EXC_STORE_MISALIGN:  usize = 6;
    /// Store/AMO access fault.
    pub const EXC_STORE_FAULT:     usize = 7;
    /// Environment call from U-mode (syscall).
    pub const EXC_ECALL_U:         usize = 8;
    /// Environment call from S-mode.
    pub const EXC_ECALL_S:         usize = 9;
    /// Instruction page fault.
    pub const EXC_INSN_PAGE_FAULT: usize = 12;
    /// Load page fault.
    pub const EXC_LOAD_PAGE_FAULT: usize = 13;
    /// Store/AMO page fault.
    pub const EXC_STORE_PAGE_FAULT: usize = 15;
}

pub mod trap {
    /// Number of 8-byte slots saved in the trap frame (32 GPRs + sepc + sstatus + pad).
    pub const FRAME_SLOTS: usize = 34;
    /// Byte size of the full trap frame on the kernel stack.
    pub const FRAME_SIZE:  usize = FRAME_SLOTS * 8; // 272

    // Field indices within the frame (slot number × 8 = byte offset).
    pub const IDX_RA:      usize = 0;
    pub const IDX_SP:      usize = 1;
    pub const IDX_GP:      usize = 2;
    pub const IDX_TP:      usize = 3;
    pub const IDX_A0:      usize = 9;
    pub const IDX_A7:      usize = 16;
    pub const IDX_SEPC:    usize = 31;
    pub const IDX_SSTATUS: usize = 32;

    /// Size of one RISC-V compressed (C) instruction in bytes.
    pub const INSN_SIZE:   usize = 4;
}

pub mod sbi {
    /// SBI base extension (spec version, impl ID, etc.).
    pub const EID_BASE:    usize = 0x10;
    /// SBI Timer extension (replaces legacy `sbi_set_timer`).
    pub const EID_TIMER:   usize = 0x5449_4D45; // ASCII "TIME"
    /// SBI IPI extension (software inter-processor interrupt).
    pub const EID_IPI:     usize = 0x73_5049;   // ASCII "sPI"
    /// SBI RFENCE extension (remote fence / TLB shootdown).
    pub const EID_RFENCE:  usize = 0x5246_4E43; // ASCII "RFNC"
    /// SBI Hart State Management extension.
    pub const EID_HSM:     usize = 0x48_534D;   // ASCII "HSM"
    /// SBI System Reset extension.
    pub const EID_SRST:    usize = 0x5352_5354; // ASCII "SRST"
    /// SBI debug console extension (OpenSBI >= 1.0).
    pub const EID_DBCN:    usize = 0x4442_434E; // ASCII "DBCN"

    pub const FID_HSM_HART_START:  usize = 0;
    pub const FID_HSM_HART_STOP:   usize = 1;
    pub const FID_HSM_HART_STATUS: usize = 2;

    /// Set the next timer event (sbi_set_timer).
    pub const FID_TIMER_SET: usize = 0;

    /// Send software IPI to a hart mask.
    pub const FID_IPI_SEND: usize = 0;

    pub const FID_RFENCE_SFENCE_VMA:       usize = 1;
    pub const FID_RFENCE_SFENCE_VMA_ASID:  usize = 2;

    pub const ERR_SUCCESS:            isize =  0;
    pub const ERR_FAILED:             isize = -1;
    pub const ERR_NOT_SUPPORTED:      isize = -2;
    pub const ERR_INVALID_PARAM:      isize = -3;
    pub const ERR_DENIED:             isize = -4;
    pub const ERR_INVALID_ADDRESS:    isize = -5;
    pub const ERR_ALREADY_AVAILABLE:  isize = -6;
    pub const ERR_ALREADY_STARTED:    isize = -7;
    pub const ERR_ALREADY_STOPPED:    isize = -8;
}

// NOTE: On QEMU `virt` the CLINT is present at 0x0200_0000.  On OpenSBI
// platforms the SBI Timer extension (EID_TIMER) should be preferred for
// setting timer events so that M-mode and S-mode timers don't conflict.
// The CLINT base is provided here for bare-metal / direct-access use cases.

pub mod clint {
    /// CLINT MMIO base on the QEMU `virt` machine.
    pub const BASE_QEMU_VIRT: usize = 0x0200_0000;

    /// MSIP register for hart N: `BASE + MSIP_OFF + N * 4` (32-bit, R/W).
    pub const MSIP_OFF:    usize = 0x0000;
    /// MTIMECMP register for hart N: `BASE + MTIMECMP_OFF + N * 8` (64-bit).
    pub const MTIMECMP_OFF: usize = 0x4000;
    /// MTIME register (global 64-bit counter): `BASE + MTIME_OFF`.
    pub const MTIME_OFF:   usize = 0xBFF8;
}

pub mod plic {
    /// PLIC MMIO base on the QEMU `virt` machine.
    pub const BASE_QEMU_VIRT: usize = 0x0C00_0000;

    /// Priority register for source N: `BASE + N * 4`.
    pub const PRIORITY_BASE:  usize = 0x0000;
    /// Pending array: `BASE + PENDING_OFF + word_index * 4`.
    pub const PENDING_OFF:    usize = 0x1000;
    /// Enable bits for context C, source N:
    /// `BASE + ENABLE_OFF + C * 0x80 + (N / 32) * 4`.
    pub const ENABLE_OFF:     usize = 0x2000;
    /// Priority threshold for context C: `BASE + THRESHOLD_OFF + C * 0x1000`.
    pub const THRESHOLD_OFF:  usize = 0x20_0000;
    /// Claim/complete register for context C: `BASE + CLAIM_OFF + C * 0x1000`.
    pub const CLAIM_OFF:      usize = 0x20_0004;

    /// Each hart N has two PLIC contexts:
    ///   M-mode context = N * 2
    ///   S-mode context = N * 2 + 1
    #[inline]
    pub const fn s_mode_context(hart_id: usize) -> usize { hart_id * 2 + 1 }
}

// MMIO-mapped, unlike the x86 ISA-port-mapped 16550.  Register width is
// 1 byte per cell, accessed as `u8` at naturally-aligned MMIO addresses.

pub mod uart {
    /// UART0 MMIO base on the QEMU `virt` machine.
    pub const BASE_QEMU_VIRT: usize = 0x1000_0000;

    // Register offsets (bytes from UART base).
    /// Receive Buffer / Transmit Holding (DLAB=0).
    pub const OFF_RBR_THR: usize = 0;
    /// Interrupt Enable Register (DLAB=0).
    pub const OFF_IER:     usize = 1;
    /// FIFO Control Register.
    pub const OFF_FCR:     usize = 2;
    /// Line Control Register.
    pub const OFF_LCR:     usize = 3;
    /// Modem Control Register.
    pub const OFF_MCR:     usize = 4;
    /// Line Status Register.
    pub const OFF_LSR:     usize = 5;
    /// Divisor Latch Low (DLAB=1).
    pub const OFF_DLL:     usize = 0;
    /// Divisor Latch High (DLAB=1).
    pub const OFF_DLH:     usize = 1;

    /// LSR bit 5: Transmit Holding Register Empty.
    pub const LSR_THRE: u8 = 0x20;
    /// LCR: 8N1, DLAB off.
    pub const LCR_8N1:  u8 = 0x03;
    /// LCR: enable DLAB.
    pub const LCR_DLAB: u8 = 0x80;
    /// FCR: enable + clear both FIFOs + 14-byte trigger.
    pub const FCR_ENABLE_CLEAR_14: u8 = 0xC7;
}

pub mod smp {
    /// Number of 4 KiB pages per AP kernel stack (64 KiB).
    pub const AP_STACK_PAGES: usize = 16;
    /// AP kernel stack size in bytes.
    pub const AP_STACK_SIZE:  usize = AP_STACK_PAGES * super::page::SIZE;
}
