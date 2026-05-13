//! x86-64 physical memory layout constants.
//!
//! **Single source of truth** for every magic address, I/O port, and
//! hardware-defined constant used by the kernel on x86-64.  No other file
//! should embed raw hex addresses or port numbers for the items listed here.
//!
//! ## Sections
//!
//!   - [`page`]       — page size / alignment helpers
//!   - [`higher_half`]— kernel higher-half virtual address space
//!   - [`serial`]     — 16550 UART COM port I/O addresses
//!   - [`pit`]        — 8253/8254 Programmable Interval Timer ports
//!   - [`apic`]       — Local APIC MMIO, MSRs, and AP trampoline
//!   - [`ioapic`]     — I/O APIC default MMIO base
//!   - [`vga`]        — Legacy VGA text-mode buffer
//!   - [`gdt_layout`] — GDT selector indices
//!   - [`trampoline`] — AP shared-memory slot offsets within the trampoline page

// ── Page constants ────────────────────────────────────────────────────────────

pub mod page {
    pub const SIZE:      usize = 4096;
    pub const SHIFT:     usize = 12;
    pub const MASK:      usize = SIZE - 1;
    pub const ALIGN_UP:  fn(usize) -> usize = |n| (n + MASK) & !MASK;
    pub const TABLE_ENTRIES: usize = 512; // entries per PML4/PDPT/PD/PT table

    /// PTE address mask — bits [51:12].
    pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
}

// ── Higher-half virtual address space ─────────────────────────────────────────

pub mod higher_half {
    /// PA → VA: add this offset to any physical address to get the
    /// kernel's direct-map virtual address.  Works before and after
    /// our page-table switch because the UEFI identity-map is still
    /// live until we install our own PML4.
    ///
    /// Memory layout:
    ///   0xFFFF_8000_0000_0000 ..= 0xFFFF_FFFF_FFFF_FFFF  — kernel direct-map
    ///   All lower-half VAs (0 ..= 0x0000_7FFF_FFFF_FFFF) — user space
    pub const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

    #[inline]
    pub fn phys_to_virt(pa: u64)  -> usize { pa as usize + PHYS_OFFSET }
    #[inline]
    pub fn virt_to_phys(va: usize) -> u64  { (va - PHYS_OFFSET) as u64 }
}

// ── 16550 UART serial ports ───────────────────────────────────────────────────

pub mod serial {
    /// COM1 base I/O port.  All register offsets are added to this.
    pub const COM1_BASE: u16 = 0x3F8;
    /// COM2 base I/O port.
    pub const COM2_BASE: u16 = 0x2F8;
    /// COM3 base I/O port.
    pub const COM3_BASE: u16 = 0x3E8;
    /// COM4 base I/O port.
    pub const COM4_BASE: u16 = 0x2E8;

    // ── Register offsets (relative to COMx_BASE) ───────────────────────────
    /// Transmit Holding / Receive Buffer (DLAB=0).
    pub const OFF_DATA:     u16 = 0;
    /// Interrupt Enable Register (DLAB=0) / Baud rate divisor high (DLAB=1).
    pub const OFF_IER:      u16 = 1;
    /// Baud rate divisor low byte (DLAB=1).
    pub const OFF_DLL:      u16 = 0;
    /// Baud rate divisor high byte (DLAB=1).
    pub const OFF_DLH:      u16 = 1;
    /// FIFO Control Register.
    pub const OFF_FCR:      u16 = 2;
    /// Line Control Register.
    pub const OFF_LCR:      u16 = 3;
    /// Modem Control Register.
    pub const OFF_MCR:      u16 = 4;
    /// Line Status Register.
    pub const OFF_LSR:      u16 = 5;

    // ── Divisors for common baud rates (assuming 1.8432 MHz clock) ─────────
    /// 115200 baud.
    pub const BAUD_115200: u16 = 1;
    /// 57600 baud.
    pub const BAUD_57600:  u16 = 2;
    /// 38400 baud.
    pub const BAUD_38400:  u16 = 3;
    /// 9600 baud.
    pub const BAUD_9600:   u16 = 12;

    // ── LCR / MCR / FCR values ──────────────────────────────────────────────
    /// LCR: 8 data bits, no parity, 1 stop bit (8N1).
    pub const LCR_8N1:   u8 = 0x03;
    /// LCR: DLAB enable bit.
    pub const LCR_DLAB:  u8 = 0x80;
    /// MCR: RTS + DTR (needed to get data to flow on most adapters).
    pub const MCR_RTS_DTR: u8 = 0x0B;
    /// FCR: Enable + clear both FIFOs + 14-byte trigger level.
    pub const FCR_ENABLE_CLEAR_14: u8 = 0xC7;
    /// LSR bit 5: Transmit Holding Register Empty — safe to send next byte.
    pub const LSR_THRE: u8 = 0x20;
}

// ── 8253/8254 PIT ─────────────────────────────────────────────────────────────

pub mod pit {
    /// PIT Channel 0 I/O port (IRQ 0 / system timer).
    pub const CH0:      u16 = 0x40;
    /// PIT Channel 2 I/O port (PC speaker).
    pub const CH2:      u16 = 0x42;
    /// PIT Mode/Command register.
    pub const CMD:      u16 = 0x43;

    /// Mode 2 (rate generator), channel 0, both bytes, binary.
    /// Write to CMD before programming CH0.
    pub const CMD_CH0_RATE_GEN: u8 = 0x34;
    /// Latch count command for CH0 (used to read current count).
    pub const CMD_CH0_LATCH:    u8 = 0x00;

    /// Divisor that gives ~50 ms gate period for TSC calibration.
    /// 1_193_182 Hz / 59_659 ≈ 20 Hz → 50 ms period.
    pub const CALIB_DIVISOR: u16 = 59_659;
}

// ── Local APIC ────────────────────────────────────────────────────────────────

pub mod apic {
    // ── MMIO base ──────────────────────────────────────────────────────────
    /// Architectural default LAPIC MMIO base (before firmware relocation).
    /// Always verify the actual base from IA32_APIC_BASE (MSR 0x1B) at init.
    pub const LAPIC_PHYS_DEFAULT: u64 = 0xFEE0_0000;

    // ── MSRs ────────────────────────────────────────────────────────────────
    /// IA32_APIC_BASE MSR — contains LAPIC enable, x2APIC enable, and
    /// the MMIO base physical address in bits [51:12].
    pub const MSR_IA32_APIC_BASE: u32 = 0x1B;
    /// Mask to extract the MMIO base PA from IA32_APIC_BASE (clears low 12).
    pub const MSR_APIC_BASE_MASK: u64 = !0xFFF;
    /// Bit 10 of IA32_APIC_BASE_LO: enable x2APIC mode.
    pub const MSR_X2APIC_ENABLE:  u32 = 1 << 10;
    /// Bit 11 of IA32_APIC_BASE_LO: global APIC enable.
    pub const MSR_APIC_GLOBAL_EN: u32 = 1 << 11;
    /// x2APIC register MSR base — MSR for LAPIC register at offset `off`
    /// is `X2APIC_MSR_BASE + (off >> 4)`.
    pub const X2APIC_MSR_BASE:    u32 = 0x800;

    // ── LAPIC register offsets (bytes from MMIO base) ───────────────────────
    pub const REG_ID:          usize = 0x020;
    pub const REG_VERSION:     usize = 0x030;
    pub const REG_TPR:         usize = 0x080;
    pub const REG_EOI:         usize = 0x0B0;
    pub const REG_SPURIOUS:    usize = 0x0F0;
    pub const REG_ICR_LO:      usize = 0x300;
    pub const REG_ICR_HI:      usize = 0x310;
    pub const REG_TIMER_LVT:   usize = 0x320;
    pub const REG_THERMAL_LVT: usize = 0x330;
    pub const REG_PERF_LVT:    usize = 0x340;
    pub const REG_LINT0_LVT:   usize = 0x350;
    pub const REG_LINT1_LVT:   usize = 0x360;
    pub const REG_ERROR_LVT:   usize = 0x370;
    pub const REG_TIMER_ICR:   usize = 0x380;
    pub const REG_TIMER_CCR:   usize = 0x390;
    pub const REG_TIMER_DCR:   usize = 0x3E0;

    // ── SPURIOUS register bits ──────────────────────────────────────────────
    /// LAPIC software-enable bit in the Spurious Vector register.
    pub const SPURIOUS_ENABLE:   u32 = 1 << 8;
    /// Vector number used for spurious interrupts (conventionally 0xFF).
    pub const SPURIOUS_VECTOR:   u8  = 0xFF;

    // ── LVT mask bit ───────────────────────────────────────────────────────
    /// Set this bit in any LVT entry to mask (disable) the interrupt.
    pub const LVT_MASKED: u32 = 1 << 16;

    // ── ICR delivery mode bits ──────────────────────────────────────────────
    pub const ICR_DELIVERY_FIXED:   u32 = 0 << 8;
    pub const ICR_DELIVERY_INIT:    u32 = 5 << 8;
    pub const ICR_DELIVERY_SIPI:    u32 = 6 << 8;
    pub const ICR_LEVEL_ASSERT:     u32 = 1 << 14;
    pub const ICR_LEVEL_DEASSERT:   u32 = 0 << 14;
    pub const ICR_TRIGGER_LEVEL:    u32 = 1 << 15;
    pub const ICR_DELIVERY_PENDING: u32 = 1 << 12;

    // ── AP trampoline ───────────────────────────────────────────────────────
    /// Physical address where the 16-bit AP trampoline code is copied.
    /// Must be in the first MiB and page-aligned.  The SIPI vector is
    /// `TRAMPOLINE_PHYS >> 12`.
    pub const TRAMPOLINE_PHYS: u64 = 0x8000;
}

// ── I/O APIC ──────────────────────────────────────────────────────────────────

pub mod ioapic {
    /// Default MMIO base for I/O APIC 0.  May differ on multi-socket systems;
    /// always prefer the value from ACPI MADT if available.
    pub const IOAPIC0_PHYS: u64 = 0xFEC0_0000;

    /// IOREGSEL register offset (index register).
    pub const REG_SELECT: usize = 0x00;
    /// IOWIN register offset (data window).
    pub const REG_WINDOW: usize = 0x10;

    /// IOAPICID register index.
    pub const IDX_ID:      u8 = 0x00;
    /// IOAPICVER register index.
    pub const IDX_VER:     u8 = 0x01;
    /// Base index for redirection table entries (each entry = 2 × 32-bit regs).
    pub const IDX_REDTBL:  u8 = 0x10;
}

// ── Legacy VGA text buffer ─────────────────────────────────────────────────────

pub mod vga {
    /// Physical address of the VGA text-mode framebuffer (80×25 characters).
    /// Only valid when a VBE/UEFI GOP framebuffer is NOT in use.  Under UEFI
    /// the GOP framebuffer supersedes this.
    pub const TEXT_BUFFER_PHYS: u64 = 0x000B_8000;
    pub const COLS: usize = 80;
    pub const ROWS: usize = 25;
    /// Bytes per character cell (character + attribute byte).
    pub const BYTES_PER_CELL: usize = 2;
    pub const BUFFER_SIZE: usize = COLS * ROWS * BYTES_PER_CELL;
}

// ── GDT selector layout ────────────────────────────────────────────────────────

pub mod gdt_layout {
    // Segment selectors used in the GDT.  These must match the entries
    // actually installed by gdt.rs.
    pub const NULL_SEL:        u16 = 0x00;
    pub const KERNEL_CODE_SEL: u16 = 0x08;
    pub const KERNEL_DATA_SEL: u16 = 0x10;
    pub const USER_DATA_SEL:   u16 = 0x1B; // RPL 3
    pub const USER_CODE_SEL:   u16 = 0x23; // RPL 3
    pub const TSS_SEL:         u16 = 0x28; // TSS (two slots)
}

// ── AP trampoline shared-memory slot offsets ───────────────────────────────────
//
// These offsets are added to `apic::TRAMPOLINE_PHYS` to find each slot.
// They must match the layout documented in apic.rs and written by gdt.rs.

pub mod trampoline {
    /// Offset of the 10-byte GdtPointer (limit:u16 + base:u64) within
    /// the trampoline page.  Written by `gdt::gdt_init()`.
    pub const GDT_PTR_OFFSET:   usize = 0xFD0; // absolute VA 0x8FD0
    /// Offset of the AP kernel RSP top pointer (8 bytes).
    /// Written by `gdt::write_trampoline_kstack()`.
    pub const KSTACK_OFFSET:    usize = 0xFE8; // absolute VA 0x8FE8
    /// Offset of the PML4 physical address (4 bytes).
    /// Written by paging initialisation.
    pub const PML4_OFFSET:      usize = 0xFF0; // absolute VA 0x8FF0
    /// Offset of the logical cpu_id (4 bytes).
    /// Written by `apic::start_ap()` before each SIPI.
    pub const CPU_ID_OFFSET:    usize = 0xFF8; // absolute VA 0x8FF8
}
