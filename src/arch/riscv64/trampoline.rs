//! User-mode trampoline page for RISC-V.
//!
//! The trampoline is a single physical page mapped into every process's
//! address space at a fixed high virtual address. It contains the
//! supervisor-mode entry/exit stubs that must remain mapped while the
//! CPU switches between U-mode and S-mode.
//!
//! ## Status
//! Stub — full implementation pending.

/// Virtual address at which the trampoline page is mapped in every
/// user process's address space. Must be page-aligned.
pub const TRAMPOLINE_VADDR: usize = 0xFFFF_FFFF_FFFF_F000;

/// Placeholder: initialise the trampoline page.
/// In the full implementation this will copy the trampoline assembly
/// into a dedicated physical page and map it read+execute into the
/// kernel page table so every `satp` switch preserves the mapping.
pub fn trampoline_init() {
    // TODO: map trampoline page
}
