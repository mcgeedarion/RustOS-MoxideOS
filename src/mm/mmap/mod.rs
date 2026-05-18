//! Virtual Memory Area (VMA) tracker — mmap / munmap / mprotect / brk.
//!
//! ## Module layout
//!
//!   mod.rs        — types (VmaKind, Vma), constants, pub re-exports
//!   mm_lock.rs    — with_mm_write, check_rlimit_as
//!   vma.rs        — insert/remove/find/clone/query VMAs
//!   mapping.rs    — sys_mmap, mmap_phys, remove_vma_inner
//!   fault.rs      — free_address_space (teardown)
//!   protection.rs — sys_mprotect, prot_to_flags
//!   anonymous.rs  — alloc_user_stack, heap helpers
//!   syscalls.rs   — sys_munmap, sys_brk, set_brk_base

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;

#[derive(Clone, Debug)]
pub enum VmaKind {
    Anonymous,
    /// fd-backed file mapping: (fd, file_offset)
    FileBacked(usize, u64),
    /// Physical memory mapping (framebuffer, MMIO)
    PhysMap(u64),
    Stack,
    Heap,
}

#[derive(Clone, Debug)]
pub struct Vma {
    pub start:       usize,
    pub end:         usize,
    pub prot:        u32,
    pub flags:       u32,
    pub kind:        VmaKind,
    pub file_offset: u64,
    pub locked:      bool,
}

impl Vma {
    pub fn is_heap(&self)  -> bool { matches!(self.kind, VmaKind::Heap) }
    pub fn is_stack(&self) -> bool { matches!(self.kind, VmaKind::Stack) }
    pub fn contains(&self, addr: usize) -> bool { self.start <= addr && addr < self.end }
}

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;

pub const MAP_SHARED:  u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED:   u32 = 0x10;
pub const MAP_ANON:    u32 = 0x20;
/// Stack segment grows downward.
pub const MAP_GROWSDOWN:   u32 = 0x0100;
pub const PAGE:            usize = 4096;

pub mod mm_lock;
pub mod vma;
pub mod mapping;
pub mod fault;
pub mod protection;
pub mod anonymous;
pub mod syscalls;

pub use mm_lock::{with_mm_write, check_rlimit_as};
pub use vma::{insert_vma, remove_vma, find_vma, clone_vmas, clear_vmas_internal,
              with_vmas, vma_total_kb, heap_kb, stack_kb, current_brk, page_align_up};
pub use mapping::sys_mmap;
pub use anonymous::{alloc_user_stack, clear_vmas_pub};
pub use fault::free_address_space;
pub use protection::sys_mprotect;
pub use syscalls::{sys_munmap, sys_brk, set_brk_base, set_brk_base_compute};