//! Virtual memory area management and mmap syscall family.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;

pub mod vma;
pub mod mm_lock;
pub mod mapping;
pub mod anonymous;
pub mod fault;
pub mod protection;
pub mod syscalls;

pub use vma::{insert_vma, remove_vma, find_vma, clone_vmas, clear_vmas_pub,
              with_vmas, vma_total_kb, heap_kb, stack_kb, current_brk,
              page_align_up};
pub use mm_lock::with_mm_write;
pub use mapping::sys_mmap;
pub use anonymous::alloc_user_stack;
pub use fault::free_address_space;
pub use protection::sys_mprotect;
pub use syscalls::{sys_munmap, sys_brk, set_brk_base, set_brk_base_compute};

#[derive(Clone, Debug)]
pub enum VmaKind {
    Anonymous,
    /// fd-backed file mapping: (fd, file_offset)
    FileBacked { fd: usize, file_offset: u64 },
    /// Stack segment (grows downward)
    Stack,
    /// Heap segment
    Heap,
    /// Shared memory
    Shared { key: u64 },
}

#[derive(Clone, Debug)]
pub struct Vma {
    pub start:  usize,
    pub end:    usize,
    pub prot:   u32,
    pub flags:  u32,
    pub kind:   VmaKind,
    pub offset: u64,
}

impl Vma {
    pub fn len(&self) -> usize { self.end - self.start }
    pub fn contains(&self, addr: usize) -> bool { addr >= self.start && addr < self.end }
    pub fn is_writable(&self) -> bool { self.prot & PROT_WRITE != 0 }
    pub fn is_executable(&self) -> bool { self.prot & PROT_EXEC != 0 }
}

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;

pub const MAP_SHARED:          u32 = 0x01;
pub const MAP_PRIVATE:         u32 = 0x02;
pub const MAP_FIXED:           u32 = 0x10;
pub const MAP_ANON:            u32 = 0x20;
pub const MAP_GROWSDOWN:       u32 = 0x0100;

pub const PAGE: usize = 4096;
