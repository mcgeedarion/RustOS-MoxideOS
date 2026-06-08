//! KASAN-lite — minimal heap shadow poisoning/checking for debug builds.
//!
//! One shadow byte covers eight bytes of heap.  The encoding is intentionally
//! simple:
//!
//!   0x00 => accessible
//!   0xFA => redzone / canary bytes
//!   0xFF => freed / poisoned
//!
//! This module is best-effort and intended for allocator-integrated checks
//! rather than compiler-inserted instrumentation.

use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::mm::pmm;

const SHADOW_SCALE: usize = 8;
pub const SHADOW_ACCESSIBLE: u8 = 0x00;
pub const SHADOW_REDZONE: u8 = 0xFA;
pub const SHADOW_POISONED: u8 = 0xFF;

static SHADOW_BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static SHADOW_SIZE: AtomicUsize = AtomicUsize::new(0);
static HEAP_BASE: AtomicUsize = AtomicUsize::new(0);
static HEAP_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Initialise the shadow region for the heap virtual address window.
pub fn init(heap_base: usize, heap_size: usize) {
    if heap_base == 0 || heap_size == 0 {
        return;
    }

    let shadow_bytes = (heap_size + SHADOW_SCALE - 1) / SHADOW_SCALE;
    let shadow_pages = (shadow_bytes + pmm::PAGE_SIZE - 1) / pmm::PAGE_SIZE;

    if let Some(base_pa) = pmm::alloc_pages_contig(shadow_pages) {
        unsafe {
            ptr::write_bytes(
                base_pa as *mut u8,
                SHADOW_ACCESSIBLE,
                shadow_pages * pmm::PAGE_SIZE,
            );
        }
        HEAP_BASE.store(heap_base, Ordering::Release);
        HEAP_SIZE.store(heap_size, Ordering::Release);
        SHADOW_BASE.store(base_pa as *mut u8, Ordering::Release);
        SHADOW_SIZE.store(shadow_pages * pmm::PAGE_SIZE, Ordering::Release);
    } else {
        log::warn!("kasan: failed to allocate shadow memory");
    }
}

#[inline]
fn shadow_addr(addr: usize) -> Option<*mut u8> {
    let heap_base = HEAP_BASE.load(Ordering::Acquire);
    let heap_size = HEAP_SIZE.load(Ordering::Relaxed);
    let shadow_base = SHADOW_BASE.load(Ordering::Acquire);
    if shadow_base.is_null() || heap_base == 0 || addr < heap_base || addr >= heap_base + heap_size
    {
        return None;
    }
    let off = (addr - heap_base) / SHADOW_SCALE;
    if off >= SHADOW_SIZE.load(Ordering::Relaxed) {
        return None;
    }
    Some(unsafe { shadow_base.add(off) })
}

fn mark(addr: usize, size: usize, value: u8) {
    if size == 0 {
        return;
    }
    let words = (size + SHADOW_SCALE - 1) / SHADOW_SCALE;
    for i in 0..words {
        if let Some(s) = shadow_addr(addr + i * SHADOW_SCALE) {
            unsafe {
                s.write(value);
            }
        }
    }
}

#[inline]
pub fn mark_accessible(addr: usize, size: usize) {
    mark(addr, size, SHADOW_ACCESSIBLE);
}

#[inline]
pub fn mark_redzone(addr: usize, size: usize) {
    mark(addr, size, SHADOW_REDZONE);
}

#[inline]
pub fn mark_poisoned(addr: usize, size: usize) {
    mark(addr, size, SHADOW_POISONED);
}

/// Explicit access check for allocator-managed pointers.
#[inline]
pub fn check_access(addr: usize, size: usize) {
    if size == 0 {
        return;
    }
    let words = (size + SHADOW_SCALE - 1) / SHADOW_SCALE;
    for i in 0..words {
        if let Some(s) = shadow_addr(addr + i * SHADOW_SCALE) {
            let tag = unsafe { s.read() };
            if tag != SHADOW_ACCESSIBLE {
                panic!(
                    "kasan: invalid heap access at {:#x}+{} shadow={:#04x}",
                    addr,
                    i * SHADOW_SCALE,
                    tag
                );
            }
        }
    }
}
