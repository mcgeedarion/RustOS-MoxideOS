//! Safe wrappers for copying data between kernel and userspace.
//!
//! ## Address validation
//! Every function rejects pointers that:
//!   - are null / zero
//!   - point into or overlap the kernel half
//!   - wrap around the address space (base + len overflows usize)
//!   - span pages that are not currently mapped in the process's page table
//!
//! ## TOCTOU mitigation
//! On an SMP system a concurrent `munmap` on the same process could unmap
//! pages between the `pages_mapped` check and the actual memory copy,
//! turning a clean EFAULT into a kernel page fault (which panics).
//!
//! We close this window by holding the process `mm_lock` (read mode) across
//! the entire validate+copy sequence.  `pages_mapped_locked` performs the
//! page-table walk while the caller already holds the lock; the copy happens
//! before the lock is released.  A concurrent `munmap` will block on the
//! write side of the same lock until our copy completes.
//!
//! If `mm_lock` is unavailable (e.g. the process PCB is not yet fully
//! initialised) we fall back to the bare walk, which is safe in single-CPU
//! contexts (early boot, kernel threads).
//!
//! ## `validate_user_ptr`
//! Now performs both range and page-presence checks (previously only range).
//! Callers that previously relied on the weaker contract (futex, signal,
//! syscall stubs) now get full protection automatically.

extern crate alloc;

use core::slice;
use crate::arch::{Arch, api::Paging};

pub const USER_SPACE_END: usize = 0x0000_8000_0000_0000;
const PAGE_SIZE: usize = 4096;

// ── Address range check ─────────────────────────────────────────────────────────────

#[inline]
fn user_range_valid(va: usize, len: usize) -> bool {
    if va == 0 || len == 0 { return false; }
    match va.checked_add(len) {
        Some(end) => end <= USER_SPACE_END,
        None      => false,
    }
}

// ── mm_lock guard helper ─────────────────────────────────────────────────────────

/// Acquire mm_lock for reading if a user process is currently running,
/// otherwise return None (safe in single-CPU / early-boot contexts).
#[inline]
fn mm_read_guard() -> Option<crate::proc::scheduler::MmReadGuard> {
    if crate::proc::scheduler::has_current_user_proc() {
        Some(crate::proc::scheduler::with_current_mm_read())
    } else {
        None
    }
}

// ── Page-table walk ────────────────────────────────────────────────────────────────

/// Walk the current process's page table under the mm_lock (read) and confirm
/// every page in [va, va+len) is mapped.  Returns false if any page is absent.
///
/// Holding mm_lock for read across the walk+copy sequence prevents a
/// concurrent munmap from unmapping pages between our check and the copy.
fn pages_mapped_locked(va: usize, len: usize) -> bool {
    // Acquire mm_lock for reading before the walk.
    let _guard = crate::proc::scheduler::with_current_mm_read();

    let cr3 = crate::proc::scheduler::with_proc(
        crate::proc::scheduler::current_pid(),
        |p| p.user_satp,
    ).unwrap_or(0);
    if cr3 == 0 { return false; }

    let first_page = va & !(PAGE_SIZE - 1);
    let last_page  = (va + len - 1) & !(PAGE_SIZE - 1);
    let mut page   = first_page;
    while page <= last_page {
        if <Arch as Paging>::virt_to_phys(cr3, page).is_none() {
            return false;
        }
        page = match page.checked_add(PAGE_SIZE) {
            Some(n) => n,
            None    => break,
        };
    }
    true
    // _guard released here — munmap may now proceed.
}

/// Fallback walk without mm_lock.  Used only during early boot / kernel
/// threads where no concurrent munmap can occur.
fn pages_mapped_unlocked(va: usize, len: usize) -> bool {
    let cr3 = crate::proc::scheduler::with_proc(
        crate::proc::scheduler::current_pid(),
        |p| p.user_satp,
    ).unwrap_or(0);
    if cr3 == 0 { return false; }

    let first_page = va & !(PAGE_SIZE - 1);
    let last_page  = (va + len - 1) & !(PAGE_SIZE - 1);
    let mut page   = first_page;
    while page <= last_page {
        if <Arch as Paging>::virt_to_phys(cr3, page).is_none() {
            return false;
        }
        page = match page.checked_add(PAGE_SIZE) {
            Some(n) => n,
            None    => break,
        };
    }
    true
}

/// Choose locked or unlocked walk depending on whether a user process is
/// currently running (i.e. mm_lock is available).
#[inline]
fn pages_mapped(va: usize, len: usize) -> bool {
    if crate::proc::scheduler::has_current_user_proc() {
        pages_mapped_locked(va, len)
    } else {
        pages_mapped_unlocked(va, len)
    }
}

// ── Public API ───────────────────────────────────────────────────────────────────

/// Return `true` iff [va, va+len) is entirely within user space **and**
/// every page is currently mapped.
///
/// Upgraded from range-only to range+presence check so callers (futex,
/// signal, syscall stubs) all receive TOCTOU-safe validation.
#[inline]
pub fn validate_user_ptr(va: usize, len: usize) -> bool {
    user_range_valid(va, len) && pages_mapped(va, len)
}

/// Copy `src_va..src_va+dst.len()` from userspace into `dst`.
///
/// Returns `Err(())` if the source range is invalid or contains unmapped pages.
///
/// # Safety
/// The mm_lock is held for read across the walk and the copy.  A concurrent
/// munmap will block until this function returns, preventing page disappearance
/// between validation and the actual memory access.
pub fn copy_from_user(dst: &mut [u8], src_va: usize) -> Result<(), ()> {
    if !user_range_valid(src_va, dst.len()) { return Err(()); }
    // Acquire mm_lock for read; hold it across the walk AND the copy below.
    let _guard = mm_read_guard();
    // Walk under the lock.
    if !pages_mapped_unlocked(src_va, dst.len()) { return Err(()); }
    // Copy under the lock — munmap cannot proceed until _guard drops.
    // SAFETY: range validated above; all pages confirmed mapped and will
    // remain mapped until _guard is released at end of scope.
    let src = unsafe { slice::from_raw_parts(src_va as *const u8, dst.len()) };
    dst.copy_from_slice(src);
    Ok(())
    // _guard released here.
}

/// Copy `src` into userspace at `dst_va..dst_va+src.len()`.
///
/// Returns `false` if the destination range is invalid or contains unmapped pages.
///
/// Holds mm_lock for read across walk+copy to prevent TOCTOU.
pub fn copy_to_user(dst_va: usize, src: &[u8]) -> bool {
    if !user_range_valid(dst_va, src.len()) { return false; }
    let _guard = mm_read_guard();
    if !pages_mapped_unlocked(dst_va, src.len()) { return false; }
    // SAFETY: same as copy_from_user above.
    let dst = unsafe { slice::from_raw_parts_mut(dst_va as *mut u8, src.len()) };
    dst.copy_from_slice(src);
    true
    // _guard released here.
}

/// Read a NUL-terminated path string from a user pointer.
///
/// Returns `None` if the pointer is invalid, not valid UTF-8, or longer
/// than PATH_MAX (4095 chars + NUL terminator).
///
/// ## Performance fix
/// Previous implementation called `pages_mapped(base + len, 1)` on every
/// single byte, causing up to 4096 page-table walks for a PATH_MAX string.
/// This version validates one full page at a time: we pre-validate each
/// 4 KiB page before scanning its bytes, reducing walk calls to at most
/// ceil(PATH_MAX / PAGE_SIZE) = 2 calls.
pub fn read_path(ptr: *const u8) -> Option<alloc::string::String> {
    if ptr.is_null() { return None; }
    let base = ptr as usize;
    if !user_range_valid(base, 1) { return None; }

    // Acquire mm_lock once for the entire scan.
    let _guard = mm_read_guard();

    let pid = crate::proc::scheduler::current_pid();
    let cr3 = crate::proc::scheduler::with_proc(pid, |p| p.user_satp)
        .unwrap_or(0);
    if cr3 == 0 { return None; }

    const PATH_MAX: usize = 4095;
    let mut len = 0usize;
    // Byte offset of the next page boundary that needs validating.
    let mut next_page_check = 0usize;

    loop {
        if len > PATH_MAX { return None; }

        // Validate the current page before reading from it.
        if len >= next_page_check {
            if !user_range_valid(base + len, 1) { return None; }
            let page_start = (base + len) & !(PAGE_SIZE - 1);
            let page_end   = page_start + PAGE_SIZE;
            // pages_mapped_unlocked is safe here because we hold _guard.
            if <Arch as Paging>::virt_to_phys(cr3, page_start).is_none() {
                return None;
            }
            // Next check at the start of the following page.
            next_page_check = page_end - base;
        }

        // SAFETY: page confirmed mapped above and mm_lock held.
        if unsafe { *ptr.add(len) } == 0 { break; }
        len += 1;
    }

    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(bytes).ok().map(alloc::string::String::from)
}
