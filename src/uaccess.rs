//! Safe wrappers for copying data between kernel and userspace.
//!
//! ## Address validation
//! Every function rejects pointers that:
//!   - are null / zero
//!   - point into or overlap the kernel half
//!   - wrap around the address space (base + len overflows usize)
//!   - span pages that are not currently mapped in the process's page table
//!
//! The page-presence check prevents kernel-mode page faults (which would panic
//! rather than return EFAULT) when userspace passes a valid but unmapped VA.
//! Without hardware SMAP + an __ex_table fixup, this walk is the safest option.

use core::slice;
use crate::arch::{Arch, api::Paging};

pub const USER_SPACE_END: usize = 0x0000_8000_0000_0000;

const PAGE_SIZE: usize = 4096;

#[inline]
fn user_range_valid(va: usize, len: usize) -> bool {
    if va == 0 || len == 0 { return false; }
    match va.checked_add(len) {
        Some(end) => end <= USER_SPACE_END,
        None      => false,
    }
}

/// Walk the current process's page table and confirm that every page in
/// [va, va+len) is mapped.  Returns false if any page is absent.
fn pages_mapped(va: usize, len: usize) -> bool {
    let cr3 = crate::proc::scheduler::with_proc(
        crate::proc::scheduler::current_pid(), |p| p.user_satp
    ).unwrap_or(0);
    if cr3 == 0 { return false; }

    let first_page = va & !(PAGE_SIZE - 1);
    let last_page  = (va + len - 1) & !(PAGE_SIZE - 1);
    let mut page = first_page;
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

/// Return `true` iff [va, va+len) is entirely within user space.
/// Public alias used by futex, signal, and syscall stubs.
#[inline]
pub fn validate_user_ptr(va: usize, len: usize) -> bool {
    user_range_valid(va, len)
}

/// Copy `src_va..src_va+dst.len()` from userspace into `dst`.
/// Returns `Err(())` if the source range is invalid or contains unmapped pages.
pub fn copy_from_user(dst: &mut [u8], src_va: usize) -> Result<(), ()> {
    if !user_range_valid(src_va, dst.len()) { return Err(()); }
    if !pages_mapped(src_va, dst.len())     { return Err(()); }
    let src = unsafe { slice::from_raw_parts(src_va as *const u8, dst.len()) };
    dst.copy_from_slice(src);
    Ok(())
}

/// Copy `src` into userspace at `dst_va..dst_va+src.len()`.
/// Returns `false` if the destination range is invalid or contains unmapped pages.
pub fn copy_to_user(dst_va: usize, src: &[u8]) -> bool {
    if !user_range_valid(dst_va, src.len()) { return false; }
    if !pages_mapped(dst_va, src.len())     { return false; }
    let dst = unsafe { slice::from_raw_parts_mut(dst_va as *mut u8, src.len()) };
    dst.copy_from_slice(src);
    true
}

/// Read a NUL-terminated path string from a user pointer.
/// Returns `None` if the pointer is invalid, not valid UTF-8,
/// or longer than PATH_MAX (4095 chars + NUL terminator).
pub fn read_path(ptr: *const u8) -> Option<alloc::string::String> {
    if ptr.is_null() { return None; }
    let base = ptr as usize;
    if !user_range_valid(base, 1) { return None; }
    let mut len = 0usize;
    loop {
        if len >= 4096 { return None; } // enforce POSIX PATH_MAX (4095 chars + NUL)
        if !user_range_valid(base, len + 1) { return None; }
        // Check the page containing ptr+len is mapped before dereferencing.
        if !pages_mapped(base + len, 1)     { return None; }
        if unsafe { *ptr.add(len) } == 0 { break; }
        len += 1;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(bytes).ok().map(alloc::string::String::from)
}
