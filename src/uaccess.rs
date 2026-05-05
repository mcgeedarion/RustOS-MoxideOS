//! Safe wrappers for copying data between kernel and userspace.
//!
//! ## Address validation
//! On x86-64 with a higher-half kernel the user address space occupies
//! the lower canonical half: [0x0000_0000_0000_0001, USER_SPACE_END).
//! USER_SPACE_END is the first non-canonical / kernel address.
//!
//! Every function here rejects pointers that:
//!   - are null / zero
//!   - point into or overlap the kernel half
//!   - wrap around the address space (base + len overflows usize)

use core::slice;

/// First address that belongs to the kernel (upper canonical half).
/// On x86-64 Sv48: 0x0000_8000_0000_0000.
pub const USER_SPACE_END: usize = 0x0000_8000_0000_0000;

/// Return `true` iff the range [va, va+len) lies entirely within
/// the user address space and does not wrap.
#[inline]
fn user_range_valid(va: usize, len: usize) -> bool {
    if va == 0 || len == 0 { return false; }
    let end = match va.checked_add(len) {
        Some(e) => e,
        None    => return false,
    };
    end <= USER_SPACE_END
}

/// Public alias for user_range_valid.
/// Called by sync::futex, proc::signal, and syscall stubs that need a
/// quick "is this pointer in user space?" check before a raw dereference.
#[inline]
pub fn validate_user_ptr(va: usize, len: usize) -> bool {
    user_range_valid(va, len)
}

/// Copy `src_va..src_va+dst.len()` from userspace into `dst`.
/// Returns `false` if the source range is invalid.
pub fn copy_from_user(dst: &mut [u8], src_va: usize) -> bool {
    if !user_range_valid(src_va, dst.len()) { return false; }
    let src = unsafe { slice::from_raw_parts(src_va as *const u8, dst.len()) };
    dst.copy_from_slice(src);
    true
}

/// Copy `src` into userspace at `dst_va..dst_va+src.len()`.
/// Returns `false` if the destination range is invalid.
pub fn copy_to_user(dst_va: usize, src: &[u8]) -> bool {
    if !user_range_valid(dst_va, src.len()) { return false; }
    let dst = unsafe { slice::from_raw_parts_mut(dst_va as *mut u8, src.len()) };
    dst.copy_from_slice(src);
    true
}

/// Read a NUL-terminated path string from a user pointer.
/// Returns `None` if the pointer is invalid, the string is not valid
/// UTF-8, or the length exceeds 4096 bytes (PATH_MAX).
pub fn read_path(ptr: *const u8) -> Option<alloc::string::String> {
    if ptr.is_null() { return None; }
    let base = ptr as usize;
    if !user_range_valid(base, 1) { return None; }

    let mut len = 0usize;
    loop {
        if len > 4096 { return None; }
        if !user_range_valid(base, len + 1) { return None; }
        if unsafe { *ptr.add(len) } == 0 { break; }
        len += 1;
    }

    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(bytes).ok().map(alloc::string::String::from)
}
