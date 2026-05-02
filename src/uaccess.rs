//! Safe wrappers for copying data between kernel and userspace.
//!
//! In a production kernel these would validate that user pointers
//! actually lie in the user address range.  For now we trust them.

use core::slice;

pub fn copy_from_user(dst: &mut [u8], src_va: usize) -> bool {
    if src_va == 0 { return false; }
    let src = unsafe { slice::from_raw_parts(src_va as *const u8, dst.len()) };
    dst.copy_from_slice(src);
    true
}

pub fn copy_to_user(dst_va: usize, src: &[u8]) -> bool {
    if dst_va == 0 { return false; }
    let dst = unsafe { slice::from_raw_parts_mut(dst_va as *mut u8, src.len()) };
    dst.copy_from_slice(src);
    true
}

pub fn read_path(ptr: *const u8) -> Option<alloc::string::String> {
    if ptr.is_null() { return None; }
    let mut len = 0usize;
    unsafe { while *ptr.add(len) != 0 { len += 1; if len > 4096 { return None; } } }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(bytes).ok().map(alloc::string::String::from)
}
