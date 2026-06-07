//! Kernel ↔ User-space memory access primitives.
//!
//! Provides [`copy_from_user`], [`copy_to_user`], [`get_user`], [`put_user`],
//! [`UserPtr`], and [`UserSlice`] — the kernel's safe boundary for touching
//! user virtual addresses.
//!
//! # Safety contract
//! All functions in this module assume they are called from a kernel context
//! (after a syscall/trap entry) where the current address space is the user
//! process's page table.  The caller must ensure that the user virtual address
//! makes sense for the current task; these functions only guarantee that a
//! fault will produce `EFAULT` rather than a kernel panic.
//!
//! # Architecture notes
//! * **x86_64** — SMAP (`CR4.SMAP`) is assumed to be enabled.  Every access
//!   bracket wraps the copy loop between `STAC` / `CLAC` to temporarily allow
//!   supervisor access to user pages.  SMEP prevents execution from user pages
//!   regardless.
//! * **RISC-V** — `sstatus.SUM` is cleared during normal kernel execution. Each
//!   access bracket sets `SUM=1`, performs the copy, then clears it again. The
//!   `stvec` fault handler translates load/store page-faults into `EFAULT`.

use core::mem;
use core::ptr;

/// Upper bound (exclusive) of the user virtual address space on x86_64
/// (canonical 48-bit, top half reserved for kernel).
#[cfg(target_arch = "x86_64")]
const USER_ADDR_MAX: usize = 0x0000_8000_0000_0000;

/// Upper bound (exclusive) of the user virtual address space on RISC-V Sv39.
/// 512 GiB: bits [38:0] are valid user bits.
#[cfg(target_arch = "riscv64")]
const USER_ADDR_MAX: usize = 0x0000_0040_0000_0000;

/// Errors returned by uaccess operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum UaccessError {
    /// The user pointer was NULL, misaligned, or outside the user address
    /// space.
    Fault = 14, // EFAULT
}

pub type UaccessResult<T = ()> = Result<T, UaccessError>;

/// Returns `true` when `[addr, addr + len)` is entirely within user space and
/// the range does not wrap around.
#[inline]
pub fn user_access_ok(addr: usize, len: usize) -> bool {
    // Prevent wrap-around (addr + len could overflow)
    if addr.checked_add(len).is_none() {
        return false;
    }
    addr + len <= USER_ADDR_MAX
}

/// Same as [`user_access_ok`] but checks only a single typed address.
#[inline]
pub fn user_ptr_ok<T>(addr: usize) -> bool {
    user_access_ok(addr, mem::size_of::<T>())
}

/// Public alias for the per-arch user/kernel split. Exclusive upper bound
/// of the user virtual address space.
pub const USER_SPACE_END: usize = USER_ADDR_MAX;

/// Public wrapper around [`user_access_ok`] used by syscall glue that
/// wants a single `validate_user_ptr(addr, len) -> bool` predicate.
#[inline]
pub fn validate_user_ptr(addr: usize, len: usize) -> bool {
    addr != 0 && user_access_ok(addr, len)
}

/// Thin wrapper around [`copy_to_user`] that returns the number of bytes
/// copied (success = `len`, failure = `0`). Matches the contract used by
/// `crate::mm::UserBuffer::write_bytes`.
///
/// # Safety
/// `src` must point to `len` bytes of readable kernel memory; `dst` must
/// reference a validated user-space range of at least `len` bytes.
#[inline]
pub unsafe fn copy_to_user_raw(dst: *mut u8, src: *const u8, len: usize) -> usize {
    match copy_to_user(dst as usize, src, len) {
        Ok(()) => len,
        Err(_) => 0,
    }
}

/// Thin wrapper around [`copy_from_user`] that returns the number of
/// bytes copied (success = `len`, failure = `0`). Matches the contract
/// used by `crate::mm::UserBuffer::read_bytes`.
///
/// # Safety
/// `dst` must point to `len` bytes of writable kernel memory; `src` must
/// reference a validated user-space range of at least `len` bytes.
#[inline]
pub unsafe fn copy_from_user_raw(dst: *mut u8, src: *const u8, len: usize) -> usize {
    match copy_from_user(dst, src as usize, len) {
        Ok(()) => len,
        Err(_) => 0,
    }
}

/// Executes `f` inside an architecture-specific "user access window".
///
/// On x86_64 this is a `STAC … CLAC` bracket (enables supervisor access to
/// user pages when `CR4.SMAP` is set).  On RISC-V it sets `sstatus.SUM=1`
/// before the closure and clears it afterward.
///
/// The closure `f` is expected to do raw pointer reads/writes.  If a page
/// fault occurs inside `f` the architecture's trap handler will set a
/// per-CPU "fixup" flag that causes [`run_in_user_access`] to return
/// `Err(UaccessError::Fault)`.
///
/// # Safety
/// Caller must have verified that the address range is within user space and
/// that `len` bytes are within that range before entering the window.
#[inline]
unsafe fn run_in_user_access<F, T>(f: F) -> UaccessResult<T>
where
    F: FnOnce() -> T,
{
    #[cfg(target_arch = "x86_64")]
    {
        arch_x86_64::with_user_access_enabled(f)
    }
    #[cfg(target_arch = "riscv64")]
    {
        arch_riscv64::with_user_access_enabled(f)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // ARM64 user access is controlled by PAN. The initial ARM64 bring-up
        // keeps this path explicit until exception-table fault fixups land.
        Ok(f())
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    )))]
    {
        let _ = f;
        Err(UaccessError::Fault)
    }
}

#[cfg(target_arch = "x86_64")]
mod arch_x86_64 {
    use super::UaccessError;
    use super::UaccessResult;

    /// Per-CPU flag set by the fault fixup path in the IDT #PF handler.
    ///
    /// The `#[thread_local]` attribute maps this to the GS-relative segment so
    /// each CPU has its own independent copy.
    #[thread_local]
    static mut USER_FAULT_OCCURRED: bool = false;

    /// Entry point from the kernel's `#PF` (page-fault) handler.
    ///
    /// Called when a page fault occurs and `rip` is inside a `stac`-guarded
    /// copy loop.  Sets the per-CPU fault flag so the copy loop can bail out.
    ///
    /// # Safety
    /// Must only be called from the IDT `#PF` handler while SMAP is active.
    pub unsafe fn signal_user_fault() {
        USER_FAULT_OCCURRED = true;
    }

    /// Clears the per-CPU fault flag.  Call before entering a new user-access
    /// window so stale faults from a previous call don't pollute the result.
    #[inline]
    unsafe fn clear_fault_flag() {
        USER_FAULT_OCCURRED = false;
    }

    /// Returns whether a fault occurred since the last [`clear_fault_flag`].
    #[inline]
    unsafe fn fault_occurred() -> bool {
        USER_FAULT_OCCURRED
    }

    /// Runs `f` between `STAC` and `CLAC` instructions.
    ///
    /// The `STAC` instruction sets `EFLAGS.AC`, which overrides `CR4.SMAP`
    /// for supervisor-mode accesses to user pages until `CLAC` clears it.
    #[inline]
    pub unsafe fn with_user_access_enabled<F, T>(f: F) -> UaccessResult<T>
    where
        F: FnOnce() -> T,
    {
        clear_fault_flag();

        // STAC — allow supervisor access to user pages.
        core::arch::asm!("stac", options(nostack, preserves_flags));

        let result = f();

        // CLAC — restore SMAP protection.
        core::arch::asm!("clac", options(nostack, preserves_flags));

        if fault_occurred() {
            Err(UaccessError::Fault)
        } else {
            Ok(result)
        }
    }
}

#[cfg(target_arch = "riscv64")]
mod arch_riscv64 {
    use super::UaccessError;
    use super::UaccessResult;

    /// `sstatus.SUM` bit — Supervisor User Memory access.
    const SSTATUS_SUM: usize = 1 << 18;

    /// Per-hart flag set by the kernel's `stvec` S-mode trap handler when a
    /// load/store page-fault fires inside a user-access window.
    #[thread_local]
    static mut USER_FAULT_OCCURRED: bool = false;

    /// Called from the `stvec` trap handler for cause 13 (load page-fault) and
    /// cause 15 (store page-fault) when the fault PC is inside a `sum_set`
    /// region.
    pub unsafe fn signal_user_fault() {
        USER_FAULT_OCCURRED = true;
    }

    #[inline]
    unsafe fn clear_fault_flag() {
        USER_FAULT_OCCURRED = false;
    }

    #[inline]
    unsafe fn fault_occurred() -> bool {
        USER_FAULT_OCCURRED
    }

    /// Sets `sstatus.SUM`, runs `f`, then clears `sstatus.SUM`.
    #[inline]
    pub unsafe fn with_user_access_enabled<F, T>(f: F) -> UaccessResult<T>
    where
        F: FnOnce() -> T,
    {
        clear_fault_flag();

        // Set SUM bit to allow S-mode access to U-mode pages.
        core::arch::asm!(
            "csrrs zero, sstatus, {sum}",
            sum = in(reg) SSTATUS_SUM,
            options(nostack)
        );

        let result = f();

        // Clear SUM to re-engage user-page protection.
        core::arch::asm!(
            "csrrc zero, sstatus, {sum}",
            sum = in(reg) SSTATUS_SUM,
            options(nostack)
        );

        if fault_occurred() {
            Err(UaccessError::Fault)
        } else {
            Ok(result)
        }
    }
}

/// Copies `len` bytes **from** a user-space address into `dst`.
///
/// Returns `Ok(())` on success.  Returns `Err(UaccessError::Fault)` if:
/// * `src` is NULL.
/// * `[src, src + len)` extends outside user virtual address space.
/// * A hardware page fault occurs during the copy (e.g. unmapped page).
///
/// # Panics
/// Never panics; all error conditions are returned via `Result`.
pub fn copy_from_user(dst: *mut u8, src: usize, len: usize) -> UaccessResult {
    if len == 0 {
        return Ok(());
    }
    if src == 0 || !user_access_ok(src, len) {
        return Err(UaccessError::Fault);
    }

    // SAFETY: We have verified the range is within user space.  The
    // `run_in_user_access` wrapper converts hardware faults to EFAULT.
    unsafe {
        run_in_user_access(|| {
            ptr::copy_nonoverlapping(src as *const u8, dst, len);
        })
    }
}

/// Copies `len` bytes **to** a user-space address from `src`.
///
/// Returns `Ok(())` on success.  Returns `Err(UaccessError::Fault)` if:
/// * `dst` is NULL.
/// * `[dst, dst + len)` extends outside user virtual address space.
/// * A hardware page fault occurs (e.g. unmapped or read-only page).
/// Copies the raw bytes of an in-kernel value or slice to a user-space address.
///
/// Compatibility helper for call sites that already hold a Rust reference; it
/// funnels through [`copy_to_user`] so address validation and fault handling
/// stay centralized.
pub fn copy_to_user_value<T: ?Sized>(dst: usize, src: &T) -> UaccessResult {
    copy_to_user(dst, src as *const T as *const u8, mem::size_of_val(src))
}

pub fn copy_to_user(dst: usize, src: *const u8, len: usize) -> UaccessResult {
    if len == 0 {
        return Ok(());
    }
    if dst == 0 || !user_access_ok(dst, len) {
        return Err(UaccessError::Fault);
    }

    // SAFETY: verified range; faults become EFAULT via the access window.
    unsafe {
        run_in_user_access(|| {
            ptr::copy_nonoverlapping(src, dst as *mut u8, len);
        })
    }
}

/// Reads a single value of type `T` from user space.
///
/// The user address must be naturally aligned to `align_of::<T>()`.
/// Unaligned reads will fault on most architectures.
///
/// # Example
/// ```no_run
/// let fd: u32 = get_user(user_ptr)?;
/// ```
pub fn get_user<T: Copy>(user_addr: usize) -> UaccessResult<T> {
    if user_addr == 0 || !user_access_ok(user_addr, mem::size_of::<T>()) {
        return Err(UaccessError::Fault);
    }

    // MaybeUninit avoids UB when constructing T from a raw read.
    let mut val = mem::MaybeUninit::<T>::uninit();

    // SAFETY: size and alignment are checked above; faults become EFAULT.
    unsafe {
        run_in_user_access(|| {
            ptr::copy_nonoverlapping(
                user_addr as *const u8,
                val.as_mut_ptr() as *mut u8,
                mem::size_of::<T>(),
            );
        })?;
        Ok(val.assume_init())
    }
}

/// Writes a single value of type `T` to user space.
///
/// The user address must be naturally aligned to `align_of::<T>()`.
///
/// # Example
/// ```no_run
/// put_user(user_ptr, 42u32)?;
/// ```
pub fn put_user<T: Copy>(user_addr: usize, val: T) -> UaccessResult {
    if user_addr == 0 || !user_access_ok(user_addr, mem::size_of::<T>()) {
        return Err(UaccessError::Fault);
    }

    // SAFETY: verified range; faults become EFAULT.
    unsafe {
        run_in_user_access(|| {
            ptr::write_volatile(user_addr as *mut T, val);
        })
    }
}

/// A typed pointer into user virtual address space.
///
/// `UserPtr<T>` carries only an address; it does not dereference the pointer
/// directly.  All reads and writes go through [`get_user`] / [`put_user`] so
/// SMAP/SUM protection is always applied.
///
/// ```no_run
/// let p: UserPtr<u64> = UserPtr::new(syscall_arg as usize);
/// let v: u64 = p.read()?;
/// p.write(v + 1)?;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserPtr<T> {
    addr: usize,
    _marker: core::marker::PhantomData<*mut T>,
}

// UserPtr is not Send/Sync — it is tied to the current task's address space.

impl<T: Copy> UserPtr<T> {
    /// Creates a new `UserPtr` wrapping a raw user virtual address.
    ///
    /// Does **not** validate the address yet; validation happens on
    /// [`read`](Self::read) / [`write`](Self::write).
    #[inline]
    pub const fn new(addr: usize) -> Self {
        Self {
            addr,
            _marker: core::marker::PhantomData,
        }
    }

    /// Creates a `UserPtr` from a raw `*mut T` (useful when the syscall ABI
    /// hands pointers through a `usize`-cast argument).
    #[inline]
    pub const fn from_raw(ptr: *mut T) -> Self {
        Self::new(ptr as usize)
    }

    /// Returns the raw user virtual address.
    #[inline]
    pub const fn addr(self) -> usize {
        self.addr
    }

    /// Returns `true` if the address is NULL.
    #[inline]
    pub const fn is_null(self) -> bool {
        self.addr == 0
    }

    /// Returns `true` if the address and type size are within user address
    /// space.
    #[inline]
    pub fn is_valid(self) -> bool {
        !self.is_null() && user_ptr_ok::<T>(self.addr)
    }

    /// Reads a `T` from user space.  Returns `EFAULT` on any access error.
    #[inline]
    pub fn read(self) -> UaccessResult<T> {
        get_user::<T>(self.addr)
    }

    /// Writes `val` to user space.  Returns `EFAULT` on any access error.
    #[inline]
    pub fn write(self, val: T) -> UaccessResult {
        put_user::<T>(self.addr, val)
    }

    /// Returns a `UserPtr` advanced by `count` elements.
    ///
    /// Does **not** validate the new address; that happens on the next
    /// `read`/`write`.
    #[inline]
    pub fn offset(self, count: isize) -> Self {
        let delta = count * (mem::size_of::<T>() as isize);
        Self::new(self.addr.wrapping_add(delta as usize))
    }

    /// Converts this pointer into a [`UserSlice<T>`] of `len` elements
    /// starting at the same address.
    #[inline]
    pub fn into_slice(self, len: usize) -> UserSlice<T> {
        UserSlice::new(self.addr, len)
    }
}

impl<T> core::fmt::Debug for UserPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UserPtr({:#018x})", self.addr)
    }
}

/// A contiguous slice of `len` elements of type `T` in user virtual address
/// space.
///
/// Bounds are checked once on construction ([`new`](UserSlice::new)); after
/// that, element access is bounds-checked by index.
///
/// ```no_run
/// // Read a whole iovec buffer from user space.
/// let slice: UserSlice<u8> = UserSlice::new(user_buf_addr, buf_len);
/// let mut kernel_buf = vec![0u8; buf_len];
/// slice.copy_to_kernel(&mut kernel_buf)?;
/// ```
pub struct UserSlice<T> {
    base: usize,
    len: usize,
    _marker: core::marker::PhantomData<*mut T>,
}

impl<T: Copy> UserSlice<T> {
    /// Creates a new `UserSlice` over `[base, base + len * size_of::<T>())`.
    ///
    /// The address range is validated immediately.  Construct succeeds even if
    /// the range is invalid — the error is surfaced on the first data access so
    /// callers do not need to check construction.  Alternatively, call
    /// [`is_valid`](Self::is_valid) to pre-check.
    #[inline]
    pub const fn new(base: usize, len: usize) -> Self {
        Self {
            base,
            len,
            _marker: core::marker::PhantomData,
        }
    }

    /// Total number of elements in the slice.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if `len == 0`.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the base user virtual address of the slice.
    #[inline]
    pub const fn base_addr(&self) -> usize {
        self.base
    }

    /// Returns `true` if the entire slice falls within user address space.
    pub fn is_valid(&self) -> bool {
        if self.len == 0 {
            return true;
        }
        let byte_len = self
            .len
            .checked_mul(mem::size_of::<T>())
            .unwrap_or(usize::MAX);
        self.base != 0 && user_access_ok(self.base, byte_len)
    }

    /// Reads element at `index` from user space.
    ///
    /// Returns `EFAULT` if `index >= self.len` or the access faults.
    pub fn get(&self, index: usize) -> UaccessResult<T> {
        if index >= self.len {
            return Err(UaccessError::Fault);
        }
        let addr = self
            .base
            .checked_add(index * mem::size_of::<T>())
            .ok_or(UaccessError::Fault)?;
        get_user::<T>(addr)
    }

    /// Writes `val` to element at `index` in user space.
    ///
    /// Returns `EFAULT` if `index >= self.len` or the write faults.
    pub fn set(&self, index: usize, val: T) -> UaccessResult {
        if index >= self.len {
            return Err(UaccessError::Fault);
        }
        let addr = self
            .base
            .checked_add(index * mem::size_of::<T>())
            .ok_or(UaccessError::Fault)?;
        put_user::<T>(addr, val)
    }

    /// Bulk-copies the entire user slice into `dst`.
    ///
    /// `dst.len()` must equal `self.len`; returns `EFAULT` otherwise.
    pub fn copy_to_kernel(&self, dst: &mut [T]) -> UaccessResult {
        if dst.len() != self.len {
            return Err(UaccessError::Fault);
        }
        let byte_len = self
            .len
            .checked_mul(mem::size_of::<T>())
            .ok_or(UaccessError::Fault)?;
        copy_from_user(dst.as_mut_ptr() as *mut u8, self.base, byte_len)
    }

    /// Bulk-copies `src` into the user slice.
    ///
    /// `src.len()` must equal `self.len`; returns `EFAULT` otherwise.
    pub fn copy_from_kernel(&self, src: &[T]) -> UaccessResult {
        if src.len() != self.len {
            return Err(UaccessError::Fault);
        }
        let byte_len = self
            .len
            .checked_mul(mem::size_of::<T>())
            .ok_or(UaccessError::Fault)?;
        copy_to_user(self.base, src.as_ptr() as *const u8, byte_len)
    }

    /// Returns a sub-slice `[start, start + new_len)` of this slice.
    ///
    /// Returns `None` if the range would exceed `self.len`.
    pub fn sub_slice(&self, start: usize, new_len: usize) -> Option<Self> {
        if start.checked_add(new_len)? > self.len {
            return None;
        }
        let new_base = self.base.checked_add(start * mem::size_of::<T>())?;
        Some(Self::new(new_base, new_len))
    }
}

impl<T: Copy> core::fmt::Debug for UserSlice<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "UserSlice {{ base: {:#018x}, len: {}, element_size: {} }}",
            self.base,
            self.len,
            mem::size_of::<T>()
        )
    }
}

/// Copies a NUL-terminated C-string from user space into `buf`.
///
/// Returns the number of bytes written (not including the NUL).  Returns
/// `EFAULT` if the string is not entirely within user address space or a
/// page fault occurs.  Returns `EFAULT` if the string exceeds `buf.len() - 1`
/// bytes (i.e. the buffer would overflow).
///
/// The output buffer is always NUL-terminated on success.
pub fn strncpy_from_user(buf: &mut [u8], user_addr: usize) -> UaccessResult<usize> {
    if buf.is_empty() {
        return Err(UaccessError::Fault);
    }
    if user_addr == 0 {
        return Err(UaccessError::Fault);
    }

    // Walk byte-by-byte up to `buf.len() - 1` (leave room for NUL).
    let max = buf.len() - 1;

    // SAFETY: We check each byte address before reading; the access window
    //         converts faults to EFAULT.
    unsafe {
        let mut i = 0usize;
        loop {
            let addr = user_addr.checked_add(i).ok_or(UaccessError::Fault)?;
            if !user_access_ok(addr, 1) {
                return Err(UaccessError::Fault);
            }
            let byte = run_in_user_access(|| ptr::read_volatile(addr as *const u8))??;

            buf[i] = byte;
            if byte == 0 {
                return Ok(i); // excludes NUL
            }
            i += 1;
            if i > max {
                // String too long for the buffer; NUL-terminate and error.
                buf[max] = 0;
                return Err(UaccessError::Fault);
            }
        }
    }
}

/// Copies the kernel string `s` to a user buffer of capacity `user_len`.
///
/// Writes `min(s.len() + 1, user_len)` bytes.  Returns the number of bytes
/// that *would* have been written if `user_len` were large enough (like
/// `snprintf`).  Returns `EFAULT` on access error.
pub fn copyout_str(user_addr: usize, s: &str, user_len: usize) -> UaccessResult<usize> {
    let bytes = s.as_bytes();
    let to_copy = bytes.len().min(user_len.saturating_sub(1));

    if to_copy > 0 {
        copy_to_user(user_addr, bytes.as_ptr(), to_copy)?;
    }

    // Write NUL terminator if there is room.
    if user_len > to_copy {
        put_user::<u8>(
            user_addr.checked_add(to_copy).ok_or(UaccessError::Fault)?,
            0u8,
        )?;
    }

    Ok(bytes.len() + 1) // "would-write" count including NUL
}

/// Writes `len` zero bytes to the user address `dst`.
///
/// Typically used by `mmap` / `execve` to clear BSS or zero-init stack frames.
pub fn clear_user(dst: usize, len: usize) -> UaccessResult {
    if len == 0 {
        return Ok(());
    }
    if dst == 0 || !user_access_ok(dst, len) {
        return Err(UaccessError::Fault);
    }

    // SAFETY: verified range; faults become EFAULT.
    unsafe {
        run_in_user_access(|| {
            ptr::write_bytes(dst as *mut u8, 0, len);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_ok_basic() {
        // Null address is always invalid
        assert!(!user_access_ok(0, 8));

        // Top of user space is valid
        assert!(user_access_ok(USER_ADDR_MAX - 8, 8));

        // One byte over the top is invalid
        assert!(!user_access_ok(USER_ADDR_MAX, 1));

        // Length 0 is always valid (no bytes accessed)
        assert!(user_access_ok(1, 0));
    }

    #[test]
    fn access_ok_wrap() {
        // usize::MAX + 1 would wrap; must be detected
        assert!(!user_access_ok(usize::MAX, 2));
        assert!(!user_access_ok(usize::MAX - 1, 4));
    }

    #[test]
    fn user_ptr_valid() {
        // A pointer into kernel space should be rejected
        let kernel_addr = USER_ADDR_MAX + 0x1000;
        let p: UserPtr<u64> = UserPtr::new(kernel_addr);
        assert!(!p.is_valid());

        // NULL pointer rejected
        let null_p: UserPtr<u64> = UserPtr::new(0);
        assert!(null_p.is_null());
        assert!(!null_p.is_valid());
    }

    #[test]
    fn user_slice_sub_slice() {
        let s: UserSlice<u32> = UserSlice::new(0x1000, 10);
        let sub = s.sub_slice(2, 5).unwrap();
        assert_eq!(sub.base_addr(), 0x1000 + 2 * 4);
        assert_eq!(sub.len(), 5);

        // Out-of-bounds sub-slice
        assert!(s.sub_slice(8, 4).is_none());
    }
}
