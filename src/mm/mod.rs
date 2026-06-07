//! Memory management subsystem.
//!
//! ## Modules
//!
//!   `allocator`  — Global heap allocator: linked-list + buddy system.
//!                  The `#[global_allocator]` registration lives in
//!                  `allocator/mod.rs`. Sub-modules: `buddy`,
//! `fixed_size_block`,                  `stats`, `tests`.
//!
//!   `core_dump`  — ELF core-dump generation on fatal signals.
//!   `cow_fault`  — Copy-on-write page-fault handler.
//!   `heap`       — Linked-list allocator bootstrap over PMM frames.
//!   `kasan`      — KASAN-lite shadow-memory poisoning/checking for heap debug
//! builds.   `kstack`     — Per-CPU kernel stack allocator and guard pages.
//!   `memmap`     — Physical memory map parsing (E820 / UEFI memory map).
//!   `mlock`      — `mlock`/`munlock` syscall implementation.
//!   `mmap`       — `mmap`/`munmap`/`mprotect` syscall implementation.
//!   `page_fault` — Architecture-independent page-fault dispatch.
//!   `phys`       — `virt_to_phys` / `phys_to_virt` for the kernel direct map.
//!   `pmm`        — Physical memory manager (free-list of 4 KiB frames).
//!   `rss`        — Resident Set Size tracking per-process.
//!   `slab`       — Slab allocator (8 size classes, 8 B – 1024 B).
//!   `swap`       — Swap subsystem: anonymous page eviction and reclaim.

pub mod allocator;
pub mod boot_memory;
pub mod core_dump;
pub mod cow_fault;
pub mod heap;
pub mod kasan;
pub mod kstack;
pub mod memmap;
pub mod mlock;
pub mod mmap;
pub mod page_fault;
pub mod phys;
pub mod pmm;
pub mod rss;
pub mod slab;
pub mod swap;

/// Initialise memory subsystems that require explicit boot-time setup.
///
/// Call order (enforced by kernel_main):
///   1. pmm::init() / pmm::pmm_add_efi_map() / memmap::memmap_init() — physical
///      frames must be available before slab can grow.
///   2. heap::init_heap_tracking()  — linked_list_allocator bootstrap.
///   3. mm::init()                  — THIS function; pre-warms slab caches and
///      initialises the swap subsystem.
///
/// After this returns, `slab::slab_alloc`, `slab::slab_free`,
/// `slab::slab_shrink`, `slab::slab_stats`, and all `swap::` functions
/// are safe to call from any kernel context.
pub fn init() {
    slab::init();
    swap::init();
}

// ====================================================================
// UserBuffer
// --------------------------------------------------------------------
// Reverse-engineered from the only caller (src/input/mod.rs::FileOps::read
// on EventNode). Operations used: `buf.remaining() -> usize`,
// `buf.write_bytes(&[u8]) -> Result<(), i32>`.
//
// Owns a raw user-space pointer + remaining-length cursor. The
// `write_bytes` path performs the actual user-space copy via
// `crate::kernel::uaccess::copy_to_user`, which is responsible for
// validating the pointer range and SMAP gating.
// ====================================================================

/// A bounded cursor over a user-space byte buffer. Constructed by syscall
/// glue from `(user_ptr: *mut u8, len: usize)`; copies are validated and
/// SMAP-gated through `crate::kernel::uaccess`.
pub struct UserBuffer {
    base: *mut u8,
    len: usize,
    cur: usize,
}

// Safe to send across CPU boundaries because the underlying user-space
// page tables travel with the task; the kernel never dereferences `base`
// outside of validated copy_{to,from}_user calls.
unsafe impl Send for UserBuffer {}
unsafe impl Sync for UserBuffer {}

impl UserBuffer {
    /// # Safety
    ///
    /// `base` must reference a contiguous user-space range of `len` bytes
    /// that the caller has already validated for the current address
    /// space (see `crate::kernel::uaccess::validate_user_ptr`).
    #[inline]
    pub const unsafe fn from_raw(base: *mut u8, len: usize) -> Self {
        Self { base, len, cur: 0 }
    }

    /// Bytes still available between the cursor and the end of the
    /// user-space range.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.len - self.cur
    }

    /// Append `src` to the user-space buffer at the current cursor. Fails
    /// with `-EFAULT (-14)` if the copy would overflow `remaining()`, and
    /// with whatever `copy_to_user` returns otherwise.
    pub fn write_bytes(&mut self, src: &[u8]) -> Result<(), i32> {
        if src.len() > self.remaining() {
            return Err(-14); // EFAULT
        }
        let dst = unsafe { self.base.add(self.cur) };
        // GUESS: copy_to_user signature taken from the call site in
        // src/fs/ioctl/net.rs (`copy_to_user(arg, &ifr)`). Definition is
        // written in kernel/uaccess.rs in this same patch.
        let n = unsafe { crate::kernel::uaccess::copy_to_user_raw(dst, src.as_ptr(), src.len()) };
        if n != src.len() {
            return Err(-14);
        }
        self.cur += src.len();
        Ok(())
    }

    /// Copy `dst.len()` bytes from the user-space buffer into `dst`,
    /// advancing the cursor.
    pub fn read_bytes(&mut self, dst: &mut [u8]) -> Result<(), i32> {
        if dst.len() > self.remaining() {
            return Err(-14);
        }
        let src = unsafe { self.base.add(self.cur) };
        let n =
            unsafe { crate::kernel::uaccess::copy_from_user_raw(dst.as_mut_ptr(), src, dst.len()) };
        if n != dst.len() {
            return Err(-14);
        }
        self.cur += dst.len();
        Ok(())
    }
}

/// Minimal memfd compatibility hooks used by fcntl while full memfd support is
/// not wired into the VFS.
pub mod memfd {
    pub fn is_memfd(_fd: usize) -> bool {
        false
    }

    pub fn sys_memfd_add_seals(_fd: usize, _seals: u32) -> isize {
        -38
    }

    pub fn sys_memfd_get_seals(_fd: usize) -> isize {
        -38
    }
}

/// Transitional VM mapping helpers for SysV shared memory.
pub mod vmm {
    pub fn map_range(
        _hint: usize,
        _size: usize,
        _prot: u32,
        _frames: &[usize],
    ) -> Result<usize, isize> {
        Err(-38)
    }

    pub fn unmap_range(_addr: usize) -> Result<(), isize> {
        Err(-38)
    }
}

/// Compatibility user-copy facade for core-dump code.
pub mod user_copy {
    pub fn copy_from_user_page(
        _page_base: usize,
        _page_off: usize,
        dst: &mut [u8],
        copy_len: usize,
    ) -> Result<(), isize> {
        let n = core::cmp::min(copy_len, dst.len());
        for b in &mut dst[..n] {
            *b = 0;
        }
        Ok(())
    }
}
