//! Slab allocator — fixed-size object caches backed by the PMM.
//!
//! ## Design overview
//!
//! ```text
//!  slab_alloc(sz)
//!       │
//!       ▼
//!  size_class(sz)  ──►  cache[i]  (spin::Mutex<Cache>)
//!                             │
//!                  ┌──────────┴──────────┐
//!                  │  partial slabs list  │
//!                  │  full    slabs list  │
//!                  │  empty   slabs list  │
//!                  └──────────┬──────────┘
//!                             │
//!               pop free slot from partial head
//!               (or carve a new slab from PMM)
//! ```
//!
//! ## Size classes
//!
//!   Index │  Object size │  Slots per 4 KiB page
//!   ──────┼──────────────┼──────────────────────
//!     0   │     8 bytes  │   512
//!     1   │    16 bytes  │   256
//!     2   │    32 bytes  │   128
//!     3   │    64 bytes  │    64
//!     4   │   128 bytes  │    32
//!     5   │   256 bytes  │    16
//!     6   │   512 bytes  │     8
//!     7   │  1024 bytes  │     4
//!
//! Requests > 1024 bytes are forwarded to the global heap allocator.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;

use crate::mm::{kasan, pmm};

const PAGE_SIZE: usize = 4096;
const SIZE_CLASSES: [usize; 8] = [8, 16, 32, 64, 128, 256, 512, 1024];
const NUM_CACHES: usize = SIZE_CLASSES.len();
const CANARY_MAGIC: u32 = 0xDEAD_C0DE;
const CANARY_SIZE: usize = core::mem::size_of::<u32>();

const SLAB_HDR_RAW: usize = core::mem::size_of::<SlabHdr>();

#[inline]
const fn hdr_offset(obj_size: usize) -> usize {
    (SLAB_HDR_RAW + obj_size - 1) & !(obj_size - 1)
}

#[inline]
const fn slots_per_page(obj_size: usize) -> usize {
    (PAGE_SIZE - hdr_offset(obj_size)) / obj_size
}

#[inline]
const fn user_size(obj_size: usize) -> usize {
    obj_size.saturating_sub(2 * CANARY_SIZE)
}

#[inline]
unsafe fn slot_user_ptr(slot: *mut u8) -> *mut u8 {
    slot.add(CANARY_SIZE)
}

#[inline]
unsafe fn user_slot_ptr(user: *mut u8) -> *mut u8 {
    user.sub(CANARY_SIZE)
}

#[inline]
unsafe fn canary_write(slot: *mut u8, obj_size: usize) {
    (slot as *mut u32).write(CANARY_MAGIC);
    (slot.add(obj_size - CANARY_SIZE) as *mut u32).write(CANARY_MAGIC);
}

#[inline]
unsafe fn canary_check(slot: *mut u8, obj_size: usize) {
    let lo = (slot as *const u32).read();
    let hi = (slot.add(obj_size - CANARY_SIZE) as *const u32).read();
    assert_eq!(
        lo, CANARY_MAGIC,
        "slab: head canary corrupted at {:p} (got {:#010x})",
        slot, lo
    );
    assert_eq!(
        hi, CANARY_MAGIC,
        "slab: tail canary corrupted at {:p} (got {:#010x})",
        slot, hi
    );
}

#[repr(C)]
struct SlabHdr {
    next: *mut SlabHdr,
    prev: *mut SlabHdr,
    free_head: *mut u8,
    in_use: u16,
    capacity: u16,
    class_idx: u8,
    _pad: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<SlabHdr>() <= 40);

struct Cache {
    partial: *mut SlabHdr,
    full: *mut SlabHdr,
    empty: *mut SlabHdr,
    obj_size: usize,
    capacity: usize,
}

unsafe impl Send for Cache {}

impl Cache {
    const fn new(obj_size: usize) -> Self {
        Cache {
            partial: ptr::null_mut(),
            full: ptr::null_mut(),
            empty: ptr::null_mut(),
            obj_size,
            capacity: slots_per_page(obj_size),
        }
    }

    unsafe fn list_push(list: &mut *mut SlabHdr, slab: *mut SlabHdr) {
        (*slab).next = *list;
        (*slab).prev = ptr::null_mut();
        if !(*list).is_null() {
            (**list).prev = slab;
        }
        *list = slab;
    }

    unsafe fn list_remove(list: &mut *mut SlabHdr, slab: *mut SlabHdr) {
        let prev = (*slab).prev;
        let next = (*slab).next;
        if !prev.is_null() {
            (*prev).next = next;
        } else {
            *list = next;
        }
        if !next.is_null() {
            (*next).prev = prev;
        }
        (*slab).next = ptr::null_mut();
        (*slab).prev = ptr::null_mut();
    }

    unsafe fn grow(&mut self, class_idx: u8) -> bool {
        let pa = match pmm::alloc_page() {
            Some(p) => p,
            None => return false,
        };
        let page = pa as *mut u8;
        let hdr = page as *mut SlabHdr;

        let obj_sz = self.obj_size;
        let cap = self.capacity;
        let slot0_off = hdr_offset(obj_sz);

        let mut prev_slot: *mut u8 = ptr::null_mut();
        let mut i = cap;
        while i > 0 {
            i -= 1;
            let slot = page.add(slot0_off + i * obj_sz);
            *(slot as *mut *mut u8) = prev_slot;
            prev_slot = slot;
        }

        (*hdr).next = ptr::null_mut();
        (*hdr).prev = ptr::null_mut();
        (*hdr).free_head = prev_slot;
        (*hdr).in_use = 0;
        (*hdr).capacity = cap as u16;
        (*hdr).class_idx = class_idx;
        (*hdr)._pad = [0u8; 3];

        Self::list_push(&mut self.partial, hdr);
        true
    }

    unsafe fn alloc(&mut self, class_idx: u8) -> Option<*mut u8> {
        if self.partial.is_null() {
            if !self.empty.is_null() {
                let s = self.empty;
                Self::list_remove(&mut self.empty, s);
                Self::list_push(&mut self.partial, s);
            } else {
                if !self.grow(class_idx) {
                    return None;
                }
            }
        }

        let slab = self.partial;
        debug_assert!(!(*slab).free_head.is_null());

        let slot = (*slab).free_head;
        let next_free = *(slot as *const *mut u8);
        (*slab).free_head = next_free;
        (*slab).in_use += 1;

        if (*slab).in_use as usize == (*slab).capacity as usize {
            Self::list_remove(&mut self.partial, slab);
            Self::list_push(&mut self.full, slab);
        }

        *(slot as *mut *mut u8) = ptr::null_mut();
        canary_write(slot, self.obj_size);

        let user = slot_user_ptr(slot);
        let payload = user_size(self.obj_size);
        kasan::mark_redzone(slot as usize, CANARY_SIZE);
        kasan::mark_accessible(user as usize, payload);
        kasan::mark_redzone(user as usize + payload, CANARY_SIZE);
        Some(user)
    }

    unsafe fn free(&mut self, user_ptr: *mut u8) {
        let ptr = user_slot_ptr(user_ptr);
        let page_base = (ptr as usize) & !(PAGE_SIZE - 1);
        let slab = page_base as *mut SlabHdr;

        let was_full = (*slab).in_use as usize == (*slab).capacity as usize;
        let was_partial = !was_full && (*slab).in_use > 0;

        kasan::check_access(user_ptr as usize, user_size(self.obj_size));
        canary_check(ptr, self.obj_size);
        kasan::mark_poisoned(ptr as usize, self.obj_size);

        ptr::write_bytes(ptr, 0, self.obj_size);
        *(ptr as *mut *mut u8) = (*slab).free_head;
        (*slab).free_head = ptr;
        (*slab).in_use -= 1;

        if was_full {
            Self::list_remove(&mut self.full, slab);
            Self::list_push(&mut self.partial, slab);
        } else if was_partial && (*slab).in_use == 0 {
            Self::list_remove(&mut self.partial, slab);
            Self::list_push(&mut self.empty, slab);
        }
    }

    unsafe fn shrink(&mut self) {
        let mut slab = self.empty;
        while !slab.is_null() {
            let next = (*slab).next;
            pmm::free_page(slab as usize);
            slab = next;
        }
        self.empty = ptr::null_mut();
    }

    unsafe fn count_list(mut head: *mut SlabHdr) -> usize {
        let mut n = 0;
        while !head.is_null() {
            n += 1;
            head = (*head).next;
        }
        n
    }

    unsafe fn stats(&self) -> CacheStats {
        let partial_slabs = Self::count_list(self.partial);
        let full_slabs = Self::count_list(self.full);
        let empty_slabs = Self::count_list(self.empty);
        let active = {
            let mut n = 0usize;
            let mut s = self.partial;
            while !s.is_null() {
                n += (*s).in_use as usize;
                s = (*s).next;
            }
            s = self.full;
            while !s.is_null() {
                n += (*s).in_use as usize;
                s = (*s).next;
            }
            n
        };
        CacheStats {
            obj_size: self.obj_size,
            active_objs: active,
            total_slabs: partial_slabs + full_slabs + empty_slabs,
            partial_slabs,
            full_slabs,
            empty_slabs,
        }
    }
}

macro_rules! make_caches {
    ($($sz:expr),*) => {
        [$(Mutex::new(Cache::new($sz))),*]
    };
}

static CACHES: [Mutex<Cache>; NUM_CACHES] = make_caches![8, 16, 32, 64, 128, 256, 512, 1024];

#[inline]
fn size_class(size: usize) -> Option<usize> {
    if size == 0 {
        return Some(0);
    }
    let needed = size.saturating_add(2 * CANARY_SIZE);
    for (i, &s) in SIZE_CLASSES.iter().enumerate() {
        if needed <= s {
            return Some(i);
        }
    }
    None
}

pub fn init() {
    for (i, cache) in CACHES.iter().enumerate() {
        let mut c = cache.lock();
        if c.partial.is_null() && c.empty.is_null() {
            unsafe {
                c.grow(i as u8);
            }
        }
    }
}

pub fn slab_alloc(size: usize) -> Option<*mut u8> {
    match size_class(size) {
        Some(idx) => unsafe { CACHES[idx].lock().alloc(idx as u8) },
        None => {
            let layout = alloc::alloc::Layout::from_size_align(size, 8).ok()?;
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if ptr.is_null() {
                None
            } else {
                Some(ptr)
            }
        },
    }
}

pub fn slab_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() {
        return;
    }
    match size_class(size) {
        Some(idx) => unsafe { CACHES[idx].lock().free(ptr) },
        None => {
            if let Ok(layout) = alloc::alloc::Layout::from_size_align(size, 8) {
                unsafe {
                    alloc::alloc::dealloc(ptr, layout);
                }
            }
        },
    }
}

pub fn slab_shrink() {
    for cache in CACHES.iter() {
        unsafe {
            cache.lock().shrink();
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheStats {
    pub obj_size: usize,
    pub active_objs: usize,
    pub total_slabs: usize,
    pub partial_slabs: usize,
    pub full_slabs: usize,
    pub empty_slabs: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SlabStats {
    pub total_slabs: usize,
    pub active_objs: usize,
    pub per_cache: [CacheStats; NUM_CACHES],
}

pub fn slab_stats() -> SlabStats {
    let mut out = SlabStats::default();
    for (i, cache) in CACHES.iter().enumerate() {
        let cs = unsafe { cache.lock().stats() };
        out.total_slabs += cs.total_slabs;
        out.active_objs += cs.active_objs;
        out.per_cache[i] = cs;
    }
    out
}

pub struct SlabBox<T> {
    ptr: *mut T,
}

impl<T> SlabBox<T> {
    pub fn new(value: T) -> Option<Self> {
        let size = core::mem::size_of::<T>();
        let ptr = slab_alloc(size)? as *mut T;
        unsafe {
            ptr.write(value);
        }
        Some(SlabBox { ptr })
    }

    pub fn into_raw(self) -> *mut T {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl<T> core::ops::Deref for SlabBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.ptr }
    }
}

impl<T> core::ops::DerefMut for SlabBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr }
    }
}

impl<T> Drop for SlabBox<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(self.ptr);
        }
        slab_free(self.ptr as *mut u8, core::mem::size_of::<T>());
    }
}

unsafe impl<T: Send> Send for SlabBox<T> {}
unsafe impl<T: Sync> Sync for SlabBox<T> {}
