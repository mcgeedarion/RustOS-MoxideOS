//! Intrusive kernel collections.
//!
//! Standard library collections (Vec, LinkedList, …) are allocation-heavy
//! and unsuitable for the kernel fast-path.  This module provides two
//! primitives that operate on **already-allocated** objects:
//!
//! * [`IntrusiveList<T>`] — a doubly-linked list where the link nodes are
//!   embedded inside `T` via the [`Linkable`] trait.
//! * [`RingBuf<T>`]      — a fixed-capacity SPSC ring buffer backed by a
//!   caller-supplied slice; used for IRQ-to-thread event queues.
//!
//! # Safety model
//!
//! Both collections work with raw pointers because:
//! 1. The kernel frequently holds mutable references to a list **and** to
//!    individual nodes simultaneously (scheduler run-queue mutations).
//! 2. Intrusive links by definition span the lifetime of the owning allocation,
//!    which the compiler cannot verify statically.
//!
//! Callers are responsible for ensuring pointer validity and exclusive
//! access during mutations.  In practice this means holding a spinlock.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Embed this in any struct you want to insert into an [`IntrusiveList`].
#[repr(C)]
pub struct ListNode {
    pub prev: Option<NonNull<ListNode>>,
    pub next: Option<NonNull<ListNode>>,
}

impl ListNode {
    pub const fn new() -> Self {
        Self {
            prev: None,
            next: None,
        }
    }
}

/// Trait implemented by types that contain an intrusive [`ListNode`].
///
/// # Safety
/// `node_ptr` must return a stable pointer to a `ListNode` embedded inside
/// `Self`.  The node must live exactly as long as `Self`.
// Linkable trait declared below (combined definition includes `from_node`).

/// Intrusive doubly-linked list.
///
/// The list itself is a sentinel node (head); all real nodes are stored
/// inside objects allocated elsewhere.
pub struct IntrusiveList<T: Linkable> {
    head: ListNode,
    len: usize,
    _marker: core::marker::PhantomData<*mut T>,
}

// SAFETY: The list is protected by an external lock in all call-sites.
unsafe impl<T: Linkable + Send> Send for IntrusiveList<T> {}

impl<T: Linkable> IntrusiveList<T> {
    /// Create an empty list.
    pub const fn new() -> Self {
        Self {
            head: ListNode::new(),
            len: 0,
            _marker: core::marker::PhantomData,
        }
    }

    /// Number of elements currently in the list.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the list contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Push `node` to the **back** of the list.
    ///
    /// # Safety
    /// `ptr` must be a valid, non-null, properly aligned pointer to a live
    /// `T`.  The node must not already be in any list.
    pub unsafe fn push_back(&mut self, ptr: NonNull<T>) {
        let node = unsafe { &mut *T::node_ptr(ptr.as_ptr()) };
        let sentinel = &mut self.head as *mut ListNode;

        // Insert before sentinel (= at the tail).
        let prev = unsafe { (*sentinel).prev };
        node.prev = prev;
        node.next = Some(unsafe { NonNull::new_unchecked(sentinel) });
        if let Some(mut p) = prev {
            unsafe { p.as_mut().next = Some(NonNull::new_unchecked(node)) };
        } else {
            // List was empty — sentinel's own `next` also points to node.
            unsafe { (*sentinel).next = Some(NonNull::new_unchecked(node)) };
        }
        unsafe { (*sentinel).prev = Some(NonNull::new_unchecked(node)) };
        self.len += 1;
    }

    /// Pop from the **front** of the list, returning the pointer.
    ///
    /// Returns `None` if the list is empty.
    pub fn pop_front(&mut self) -> Option<NonNull<T>> {
        let sentinel = &mut self.head as *mut ListNode;
        let first = unsafe { (*sentinel).next }?;
        let first_ptr = first.as_ptr();

        // Detach `first` from the list.
        let next = unsafe { (*first_ptr).next };
        unsafe { (*sentinel).next = next };
        if let Some(mut n) = next {
            unsafe { n.as_mut().prev = Some(NonNull::new_unchecked(sentinel)) };
        } else {
            unsafe { (*sentinel).prev = None };
        }
        unsafe {
            (*first_ptr).prev = None;
            (*first_ptr).next = None;
        }
        self.len -= 1;

        // Recover the owning `T` pointer from the embedded node pointer.
        // We need to go from *ListNode → *T using the Linkable offset.
        // Because we cannot know the field offset at compile time without
        // the concrete type, we use a trick: push_back stored a *T, and
        // node_ptr(T) must point into T.  We walk the other direction by
        // searching — but that's O(n).  Instead we require that Linkable
        // impls store the node at offset 0 OR expose an inverse.
        // For now we expose a helper that each impl provides.
        Some(unsafe { NonNull::new_unchecked(T::from_node(first_ptr)) })
    }
}

/// Extension to [`Linkable`]: recover `*mut T` from `*mut ListNode`.
///
/// # Safety
/// Must be the inverse of `node_ptr`.
pub unsafe trait Linkable: Sized {
    fn node_ptr(this: *mut Self) -> *mut ListNode;
    /// # Safety
    /// `node` must point to the node embedded inside a live `Self`.
    unsafe fn from_node(node: *mut ListNode) -> *mut Self;
}

/// Fixed-capacity, lock-free SPSC ring buffer.
///
/// The buffer operates on a **caller-supplied** slice so it never
/// allocates.  Suitable for IRQ→thread event queues where the producer
/// is an interrupt handler and the consumer is a kernel thread.
///
/// ```ignore
/// static mut BUF_MEM: [MaybeUninit<Event>; 64] =
///     unsafe { MaybeUninit::uninit().assume_init() };
/// let ring = RingBuf::from_raw(unsafe { &mut BUF_MEM });
/// ```
pub struct RingBuf<T> {
    buf: *mut core::mem::MaybeUninit<T>,
    cap: usize,
    /// Producer write index (mod cap).
    head: AtomicUsize,
    /// Consumer read index (mod cap).
    tail: AtomicUsize,
}

// SAFETY: RingBuf is only safe to share if T: Send.  The SPSC contract
// means at most one producer + one consumer simultaneously.
unsafe impl<T: Send> Send for RingBuf<T> {}
unsafe impl<T: Send> Sync for RingBuf<T> {}

impl<T> RingBuf<T> {
    /// Create a `RingBuf` from a raw slice of uninitialised memory.
    ///
    /// `buf.len()` must be a power of two for efficient masking.
    ///
    /// # Safety
    /// `buf` must remain valid for the lifetime of this `RingBuf`.
    pub unsafe fn from_raw(buf: &'static mut [core::mem::MaybeUninit<T>]) -> Self {
        debug_assert!(
            buf.len().is_power_of_two(),
            "RingBuf capacity must be a power of two"
        );
        Self {
            buf: buf.as_mut_ptr(),
            cap: buf.len(),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Returns `true` if no items are available to consume.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tail.load(Ordering::Acquire) == self.head.load(Ordering::Acquire)
    }

    /// Returns `true` if the buffer is at capacity.
    #[inline]
    pub fn is_full(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) == self.cap
    }

    /// Push an item (producer side).  Returns `Err(item)` if full.
    #[inline]
    pub fn push(&self, item: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) == self.cap {
            return Err(item);
        }
        let slot = head & (self.cap - 1);
        // SAFETY: slot is within bounds; producer has exclusive write access.
        unsafe { (*self.buf.add(slot)).write(item) };
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Pop an item (consumer side).  Returns `None` if empty.
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let slot = tail & (self.cap - 1);
        // SAFETY: slot is within bounds; consumer has exclusive read access.
        let item = unsafe { (*self.buf.add(slot)).assume_init_read() };
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(item)
    }
}
