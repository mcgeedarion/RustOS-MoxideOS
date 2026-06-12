//! Intrusive kernel collections.

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

/// Intrusive doubly-linked list.
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

        Some(unsafe { NonNull::new_unchecked(T::from_node(first_ptr)) })
    }
}

/// Extension to [`Linkable`]: recover `*mut T` from `*mut ListNode`.
pub unsafe trait Linkable: Sized {
    fn node_ptr(this: *mut Self) -> *mut ListNode;
    /// # Safety
    /// `node` must point to the node embedded inside a live `Self`.
    unsafe fn from_node(node: *mut ListNode) -> *mut Self;
}

/// Fixed-capacity, lock-free SPSC ring buffer.
pub struct RingBuf<T> {
    buf: *mut core::mem::MaybeUninit<T>,
    cap: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
}

// SAFETY: RingBuf is only safe to share if T: Send.  The SPSC contract
// means at most one producer + one consumer simultaneously.
unsafe impl<T: Send> Send for RingBuf<T> {}
unsafe impl<T: Send> Sync for RingBuf<T> {}

impl<T> RingBuf<T> {
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
