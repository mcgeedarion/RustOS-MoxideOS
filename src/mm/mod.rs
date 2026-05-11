pub mod core_dump;
pub mod cow_fault;
pub mod heap;
pub mod kstack;
pub mod memmap;
pub mod mlock;
pub mod mmap;
pub mod page_fault;
pub mod pmm;
pub mod rss;
pub mod slab;
pub mod swap;

/// Initialise memory subsystems that require explicit boot-time setup.
///
/// Call order (enforced by kernel_main):
///   1. pmm::init() / pmm::pmm_add_efi_map() / memmap::memmap_init()
///      — physical frames must be available before slab can grow.
///   2. heap::init_heap_tracking()  — linked_list_allocator bootstrap.
///   3. mm::init()                  — THIS function; pre-warms slab caches
///                                    and initialises the swap subsystem.
///
/// After this returns, `slab::slab_alloc`, `slab::slab_free`,
/// `slab::slab_shrink`, `slab::slab_stats`, and all `swap::` functions
/// are safe to call from any kernel context.
pub fn init() {
    slab::init();
    swap::init();
}
