//! Miscellaneous kernel utilities — canonical location: src/kernel/utils.rs
pub fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}
pub fn align_down(val: usize, align: usize) -> usize {
    val & !(align - 1)
}
