//! Simple LCG PRNG seeded from TSC.
use core::sync::atomic::{AtomicU64, Ordering};
static STATE: AtomicU64 = AtomicU64::new(0xdeadbeef_cafebabe);
pub fn next_u64() -> u64 {
    let s = STATE.load(Ordering::Relaxed);
    let s = s ^ (s << 13); let s = s ^ (s >> 7); let s = s ^ (s << 17);
    STATE.store(s, Ordering::Relaxed); s
}
