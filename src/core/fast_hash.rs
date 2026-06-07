//! Fast, non-cryptographic hash tables for trusted kernel-internal keys.

extern crate alloc;

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use core::mem;

const INITIAL_BUCKETS: usize = 16;
const FX_SEED: u64 = 0xcbf2_9ce4_8422_2325;
const FX_MULTIPLIER: u64 = 0x517c_c1b7_2722_0a95;

/// Fast FxHash-style hasher for trusted kernel bookkeeping keys.
#[derive(Clone)]
pub struct KernelFastHasher {
    hash: u64,
}

impl Default for KernelFastHasher {
    fn default() -> Self {
        Self { hash: FX_SEED }
    }
}

impl KernelFastHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = self.hash.rotate_left(5) ^ word;
        self.hash = self.hash.wrapping_mul(FX_MULTIPLIER);
    }
}

impl Hasher for KernelFastHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            self.add(u64::from_ne_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]));
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut tail = [0u8; 8];
            tail[..rem.len()].copy_from_slice(rem);
            self.add(u64::from_ne_bytes(tail));
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
}

fn make_hash<K: Hash + ?Sized>(key: &K) -> u64 {
    let mut hasher = KernelFastHasher::default();
    key.hash(&mut hasher);
    hasher.finish()
}

/// Dependency-free hash map for trusted, bounded kernel-internal keys.
pub struct KernelFastMap<K, V> {
    buckets: Vec<Vec<(u64, K, V)>>,
    len: usize,
}

impl<K, V> Default for KernelFastMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> KernelFastMap<K, V> {
    pub const fn new() -> Self {
        Self {
            buckets: Vec::new(),
            len: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.iter().map(|(_, key, _)| key))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.iter().map(|(_, key, value)| (key, value)))
    }
}

impl<K: Hash + Eq, V> KernelFastMap<K, V> {
    #[inline]
    fn bucket_index(&self, hash: u64) -> usize {
        debug_assert!(!self.buckets.is_empty());
        hash as usize & (self.buckets.len() - 1)
    }

    fn allocate_buckets(&mut self, count: usize) {
        debug_assert!(count.is_power_of_two());
        self.buckets.clear();
        self.buckets.reserve(count);
        for _ in 0..count {
            self.buckets.push(Vec::new());
        }
    }

    fn ensure_capacity_for_insert(&mut self) {
        if self.buckets.is_empty() {
            self.allocate_buckets(INITIAL_BUCKETS);
            return;
        }

        if (self.len + 1) * 4 <= self.buckets.len() * 3 {
            return;
        }

        let new_count = self.buckets.len() * 2;
        let mut old = Vec::new();
        mem::swap(&mut old, &mut self.buckets);
        self.allocate_buckets(new_count);
        for bucket in old {
            for (hash, key, value) in bucket {
                let idx = self.bucket_index(hash);
                self.buckets[idx].push((hash, key, value));
            }
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        if self.buckets.is_empty() {
            return None;
        }
        let hash = make_hash(key);
        self.buckets[self.bucket_index(hash)]
            .iter()
            .find(|(entry_hash, entry_key, _)| *entry_hash == hash && entry_key == key)
            .map(|(_, _, value)| value)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if self.buckets.is_empty() {
            return None;
        }
        let hash = make_hash(key);
        let idx = self.bucket_index(hash);
        self.buckets[idx]
            .iter_mut()
            .find(|(entry_hash, entry_key, _)| *entry_hash == hash && entry_key == key)
            .map(|(_, _, value)| value)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.ensure_capacity_for_insert();
        let hash = make_hash(&key);
        let idx = self.bucket_index(hash);
        if let Some((_, _, existing)) = self.buckets[idx]
            .iter_mut()
            .find(|(entry_hash, entry_key, _)| *entry_hash == hash && entry_key == &key)
        {
            return Some(mem::replace(existing, value));
        }
        self.buckets[idx].push((hash, key, value));
        self.len += 1;
        None
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        if self.buckets.is_empty() {
            return None;
        }
        let hash = make_hash(key);
        let idx = self.bucket_index(hash);
        let pos = self.buckets[idx]
            .iter()
            .position(|(entry_hash, entry_key, _)| *entry_hash == hash && entry_key == key)?;
        self.len -= 1;
        Some(self.buckets[idx].swap_remove(pos).2)
    }
}

impl<K: Clone, V: Clone> Clone for KernelFastMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            buckets: self.buckets.clone(),
            len: self.len,
        }
    }
}

impl<K, V> IntoIterator for KernelFastMap<K, V> {
    type Item = (K, V);
    type IntoIter = alloc::vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        let mut entries = Vec::with_capacity(self.len);
        for bucket in self.buckets {
            for (_, key, value) in bucket {
                entries.push((key, value));
            }
        }
        entries.into_iter()
    }
}
