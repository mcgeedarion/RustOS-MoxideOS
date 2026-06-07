//! Dentry cache — maps (parent_inode, name) → child inode_id.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;

const DCACHE_MAX: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct DKey {
    parent: u64,
    name: String,
}

struct DCache {
    map: BTreeMap<DKey, u64>,
    order: Vec<DKey>,
}

impl DCache {
    const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            order: Vec::new(),
        }
    }

    fn lookup(&self, parent: u64, name: &str) -> Option<u64> {
        let key = DKey {
            parent,
            name: String::from(name),
        };
        self.map.get(&key).copied()
    }

    fn insert(&mut self, parent: u64, name: String, child: u64) {
        let key = DKey { parent, name };

        // Update existing entry in-place (don't shuffle the LRU order).
        if self.map.contains_key(&key) {
            self.map.insert(key, child);
            return;
        }

        // Evict the oldest entry when at capacity.
        if self.order.len() >= DCACHE_MAX {
            let evict = self.order.remove(0);
            self.map.remove(&evict);
        }

        self.order.push(key.clone());
        self.map.insert(key, child);
    }

    fn invalidate(&mut self, parent: u64, name: &str) {
        let key = DKey {
            parent,
            name: String::from(name),
        };
        if self.map.remove(&key).is_some() {
            self.order.retain(|k| k != &key);
        }
    }

    fn invalidate_inode(&mut self, inode: u64) {
        let victims: Vec<DKey> = self
            .map
            .iter()
            .filter(|(_, &v)| v == inode)
            .map(|(k, _)| k.clone())
            .collect();
        for k in victims {
            self.map.remove(&k);
            self.order.retain(|o| o != &k);
        }
    }

    fn flush(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

static DCACHE: Mutex<DCache> = Mutex::new(DCache::new());

/// Return the child inode number for `(parent, name)`, or `None` on a miss.
pub fn dcache_lookup(parent: u64, name: &str) -> Option<u64> {
    DCACHE.lock().lookup(parent, name)
}

/// Insert or refresh the mapping `(parent, name) → child`.
pub fn dcache_insert(parent: u64, name: String, child: u64) {
    DCACHE.lock().insert(parent, name, child);
}

/// Remove a single dentry — call on `unlink` / `rename`.
pub fn dcache_invalidate(parent: u64, name: &str) {
    DCACHE.lock().invalidate(parent, name);
}

/// Remove every dentry that resolves to `inode` — call on inode deletion.
pub fn dcache_invalidate_inode(inode: u64) {
    DCACHE.lock().invalidate_inode(inode);
}

/// Flush the entire cache — call on unmount.
pub fn dcache_flush() {
    DCACHE.lock().flush();
}

// ===== GUESS: short alias for new callers =====
pub fn invalidate(path: &str) {
    // GUESS: without parent-inode resolution we can't target a single entry,
    // so do a full flush. Correctness > efficiency in early kernel bring-up.
    dcache_flush();
    let _ = path;
}
