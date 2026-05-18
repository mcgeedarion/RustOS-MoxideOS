//! Btrfs mount logic, superblock parsing, chunk-tree bootstrap, and block I/O.
//! Merged from mount.rs + io.rs
extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::superblock::{BtrfsSuperblock, BtrfsChunkItem, BtrfsKey,
                        BtrfsFs, BTRFS_MOUNTS};

pub fn mount(subpath: &str, lba_start: u64) -> Result<(), &'static str> {
    // Read superblock at byte offset 0x10_000 (64 KiB from partition start)
    let sb_lba = lba_start + 128;
    let raw    = read_sectors_raw(sb_lba, 16);
    let sb     = BtrfsSuperblock::from_bytes(&raw).ok_or("bad superblock")?;
    let chunk_map = parse_sys_chunk_array(&sb).ok_or("empty chunk array")?;
    let root_tree_root = sb.root;
    let mut fs = BtrfsFs {
        superblock:     sb.clone(),
        chunk_map:      chunk_map.clone(),
        root_tree_root,
        fs_tree_root:   0,
        path_cache:     BTreeMap::new(),
        alloc_cursor:   sb.total_bytes,
    };
    fs.fs_tree_root = resolve_fs_tree_root(&fs).ok_or("no FS tree")?;
    BTRFS_MOUNTS.lock().insert(subpath.to_string(), fs);
    Ok(())
}

fn parse_sys_chunk_array(
    sb: &BtrfsSuperblock,
) -> Option<Vec<(u64, u64, BtrfsChunkItem)>> {
    let arr = &sb.sys_chunk_array[..sb.sys_chunk_array_size as usize];
    let mut map = Vec::new();
    let mut off = 0usize;
    while off + 17 <= arr.len() {
        let key = BtrfsKey::from_bytes(&arr[off..off + 17]);
        off += 17;
        if key.ty != 228 { break; }
        let chunk = BtrfsChunkItem::from_bytes(&arr[off..])?;
        let stripe_sz = 80 + chunk.num_stripes as usize * 64;
        map.push((key.offset, key.offset + chunk.length, chunk));
        off += stripe_sz;
    }
    if map.is_empty() { None } else { Some(map) }
}

fn resolve_fs_tree_root(fs: &BtrfsFs) -> Option<u64> {
    use super::superblock::{BtrfsRootItem, BTRFS_ROOT_ITEM_KEY};
    const BTRFS_FS_TREE_OBJECTID: u64 = 5;
    let key  = BtrfsKey::new(BTRFS_FS_TREE_OBJECTID, BTRFS_ROOT_ITEM_KEY, 0);
    let data = fs.lookup_item(fs.root_tree_root, key)?;
    Some(BtrfsRootItem::from_bytes(&data)?.bytenr)
}

// ── block-level I/O helpers (from io.rs) ────────────────────────────────────────────────────
pub(crate) fn read_sectors_raw(lba: u64, count: u32) -> Vec<u8> {
    crate::drivers::block::read_sectors_vec(lba, count)
}

pub(crate) fn write_sectors_raw(lba: u64, data: &[u8]) {
    debug_assert!(data.len() % 512 == 0);
    crate::drivers::block::write_sectors(lba, data);
}

pub(crate) fn read_logical(
    fs: &BtrfsFs, logical: u64, byte_len: usize,
) -> Option<Vec<u8>> {
    let phys  = fs.logical_to_physical(logical)?;
    let nsecs = ((byte_len + 511) / 512) as u32;
    let raw   = read_sectors_raw(phys / 512, nsecs);
    if raw.len() < byte_len { return None; }
    Some(raw[..byte_len].to_vec())
}

pub(crate) fn write_logical(
    fs: &BtrfsFs, logical: u64, data: &[u8],
) -> Result<(), &'static str> {
    let phys = fs.logical_to_physical(logical).ok_or("unmapped logical addr")?;
    let mut aligned = vec![0u8; (data.len() + 511) & !511];
    aligned[..data.len()].copy_from_slice(data);
    write_sectors_raw(phys / 512, &aligned);
    Ok(())
}

pub(crate) fn read_node(
    fs: &BtrfsFs, logical: u64,
) -> Option<Vec<u8>> {
    read_logical(fs, logical, fs.superblock.nodesize as usize)
}

pub(crate) fn write_node(
    fs: &BtrfsFs, logical: u64, data: &[u8],
) -> Result<(), &'static str> {
    let ns = fs.superblock.nodesize as usize;
    let mut buf = vec![0u8; ns];
    let cl = data.len().min(ns);
    buf[..cl].copy_from_slice(&data[..cl]);
    write_logical(fs, logical, &buf)
}