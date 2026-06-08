//! Btrfs transaction facade.

extern crate alloc;

use alloc::vec::Vec;

use super::superblock::BtrfsFs;

/// Lightweight transaction handle for synchronous Btrfs mutations.
///
/// The current filesystem driver writes synchronously, so this type mostly
/// provides a structured boundary around a mutable `BtrfsFs` reference.
/// It is still useful because higher layers can depend on transaction-shaped
/// control flow now, while a real commit/rollback implementation can be added
/// later without changing call sites.
pub struct BtrfsTransaction<'a> {
    fs: &'a mut BtrfsFs,
    generation: u64,
    dirty: bool,
    aborted: bool,
}

impl<'a> BtrfsTransaction<'a> {
    /// Start a new transaction on a mounted Btrfs instance.
    pub fn begin(fs: &'a mut BtrfsFs) -> Self {
        let generation = fs.superblock.generation.saturating_add(1);

        Self {
            fs,
            generation,
            dirty: false,
            aborted: false,
        }
    }

    /// Return the transaction generation that will be committed.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return whether the transaction has performed any mutation.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Return whether the transaction was aborted.
    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    /// Access the underlying filesystem immutably.
    pub fn fs(&self) -> &BtrfsFs {
        self.fs
    }

    /// Access the underlying filesystem mutably and mark the transaction dirty.
    pub fn fs_mut(&mut self) -> &mut BtrfsFs {
        self.dirty = true;
        self.fs
    }

    /// Mark this transaction as dirty after a lower-level mutation.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Abort the transaction.
    ///
    /// This does not roll back already-written metadata because the current
    /// driver writes synchronously. It only prevents `commit` from advancing
    /// the in-memory generation.
    pub fn abort(mut self) -> Result<(), isize> {
        self.aborted = true;
        Err(-5)
    }

    /// Commit the transaction.
    ///
    /// Because writes are synchronous in this driver, commit only advances the
    /// in-memory superblock generation when mutations occurred.
    pub fn commit(mut self) -> Result<(), isize> {
        if self.aborted {
            return Err(-5);
        }

        if self.dirty {
            self.fs.superblock.generation = self.generation;
        }

        Ok(())
    }

    /// Run a closure inside a transaction and commit it if the closure succeeds.
    pub fn run<T, F>(fs: &'a mut BtrfsFs, f: F) -> Result<T, isize>
    where
        F: FnOnce(&mut BtrfsTransaction<'a>) -> Result<T, isize>,
    {
        let mut tx = BtrfsTransaction::begin(fs);
        let result = f(&mut tx)?;

        tx.commit()?;

        Ok(result)
    }

    /// Transaction-aware create wrapper.
    pub fn create(&mut self, path: &str) -> Result<(), isize> {
        self.fs.create(path)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware mkdir wrapper.
    pub fn mkdir(&mut self, path: &str) -> Result<(), isize> {
        self.fs.mkdir(path)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware unlink wrapper.
    pub fn unlink(&mut self, path: &str) -> Result<(), isize> {
        self.fs.unlink(path)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware rmdir wrapper.
    pub fn rmdir(&mut self, path: &str) -> Result<(), isize> {
        self.fs.rmdir(path)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware rename wrapper.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), isize> {
        self.fs.rename(old, new)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware hard-link wrapper.
    pub fn link(&mut self, existing: &str, new: &str) -> Result<(), isize> {
        self.fs.link(existing, new)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware symlink wrapper.
    pub fn symlink(&mut self, target: &str, path: &str) -> Result<(), isize> {
        self.fs.symlink(target, path)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware chmod wrapper.
    pub fn chmod(&mut self, path: &str, mode: u32) -> Result<(), isize> {
        self.fs.chmod(path, mode)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware chown wrapper.
    pub fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), isize> {
        self.fs.chown(path, uid, gid)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware timestamp update wrapper.
    pub fn set_times(
        &mut self,
        path: &str,
        atime_sec: u64,
        mtime_sec: u64,
    ) -> Result<(), isize> {
        self.fs.set_times(path, atime_sec, mtime_sec)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware truncate wrapper.
    pub fn truncate(&mut self, path: &str, new_len: u64) -> Result<(), isize> {
        self.fs.truncate(path, new_len)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware full-file write wrapper.
    pub fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), isize> {
        self.fs.write_all(path, data)?;
        self.dirty = true;
        Ok(())
    }

    /// Transaction-aware read helper.
    pub fn read_all(&self, path: &str) -> Result<Vec<u8>, isize> {
        self.fs.read_all(path)
    }
}

/// Convenience helper for callers that do not need to hold the transaction.
pub fn transaction<T, F>(fs: &mut BtrfsFs, f: F) -> Result<T, isize>
where
    F: FnOnce(&mut BtrfsTransaction<'_>) -> Result<T, isize>,
{
    let mut tx = BtrfsTransaction::begin(fs);
    let result = f(&mut tx)?;

    tx.commit()?;

    Ok(result)
}