//! Kernel-mode test syscall handlers.
//!
//! Only compiled when `feature = "kmtest"` is active.
//! Exposes two syscalls to userspace:
//!
//! | NR              | a0            | a1            | Returns |
//! |-----------------|---------------|---------------|---------|
//! | SYS_KMTEST_LIST | buf_ptr / 0   | buf_len / 0   | test count (≥ 0) or -EFAULT |
//! | SYS_KMTEST_RUN  | index / `!0`  | —             | 0 = pass, 1 = fail, -EINVAL = bad index; `!0` runs all |
//!
//! Results for every test are streamed to the serial console as lines:
//!
//! ```text
//! KMTEST  PASS  smoke_assert_true
//! KMTEST  FAIL  smoke_assert_eq — assertion failed: 1 + 1 == 3
//! KMTEST  DONE  2/2 passed
//! ```
//!
//! This format is designed to be trivially grep-able by the QEMU runner
//! script: `grep '^KMTEST' serial.log`.

use crate::syscall::errno::{efault, einval};

/// Handler for `SYS_KMTEST_LIST`.
///
/// If `buf_ptr == 0` the call returns the test count without writing anything.
/// Otherwise it writes NUL-terminated name strings back-to-back into the
/// user buffer (up to `buf_len` bytes) and returns the number of names written.
///
/// # Safety
/// `buf_ptr` must be a valid userspace pointer when non-zero.
pub fn sys_kmtest_list(buf_ptr: usize, buf_len: usize) -> isize {
    // SAFETY: linker symbols were validated at harness init; see kmtest::registry().
    let tests = unsafe { kmtest::registry_slice() };

    if buf_ptr == 0 {
        return tests.len() as isize;
    }

    // Copy names into the user buffer as NUL-terminated strings.
    let buf = unsafe {
        // SAFETY: caller guarantees buf_ptr is a valid userspace write target.
        core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len)
    };
    let mut pos = 0usize;
    let mut written = 0isize;
    for entry in tests {
        let name = entry.name.as_bytes();
        let needed = name.len() + 1; // +1 for NUL
        if pos + needed > buf.len() {
            break;
        }
        buf[pos..pos + name.len()].copy_from_slice(name);
        buf[pos + name.len()] = 0;
        pos += needed;
        written += 1;
    }
    written
}

/// Handler for `SYS_KMTEST_RUN`.
///
/// `index == usize::MAX` means run all tests.
/// Otherwise runs the single test at `index`.
/// Results are streamed to serial; returns 0 on pass, 1 on fail.
pub fn sys_kmtest_run(index: usize) -> isize {
    // SAFETY: same as above.
    let tests = unsafe { kmtest::registry_slice() };

    if index == usize::MAX {
        run_range(tests, 0, tests.len())
    } else {
        if index >= tests.len() {
            return einval();
        }
        run_range(tests, index, index + 1)
    }
}

// Run tests[start..end], print results to serial, return failure count as isize.
fn run_range(tests: &[kmtest::KmTestEntry], start: usize, end: usize) -> isize {
    let mut failures = 0usize;
    let mut total    = 0usize;

    for entry in &tests[start..end] {
        let result = (entry.run)();
        total += 1;
        match result {
            Ok(()) => {
                serial_println!("KMTEST  PASS  {}", entry.name);
            }
            Err(msg) => {
                serial_println!("KMTEST  FAIL  {} \u{2014} {}", entry.name, msg);
                failures += 1;
            }
        }
    }

    let passed = total - failures;
    serial_println!("KMTEST  DONE  {}/{} passed", passed, total);

    failures as isize
}
