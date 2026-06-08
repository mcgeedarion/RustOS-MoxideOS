//! Debug shell commands: info mem, info proc, bt, dump <addr> <len>
extern crate alloc;
use alloc::format;
use alloc::str::SplitWhitespace;

const DUMP_MAX_LEN: usize = 1024;
const PAGE_SIZE: usize = 4096;

/// Entry point — call from your REPL loop after reading a line.
pub fn dispatch(line: &str) {
    let mut parts = line.trim().split_whitespace();
    match parts.next() {
        Some("info") => cmd_info(parts),
        Some("bt") => cmd_bt(),
        Some("dump") => cmd_dump(parts),
        Some("help") => print_help(),
        Some(other) => crate::shell::tty::write(
            format!("unknown command: {other}\r\ntype 'help' for a list\r\n").as_bytes(),
        ),
        None => {},
    };
}

fn cmd_info(mut parts: SplitWhitespace) {
    match parts.next() {
        Some("mem") => cmd_info_mem(),
        Some("proc") => cmd_info_proc(),
        _ => crate::shell::tty::write(b"usage: info mem | info proc\r\n"),
    }
}

fn cmd_info_mem() {
    let stats = crate::mm::pmm::stats();
    let free_kb = stats.free_pages * 4;
    let total_kb = stats.total_pages * 4;
    let used_kb = total_kb - free_kb;
    crate::shell::tty::write(
        format!("mem: used={used_kb} KiB  free={free_kb} KiB  total={total_kb} KiB\r\n").as_bytes(),
    );
}

fn cmd_info_proc() {
    crate::shell::tty::write(b"PID   PPID  STATE       NAME\r\n");
    crate::proc::table::for_each(|p| {
        crate::shell::tty::write(
            format!(
                "  {:4}  {:4}  {:<10?}  {}\r\n",
                p.pid, p.ppid, p.state, p.name
            )
            .as_bytes(),
        );
    });
}

/// Walk frame pointers from the current rbp / s0.
/// Requires compilation with `-C force-frame-pointers=yes` in RUSTFLAGS.
fn cmd_bt() {
    let mut fp: usize;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) fp, options(nostack))
    };
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv {}, s0",  out(reg) fp, options(nostack))
    };

    crate::shell::tty::write(b"backtrace:\r\n");
    let mut depth = 0usize;
    while fp != 0 && depth < 32 {
        // On both x86_64 and RISC-V with the standard frame layout:
        //   [fp - 8]  = return address
        //   [fp - 16] = saved previous fp
        let ra = unsafe { *((fp as *const usize).wrapping_sub(1)) };
        let pfp = unsafe { *((fp as *const usize).wrapping_sub(2)) };
        crate::shell::tty::write(format!("  #{depth:02}  0x{ra:016x}\r\n").as_bytes());
        if pfp == fp {
            break;
        }
        fp = pfp;
        depth += 1;
    }
}

fn cmd_dump(mut parts: SplitWhitespace) {
    let addr = parts
        .next()
        .and_then(|s| usize::from_str_radix(s.trim_start_matches("0x"), 16).ok());
    let len = parts
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(64);

    let Some(addr) = addr else {
        crate::shell::tty::write(b"usage: dump <hex_addr> [len]\r\n");
        return;
    };

    let len = len.min(DUMP_MAX_LEN);
    if len == 0 {
        return;
    }

    if let Err(reason) = validate_kernel_dump_range(addr, len) {
        crate::shell::tty::write(
            format!("dump: refusing unsafe range 0x{addr:016x}+0x{len:x}: {reason}\r\n").as_bytes(),
        );
        return;
    }

    let rows = (len + 15) / 16;

    for row in 0..rows {
        let base = addr + row * 16;
        let cols = 16usize.min(len - row * 16);

        // Read each byte exactly once after the full range has been validated.
        let mut bytes = [0u8; 16];
        for i in 0..cols {
            bytes[i] = unsafe { core::ptr::read_volatile((base + i) as *const u8) };
        }

        let mut line = format!("{base:016x}: ");

        for b in &bytes[..cols] {
            line.push_str(&format!("{b:02x} "));
        }

        for _ in cols..16 {
            line.push_str("   ");
        }

        line.push_str(" |");
        for b in &bytes[..cols] {
            line.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        line.push_str("|\r\n");

        crate::shell::tty::write(line.as_bytes());
    }
}

fn validate_kernel_dump_range(addr: usize, len: usize) -> Result<(), &'static str> {
    let end_exclusive = addr.checked_add(len).ok_or("address overflow")?;
    let last = end_exclusive.checked_sub(1).ok_or("empty range")?;

    if !crate::arch::api::is_valid_addr(addr) || !crate::arch::api::is_valid_addr(last) {
        return Err("non-canonical virtual address");
    }

    let kva = crate::arch::api::kernel_va_range();
    if !kva.contains(&addr) || !kva.contains(&last) {
        return Err("outside kernel virtual-address range");
    }

    let cr3 = <crate::arch::Arch as crate::arch::api::Paging>::kernel_cr3();

    let mut page = align_down(addr, PAGE_SIZE);
    let last_page = align_down(last, PAGE_SIZE);

    loop {
        if <crate::arch::Arch as crate::arch::api::Paging>::virt_to_phys(cr3, page).is_none() {
            return Err("unmapped kernel virtual page");
        }

        if page == last_page {
            break;
        }

        page = page.checked_add(PAGE_SIZE).ok_or("page walk overflow")?;
    }

    Ok(())
}

#[inline]
const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn print_help() {
    crate::shell::tty::write(
        b"debug shell commands:\r\n\
          \x20 info mem              -- physical memory stats\r\n\
          \x20 info proc             -- process table\r\n\
          \x20 bt                    -- stack backtrace (needs -C force-frame-pointers=yes)\r\n\
          \x20 dump <hex_addr> [len] -- hex dump len bytes (default 64) from addr\r\n\
          \x20 help                  -- this message\r\n",
    );
}