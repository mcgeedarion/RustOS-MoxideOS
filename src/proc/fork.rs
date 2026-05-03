//! fork() and execve() for the x86_64 kernel.
//!
//! # fork
//! Creates a child PCB that is a near-copy of the parent.
//! Page tables are cloned with **copy-on-write (COW)** semantics:
//!   - Shared pages are marked read-only in both parent and child PTEs.
//!   - On a write-fault (page fault, error code bit 1 set), the faulting
//!     process gets a private writable copy and the shared reference count
//!     is decremented.
//!
//! # execve
//! Replaces the current process image:
//!   1. Free all owned pages + page tables.
//!   2. Allocate a fresh CR3.
//!   3. Load the ELF64 binary from the VFS.
//!   4. Build a new user stack with argv/envp.
//!   5. Reset the syscall return frame so the next SYSRET enters the binary.

extern crate alloc;
use alloc::vec::Vec;

use crate::mm::pmm::{self, PAGE_SIZE};
use crate::proc::process::{Pcb, State};
use crate::proc::context::Context;
use crate::proc::scheduler;
use crate::arch::x86_64::paging as pg;
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::security::CapSet;

const COW_TABLE_SIZE: usize = 65536;
static mut COW_REFCNT: [u8; COW_TABLE_SIZE] = [0u8; COW_TABLE_SIZE];

fn cow_idx(pa: usize) -> Option<usize> {
    let idx = pa / PAGE_SIZE;
    if idx < COW_TABLE_SIZE { Some(idx) } else { None }
}

pub fn cow_inc(pa: usize) {
    if let Some(i) = cow_idx(pa) {
        unsafe { COW_REFCNT[i] = COW_REFCNT[i].saturating_add(1); }
    }
}

pub fn cow_dec(pa: usize) -> bool {
    if let Some(i) = cow_idx(pa) {
        unsafe {
            if COW_REFCNT[i] > 0 { COW_REFCNT[i] -= 1; }
            return COW_REFCNT[i] == 0;
        }
    }
    true
}

pub fn cow_count(pa: usize) -> u8 {
    cow_idx(pa).map_or(0, |i| unsafe { COW_REFCNT[i] })
}

pub fn do_fork(parent_frame: &mut SyscallFrame) -> isize {
    let parent_pid = scheduler::current_pid();
    if parent_pid == 0 { return -1; }
    let child_pid = scheduler::next_pid();

    let mut child = {
        let procs = scheduler::procs_lock();
        let parent = match procs.iter().find(|p| p.pid == parent_pid) {
            Some(p) => p, None => return -1,
        };
        Pcb {
            pid: child_pid, ppid: parent_pid, state: State::Ready,
            exit_code: 0, caps: parent.caps,
            pc: parent.pc, sp: parent.sp,
            kernel_satp: 0, user_satp: 0, trapframe_pa: 0,
            ctx: Context::zero(), kstack_top: 0,
            owned_pages: Vec::new(),
        }
    };

    for _ in 0..4 {
        let pa = match pmm::alloc_page() { Some(p) => p, None => return -12 };
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        child.kstack_top = pa + PAGE_SIZE;
        child.owned_pages.push(pa);
    }

    let child_cr3 = match pmm::alloc_page() { Some(p) => p, None => return -12 };
    unsafe { core::ptr::write_bytes(child_cr3 as *mut u8, 0, PAGE_SIZE); }
    child.owned_pages.push(child_cr3);
    pg::install_kernel_entries(child_cr3);

    {
        let procs = scheduler::procs_lock();
        if let Some(parent) = procs.iter().find(|p| p.pid == parent_pid) {
            cow_clone_pml4(parent.user_satp, child_cr3, &mut child.owned_pages);
        }
    }

    child.user_satp   = child_cr3;
    child.kernel_satp = child_cr3;

    let child_rsp0 = child.kstack_top as *mut u64;
    let frame_size = core::mem::size_of::<SyscallFrame>() / 8;
    let child_frame_ptr = unsafe { child_rsp0.sub(frame_size) };
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame as *const SyscallFrame as *const u64,
            child_frame_ptr, frame_size,
        );
        let child_frame = &mut *(child_frame_ptr as *mut SyscallFrame);
        child_frame.rax = 0;
    }

    child.ctx.rsp = child_frame_ptr as usize;
    child.ctx.rip = sysret_trampoline as usize;
    child.trapframe_pa = child.kstack_top;
    scheduler::enqueue(child);
    child_pid as isize
}

#[naked]
unsafe extern "C" fn sysret_trampoline() {
    core::arch::asm!(
        "pop r11", "pop rcx", "pop r9", "pop r8", "pop r10",
        "pop rdx", "pop rsi", "pop rdi", "pop rax",
        "pop rbx", "pop rbp", "pop r12", "pop r13", "pop r14", "pop r15",
        "pop rsp", "swapgs", "sysretq",
        options(noreturn)
    );
}

fn cow_clone_pml4(parent_cr3: usize, child_cr3: usize, child_owned: &mut Vec<usize>) {
    let pml4 = parent_cr3 as *mut u64;
    for pml4i in 0usize..256 {
        let pml4e = unsafe { pml4.add(pml4i).read_volatile() };
        if pml4e & 1 == 0 { continue; }
        let child_pdpt_pa = alloc_pt(child_owned);
        unsafe {
            (child_cr3 as *mut u64).add(pml4i)
                .write_volatile((child_pdpt_pa as u64 & !0xFFF) | (pml4e & 0xFFF));
        }
        let pdpt = (pml4e & !0xFFF) as *mut u64;
        let child_pdpt = child_pdpt_pa as *mut u64;
        for pdpti in 0usize..512 {
            let pdpte = unsafe { pdpt.add(pdpti).read_volatile() };
            if pdpte & 1 == 0 { continue; }
            let child_pd_pa = alloc_pt(child_owned);
            unsafe {
                child_pdpt.add(pdpti)
                    .write_volatile((child_pd_pa as u64 & !0xFFF) | (pdpte & 0xFFF));
            }
            let pd = (pdpte & !0xFFF) as *mut u64;
            let child_pd = child_pd_pa as *mut u64;
            for pdi in 0usize..512 {
                let pde = unsafe { pd.add(pdi).read_volatile() };
                if pde & 1 == 0 { continue; }
                if pde & (1 << 7) != 0 {
                    let pa = (pde & !0xFFF) as usize;
                    cow_inc(pa);
                    let ro_pde = pde & !(1 << 1);
                    unsafe { pd.add(pdi).write_volatile(ro_pde); child_pd.add(pdi).write_volatile(ro_pde); }
                    continue;
                }
                let child_pt_pa = alloc_pt(child_owned);
                unsafe {
                    child_pd.add(pdi)
                        .write_volatile((child_pt_pa as u64 & !0xFFF) | (pde & 0xFFF));
                }
                let pt = (pde & !0xFFF) as *mut u64;
                let child_pt = child_pt_pa as *mut u64;
                for pti in 0usize..512 {
                    let pte = unsafe { pt.add(pti).read_volatile() };
                    if pte & 1 == 0 { continue; }
                    let pa = (pte & !0xFFF) as usize;
                    cow_inc(pa);
                    let ro_pte = pte & !(1 << 1);
                    unsafe { pt.add(pti).write_volatile(ro_pte); child_pt.add(pti).write_volatile(ro_pte); }
                }
            }
        }
    }
    pg::flush_all();
}

fn alloc_pt(owned: &mut Vec<usize>) -> usize {
    let pa = pmm::alloc_page().expect("OOM: COW page table");
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    owned.push(pa);
    pa
}

pub fn do_execve(
    path_va:  usize,
    argv_va:  usize,
    envp_va:  usize,
    frame:    &mut crate::arch::x86_64::interrupts::SyscallFrame,
) -> isize {
    use crate::uaccess::strncpy_from_user;
    extern crate alloc;
    use alloc::{string::String, vec::Vec};

    let mut pbuf = [0u8; 512];
    let plen = match unsafe { strncpy_from_user(&mut pbuf, path_va as *const u8, 512) } {
        Ok(n) => n, Err(_) => return -14,
    };
    let path = match core::str::from_utf8(&pbuf[..plen]) { Ok(s) => s, Err(_) => return -2 };

    let argv = copy_string_array(argv_va, 256);
    let envp = copy_string_array(envp_va, 256);

    let elf_data = match read_binary(path) { Some(d) => d, None => return -2 };

    let new_cr3 = match pmm::alloc_page() { Some(p) => p, None => return -12 };
    unsafe { core::ptr::write_bytes(new_cr3 as *mut u8, 0, PAGE_SIZE); }
    pg::install_kernel_entries(new_cr3);

    let mut load_result = match crate::loader::elf64::load(&elf_data, new_cr3) {
        Ok(r)  => r,
        Err(e) => {
            crate::serial_println!("[execve] ELF load failed: {}", e);
            pmm::free_page(new_cr3);
            return -8;
        }
    };

    let stack_top  = 0x7FFF_F000_0000usize;
    let stack_size = 8 * 1024 * 1024;
    let mut all_argv = Vec::new();
    all_argv.push(String::from(path));
    all_argv.extend(argv.into_iter().skip(1));

    let user_rsp = crate::loader::auxv::build(&crate::loader::auxv::AuxvParams {
        stack_top, stack_size,
        load: &load_result,
        argv: &all_argv,
        envp: &envp,
        execfn: path,
        cr3: new_cr3,
    });
    load_result.owned_pages.push(0);

    let pid = crate::proc::scheduler::current_pid();
    {
        let mut procs = crate::proc::scheduler::procs_lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            // Flush old VMA table before tearing down page tables
            crate::mm::mmap::clear_vmas(pid);
            for pa in p.owned_pages.drain(..) { if pa != 0 { pmm::free_page(pa); } }
            p.owned_pages = load_result.owned_pages;
            p.user_satp   = new_cr3;
            p.kernel_satp = new_cr3;
            p.pc          = load_result.entry;
            p.sp          = user_rsp;
        }
    }

    unsafe { core::arch::asm!("mov cr3, {}", in(reg) new_cr3, options(nostack)); }
    frame.rip = load_result.entry;
    frame.rsp = user_rsp;
    frame.rbp = 0;

    // Close FD_CLOEXEC descriptors
    crate::fs::fcntl::close_on_exec();

    0
}

fn read_binary(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let fd = crate::fs::vfs::open(path, 0).ok()?;
    let size = crate::fs::vfs::fstat(fd)? as usize;
    let mut buf = alloc::vec![0u8; size];
    crate::fs::vfs::read(fd, &mut buf);
    crate::fs::vfs::close(fd);
    Some(buf)
}

fn copy_string_array(va: usize, max: usize) -> alloc::vec::Vec<alloc::string::String> {
    let mut out = alloc::vec::Vec::new();
    if va == 0 { return out; }
    for i in 0..max {
        let ptr_va = va + i * 8;
        let str_va = unsafe { *(ptr_va as *const usize) };
        if str_va == 0 { break; }
        let mut buf = [0u8; 256];
        let len = match unsafe { crate::uaccess::strncpy_from_user(&mut buf, str_va as *const u8, 256) } {
            Ok(n) => n, Err(_) => break,
        };
        out.push(alloc::string::String::from(
            core::str::from_utf8(&buf[..len]).unwrap_or("")));
    }
    out
}
