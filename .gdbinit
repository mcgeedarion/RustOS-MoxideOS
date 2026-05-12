# rustos kernel debugger init
# Usage:
#   gdb                     # connects to a running run_qemu.sh --gdb session
#   gdb -ex 'source .gdbinit'
#
# Requires: run_qemu.sh --gdb (adds -s -S to QEMU, halts at startup)

set pagination off
set disassembly-flavor intel
set print pretty on
set print array on

file target/x86_64-unknown-none/debug/rustos

set architecture i386:x86-64

target remote :1234

# Uncomment to break at kernel entry and panic handler automatically.
# break kernel_main
# break rust_begin_unwind

define procs
  printf "%-4s %-6s %-6s %-6s %-8s %-18s %s\n", \
    "idx", "pid", "ppid", "tgid", "state", "pc", "sp"
  printf "%-4s %-6s %-6s %-6s %-8s %-18s %s\n", \
    "---", "------", "------", "------", "--------", "------------------", "------------------"
  set $__procs_ptr  = rustos::proc::scheduler::SCHED.lock.data.procs.buf.ptr.pointer
  set $__procs_len  = rustos::proc::scheduler::SCHED.lock.data.procs.len
  set $__i = 0
  while $__i < $__procs_len
    set $__p = $__procs_ptr[$__i]
    set $__state = $__p.state
    if $__state == 0
      set $__sname = "Ready"
    end
    if $__state == 1
      set $__sname = "Running"
    end
    if $__state == 2
      set $__sname = "Blocked"
    end
    if $__state == 3
      set $__sname = "Zombie"
    end
    printf "%-4d %-6d %-6d %-6d %-8s 0x%016lx 0x%016lx\n", \
      $__i, $__p.pid, $__p.ppid, $__p.tgid, $__sname, $__p.pc, $__p.sp
    set $__i = $__i + 1
  end
end
document procs
Print a summary table of all PCBs in the scheduler run queue.
Columns: index, pid, ppid, tgid, state, saved user-mode pc, saved sp.
end

# pcb N -- pretty-print PCB at index N
define pcb
  set $__p = rustos::proc::scheduler::SCHED.lock.data.procs.buf.ptr.pointer[$arg0]
  printf "PCB[%d]\n", $arg0
  printf "  pid          = %d\n",    $__p.pid
  printf "  ppid         = %d\n",    $__p.ppid
  printf "  tgid         = %d\n",    $__p.tgid
  printf "  exit_code    = %d\n",    $__p.exit_code
  printf "  user_satp    = 0x%lx\n", $__p.user_satp
  printf "  pc           = 0x%lx\n", $__p.pc
  printf "  sp           = 0x%lx\n", $__p.sp
  printf "  kstack_top   = 0x%lx\n", $__p.kstack_top
  printf "  brk          = 0x%lx\n", $__p.brk
  printf "  next_va      = 0x%lx\n", $__p.next_va
  printf "  vfork_parent = %d\n",    $__p.vfork_parent
  printf "  exit_signal  = %d\n",    $__p.exit_signal
end
document pcb
pcb N -- print detailed fields of PCB at scheduler run-queue index N.
Use `procs` first to find the index for a given pid.
end

define kbt
  set $__rsp = $rsp
  printf "kernel stack backtrace from rsp=0x%lx:\n", $__rsp
  set $__n = 0
  while $__n < 32
    set $__slot = *(unsigned long*)($__rsp + $__n * 8)
    if $__slot > 0x400000 && $__slot < 0x10000000
      info symbol $__slot
    end
    set $__n = $__n + 1
  end
end
document kbt
Scan 32 stack slots from RSP and print symbol names for plausible
kernel return addresses (VA in [0x400000, 0x10000000)).
Faster than `bt` when DWARF unwind info is missing.
end

printf "[gdbinit] rustos kernel debugger ready. Type `procs` to list processes.\n"
