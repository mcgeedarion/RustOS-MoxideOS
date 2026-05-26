# RISC-V user-mode trampoline.
#
# Mapped at TRAMPOLINE_VADDR (0xFFFF_FFFF_FFFF_F000) in both the kernel
# page table and every user page table, so it is reachable across satp
# switches.
#
# TrapFrame layout (offsets must match trap.rs TrapFrame exactly):
#   0   ra      8   sp     16  gp     24  tp
#   32  t0      40  t1     48  t2
#   56  s0      64  s1
#   72  a0      80  a1     88  a2     96  a3
#  104  a4     112  a5    120  a6    128  a7
#  136  s2  ... 208 s11
#  216  t3  ... 240 t6
#  248  sepc   256  sstatus
#
# Save area appended after the 272-byte TrapFrame (kernel fills before sret):
#  272  kernel_satp  (slot 34)
#  280  kernel_sp    (slot 35)
#  288  kernel_trap  (slot 36)  VA of riscv_trap_entry
#  296  user_satp    (slot 37)
#  304  hartid       (slot 38)  -> restored into tp

.section .trampoline, "ax"
.balign 4096
.globl _trampoline_start
_trampoline_start:

# ── uservec ────────────────────────────────────────────────────────────────
# Called on every U-mode trap.  stvec points here.
# sscratch = TRAPFRAME_VADDR (per-process trapframe page VA).
.globl uservec
uservec:
    # Exchange a0 with sscratch: a0 = trapframe VA, sscratch = user a0.
    csrrw a0, sscratch, a0

    # Save all user GPRs.
    sd ra,    0*8(a0)
    sd sp,    1*8(a0)
    sd gp,    2*8(a0)
    sd tp,    3*8(a0)
    sd t0,    4*8(a0)
    sd t1,    5*8(a0)
    sd t2,    6*8(a0)
    sd s0,    7*8(a0)
    sd s1,    8*8(a0)
    # Recover original a0 from sscratch and save it.
    csrr t0, sscratch
    sd t0,    9*8(a0)        # a0
    sd a1,   10*8(a0)
    sd a2,   11*8(a0)
    sd a3,   12*8(a0)
    sd a4,   13*8(a0)
    sd a5,   14*8(a0)
    sd a6,   15*8(a0)
    sd a7,   16*8(a0)
    sd s2,   17*8(a0)
    sd s3,   18*8(a0)
    sd s4,   19*8(a0)
    sd s5,   20*8(a0)
    sd s6,   21*8(a0)
    sd s7,   22*8(a0)
    sd s8,   23*8(a0)
    sd s9,   24*8(a0)
    sd s10,  25*8(a0)
    sd s11,  26*8(a0)
    sd t3,   27*8(a0)
    sd t4,   28*8(a0)
    sd t5,   29*8(a0)
    sd t6,   30*8(a0)

    # Save sepc and sstatus.
    csrr t0, sepc
    sd t0,   31*8(a0)        # sepc
    csrr t0, sstatus
    sd t0,   32*8(a0)        # sstatus

    # Load kernel bootstrap values from save area.
    ld t0, 34*8(a0)          # kernel_satp
    ld sp, 35*8(a0)          # kernel_sp
    ld t1, 36*8(a0)          # kernel_trap (VA of riscv_trap_entry)
    ld tp, 38*8(a0)          # hartid -> tp

    # Switch to kernel page table and flush TLB.
    csrw satp, t0
    sfence.vma zero, zero

    # a0 = trapframe VA; matches riscv_trap_entry's *mut TrapFrame argument.
    jr t1

# ── userret ────────────────────────────────────────────────────────────────
# Called by the kernel before returning to user mode.
# a0 = TRAPFRAME_VADDR (user VA of trapframe page)
# a1 = user satp value
.globl userret
userret:
    # Switch to user page table.
    csrw satp, a1
    sfence.vma zero, zero

    # Reload sscratch with trapframe VA so next uservec can find it.
    csrw sscratch, a0

    # Restore sepc and sstatus.
    ld t0, 31*8(a0)          # sepc
    csrw sepc, t0
    ld t0, 32*8(a0)          # sstatus
    csrw sstatus, t0

    # Restore all GPRs except a0 (last).
    ld ra,   0*8(a0)
    ld sp,   1*8(a0)
    ld gp,   2*8(a0)
    ld tp,   3*8(a0)
    ld t0,   4*8(a0)
    ld t1,   5*8(a0)
    ld t2,   6*8(a0)
    ld s0,   7*8(a0)
    ld s1,   8*8(a0)
    ld a1,  10*8(a0)
    ld a2,  11*8(a0)
    ld a3,  12*8(a0)
    ld a4,  13*8(a0)
    ld a5,  14*8(a0)
    ld a6,  15*8(a0)
    ld a7,  16*8(a0)
    ld s2,  17*8(a0)
    ld s3,  18*8(a0)
    ld s4,  19*8(a0)
    ld s5,  20*8(a0)
    ld s6,  21*8(a0)
    ld s7,  22*8(a0)
    ld s8,  23*8(a0)
    ld s9,  24*8(a0)
    ld s10, 25*8(a0)
    ld s11, 26*8(a0)
    ld t3,  27*8(a0)
    ld t4,  28*8(a0)
    ld t5,  29*8(a0)
    ld t6,  30*8(a0)
    ld a0,   9*8(a0)         # a0 last

    sret

.globl _trampoline_end
_trampoline_end:
