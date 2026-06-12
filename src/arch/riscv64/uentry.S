# RISC-V user-entry trampoline section.
#
# This translation unit exists to provide a dedicated `.uentry` ELF
# section that the linker script can place adjacent to (but distinct
# from) the `.trampoline` section in `trampoline.S`. The Rust side in
# `arch/riscv64/uentry.rs` and `arch/riscv64/trampoline.rs` performs the
# actual S→U mode transition through the `_trampoline_start` /
# `_trampoline_end` window; the symbols below give the kernel a way to
# refer to this object file's image in linker scripts and in
# `cargo:rustc-link-lib=static=uentry_riscv64` (see `build.rs`).
#
# Keep this file minimal: any executable user-mode entry asm lives in
# `trampoline.S`. Adding code here without coordinating section
# placement in the linker script will lead to relocation surprises.

    .section .uentry, "ax"
    .balign 4096
    .globl _uentry_start
_uentry_start:

    # Placeholder NOP. The trampoline page (trampoline.S) carries the
    # real `uservec` / `userret` body; this slot is reserved for a
    # future per-process user-entry stub when we move stack zeroing /
    # GPR scrub out of the Rust `jump_to_user` path on RISC-V.
    nop

    .balign 4096
    .globl _uentry_end
_uentry_end:
