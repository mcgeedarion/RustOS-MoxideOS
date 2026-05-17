/*
 * src/init/crt/crt0.c — Freestanding CRT shim for rustos kernel
 *
 * Compiled with -ffreestanding -nostdlib -nostartfiles.
 * No host libc is linked. These stubs satisfy linker references that
 * compilers may emit even in freestanding mode.
 */

/* Satisfy -fstack-protector linkage without pulling in libc. */
void __stack_chk_fail(void) {
    __builtin_trap();
}

/* Stub for C++ static destructor registration — we never unload the kernel. */
int __cxa_atexit(void (*f)(void *), void *arg, void *dso) {
    (void)f;
    (void)arg;
    (void)dso;
    return 0;
}

/* Called when a pure-virtual function is invoked — treat as fatal. */
void __cxa_pure_virtual(void) {
    __builtin_trap();
}

extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

void run_init_array(void) {
    for (void (**fn)(void) = __init_array_start; fn < __init_array_end; fn++) {
        (*fn)();
    }
}
