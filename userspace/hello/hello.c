/*
 * userspace/hello/hello.c — minimal smoke-test binary for rustos
 *
 * Writes "Hello from rustos userspace!" to stdout and exits.
 * Used to verify that:
 *   - elf64::load() maps PT_LOAD segments correctly
 *   - auxv / initial stack is set up correctly by write_initial_stack()
 *   - SYS_write and SYS_exit syscalls are dispatched correctly
 *
 * Build:
 *   musl-gcc -static -O2 -o build/x86_64/hello hello/hello.c
 */

#include <unistd.h>
#include <stdlib.h>

int main(void) {
    const char msg[] = "Hello from rustos userspace!\n";
    write(1, msg, sizeof(msg) - 1);
    exit(0);
}
