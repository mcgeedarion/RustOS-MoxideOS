/* tests/arch/riscv64/mm/mm_test.c
 *
 * RISC-V 64 memory management validation.
 *
 * Checks serial log for MM markers:
 *   PMM_OK         – physical memory manager initialised
 *   VMM_OK         – Sv39 3-level page tables active
 *   HEAP_OK        – kernel heap allocator online
 *   COW_OK         – copy-on-write fault handler registered
 *
 * Expected serial output from src/mem/ on riscv64.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing riscv64 mm marker: %s", marker);
}

int main(int argc, char **argv) {
    const char *log_path = argc > 1 ? argv[1] : "logs/riscv64/serial.log";

    FILE *f = fopen(log_path, "r");
    if (!f) TEST_FAILF("cannot open %s", log_path);

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *log = malloc(sz + 1);
    fread(log, 1, sz, f);
    log[sz] = '\0';
    fclose(f);

    check_marker(log, "PMM_OK");
    check_marker(log, "VMM_OK");
    check_marker(log, "HEAP_OK");
    check_marker(log, "COW_OK");

    free(log);
    TEST_PASS();
}
