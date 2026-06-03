/* tests/arch/x86_64/boot/boot_test.c
 *
 * x86_64 boot validation.
 *
 * Checks that the kernel serial log contains the expected markers emitted
 * by the x86_64 boot path:
 *   BOOT_OK        – early UEFI/multiboot2 entry completed
 *   GDT_OK         – GDT loaded, long-mode segments set
 *   IDT_OK         – IDT installed, exception stubs wired
 *   APIC_OK        – local APIC detected and mapped
 *
 * This test is compiled on the host and run by scripts/ci/collect-logs.sh
 * against logs/x86_64/serial.log produced by the QEMU run.
 *
 * Build: cc -o boot_test boot_test.c ../../../shared/test_helpers.h
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing boot marker: %s", marker);
}

int main(int argc, char **argv) {
    const char *log_path = argc > 1 ? argv[1] : "logs/x86_64/serial.log";

    FILE *f = fopen(log_path, "r");
    if (!f) TEST_FAILF("cannot open %s", log_path);

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *log = malloc(sz + 1);
    fread(log, 1, sz, f);
    log[sz] = '\0';
    fclose(f);

    check_marker(log, "BOOT_OK");
    check_marker(log, "GDT_OK");
    check_marker(log, "IDT_OK");
    check_marker(log, "APIC_OK");

    free(log);
    TEST_PASS();
}
