/* tests/arch/riscv64/boot/boot_test.c
 *
 * RISC-V 64 boot validation.
 *
 * Checks serial log for markers emitted by the RISC-V boot path:
 *   BOOT_OK        – SBI M-mode -> S-mode handoff completed
 *   SATP_OK        – satp CSR written, Sv39 paging active
 *   STVEC_OK       – stvec trap vector installed
 *   SBI_OK         – SBI base extension probed successfully
 *
 * Expected serial output from src/arch/riscv64/boot/.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing riscv64 boot marker: %s", marker);
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

    check_marker(log, "BOOT_OK");
    check_marker(log, "SATP_OK");
    check_marker(log, "STVEC_OK");
    check_marker(log, "SBI_OK");

    free(log);
    TEST_PASS();
}
