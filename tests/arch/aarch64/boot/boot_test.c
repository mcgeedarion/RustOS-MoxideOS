/* tests/arch/aarch64/boot/boot_test.c
 *
 * AArch64 boot validation.
 *
 * Checks serial log for markers emitted by the AArch64 boot path:
 *   BOOT_OK        – EL2 -> EL1 drop and kernel entry completed
 *   MAIR_OK        – MAIR_EL1 / TCR_EL1 configured
 *   TTBR_OK        – TTBR0/TTBR1 page tables active
 *   VBAR_OK        – VBAR_EL1 exception vector table installed
 *
 * Expected serial output from src/arch/aarch64/boot/.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing aarch64 boot marker: %s", marker);
}

int main(int argc, char **argv) {
    const char *log_path = argc > 1 ? argv[1] : "logs/aarch64/serial.log";

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
    check_marker(log, "MAIR_OK");
    check_marker(log, "TTBR_OK");
    check_marker(log, "VBAR_OK");

    free(log);
    TEST_PASS();
}
