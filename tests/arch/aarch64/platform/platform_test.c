/* tests/arch/aarch64/platform/platform_test.c
 *
 * AArch64 platform abstraction validation.
 *
 * Checks serial log for platform markers:
 *   PLATFORM_OK    – platform_init() returned success
 *   SERIAL_OK      – PL011 UART initialised
 *   PSCI_OK        – PSCI firmware interface detected
 *   FDT_OK         – Flattened Device Tree parsed, /memory node found
 *
 * Expected serial output from src/arch/aarch64/platform/.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing aarch64 platform marker: %s", marker);
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

    check_marker(log, "PLATFORM_OK");
    check_marker(log, "SERIAL_OK");
    check_marker(log, "PSCI_OK");
    check_marker(log, "FDT_OK");

    free(log);
    TEST_PASS();
}
