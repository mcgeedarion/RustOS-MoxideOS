/* tests/arch/x86_64/platform/platform_test.c
 *
 * x86_64 platform abstraction validation.
 *
 * Checks serial log for platform markers:
 *   PLATFORM_OK    – platform_init() returned success
 *   SERIAL_OK      – COM1 UART initialised
 *   HPET_OK        – HPET or PIT timer source configured
 *   ACPI_OK        – ACPI tables parsed, MADT found
 *
 * Expected serial output from src/arch/x86_64/platform/.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing platform marker: %s", marker);
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

    check_marker(log, "PLATFORM_OK");
    check_marker(log, "SERIAL_OK");
    check_marker(log, "HPET_OK");
    check_marker(log, "ACPI_OK");

    free(log);
    TEST_PASS();
}
