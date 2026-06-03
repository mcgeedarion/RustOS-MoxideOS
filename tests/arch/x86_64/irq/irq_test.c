/* tests/arch/x86_64/irq/irq_test.c
 *
 * x86_64 interrupt handling validation.
 *
 * Checks serial log for IRQ markers emitted by the x86_64 interrupt path:
 *   IRQ_INIT_OK    – IDT fully populated, APIC unmasked
 *   TIMER_IRQ_OK   – first APIC timer tick received
 *   SPURIOUS_OK    – spurious vector handler installed
 *   SYSCALL_OK     – SYSCALL/SYSRET MSRs configured
 *
 * Expected serial output from src/arch/x86_64/interrupts/.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing irq marker: %s", marker);
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

    check_marker(log, "IRQ_INIT_OK");
    check_marker(log, "TIMER_IRQ_OK");
    check_marker(log, "SPURIOUS_OK");
    check_marker(log, "SYSCALL_OK");

    free(log);
    TEST_PASS();
}
