/* tests/arch/riscv64/irq/irq_test.c
 *
 * RISC-V 64 interrupt handling validation.
 *
 * Checks serial log for IRQ markers:
 *   IRQ_INIT_OK    – PLIC initialised, S-mode external IRQ unmasked
 *   TIMER_IRQ_OK   – first SBI timer interrupt (STIP) received
 *   SOFT_IRQ_OK    – software interrupt (SSIP) self-IPI round-trips
 *   ECALL_OK       – ecall trap handler installed and dispatches correctly
 *
 * Expected serial output from src/arch/riscv64/interrupts/.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../shared/test_helpers.h"

static void check_marker(const char *log, const char *marker) {
    if (!strstr(log, marker))
        TEST_FAILF("missing riscv64 irq marker: %s", marker);
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

    check_marker(log, "IRQ_INIT_OK");
    check_marker(log, "TIMER_IRQ_OK");
    check_marker(log, "SOFT_IRQ_OK");
    check_marker(log, "ECALL_OK");

    free(log);
    TEST_PASS();
}
