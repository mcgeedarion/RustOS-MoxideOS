/*
 * boot_test.c — x86_64 boot path smoke test.
 *
 * Checks that the kernel serial log contains the expected markers emitted
 * by the x86_64 boot path:
 *   BOOT_OK        – early UEFI entry completed
 *   GDT_OK         – GDT loaded, long-mode segments set
 *   IDT_OK         – IDT installed, exception stubs wired
 *   APIC_OK        – local APIC detected and mapped
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *EXPECTED[] = {
    "BOOT_OK",
    "GDT_OK",
    "IDT_OK",
    "APIC_OK",
    NULL,
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <serial-log-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    char line[512];
    int found[4] = {0};
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; EXPECTED[i]; i++) {
            if (strstr(line, EXPECTED[i])) found[i] = 1;
        }
    }
    fclose(f);

    int all_ok = 1;
    for (int i = 0; EXPECTED[i]; i++) {
        if (!found[i]) {
            fprintf(stderr, "FAIL: missing marker %s\n", EXPECTED[i]);
            all_ok = 0;
        }
    }

    if (all_ok) printf("PASS\n");
    return all_ok ? 0 : 1;
}
