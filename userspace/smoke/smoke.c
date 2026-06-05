// userspace/smoke/smoke.c
// Minimal QEMU smoke-test helper.
//
// Responsibilities:
//   - Run basic userspace invariant checks.
//   - Print SMOKE OK on success, SMOKE FAIL:<name> on failure.
//   - Exit(0) on success, Exit(1) on any failure.
//   - Kept deliberately tiny so it is safe to run very early in boot.
//
// This is invoked from init(8) or a simple shell script during
// CI/QEMU smoke tests; see run_qemu_x86_64.sh --smoke.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static int check(const char *name, int ok) {
    if (!ok) fprintf(stderr, "SMOKE FAIL: %s\n", name);
    return ok;
}

int main(void) {
    int pass = 1;

    pass &= check("getpid >= 2", getpid() >= 2);
    pass &= check("/dev/null",   open("/dev/null", O_RDONLY) >= 0);

    if (pass)
        printf("SMOKE OK: userspace_smoke\n");
    fflush(stdout);
    return pass ? 0 : 1;
}
