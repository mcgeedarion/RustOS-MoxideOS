// userspace/smoke/smoke.c
// Minimal QEMU smoke-test helper.
//
// Responsibilities:
//   - Print a well-known marker to the serial console.
//   - Exit(0) on success.
//   - Kept deliberately tiny so it is safe to run very early in boot.
//
// This is invoked from init(8) or a simple shell script during
// CI/QEMU smoke tests; see run_qemu_x86_64.sh --smoke.

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    // Flush stdio directly to the serial console.
    printf("SMOKE OK: userspace_smoke\n");
    fflush(stdout);

    // In the future this can grow basic invariants, e.g.:
    //   - verify getpid() == 2 or higher
    //   - check /proc/1 exists
    //   - open("/dev/null")
    (void)getpid();

    return 0;
}
