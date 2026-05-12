/* tests/fork_exec_wait.c
 *
 * Smoke: fork() / waitpid() exit-status propagation.
 *
 * Spawns N_CHILDREN children that each call _exit(0). The parent
 * collects every child with waitpid() and verifies clean exit status.
 * Targets do_fork / do_waitpid / exit_status propagation
 * (src/proc/process.rs).
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include "test_helpers.h"

#define N_CHILDREN 8

int main(void) {
    pid_t pids[N_CHILDREN];

    for (int i = 0; i < N_CHILDREN; i++) {
        pid_t p = fork();
        TEST_SYSCALL((int)p, "fork");
        if (p == 0)
            _exit(0);
        pids[i] = p;
    }

    for (int i = 0; i < N_CHILDREN; i++) {
        int status;
        pid_t r = waitpid(pids[i], &status, 0);
        if (r != pids[i])
            TEST_FAILF("waitpid: got pid %d expected %d", (int)r, (int)pids[i]);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            TEST_FAILF("child %d bad exit status 0x%x", i, status);
    }

    TEST_PASS();
}
