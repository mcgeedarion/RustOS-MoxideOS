/* tests/shared/fork_exec_wait.c
 *
 * Smoke: fork / execve / waitpid round-trip.
 */
#define _GNU_SOURCE
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "test_helpers.h"

int main(void) {
    pid_t pid = fork();
    TEST_SYSCALL(pid, "fork");
    if (pid == 0) {
        char *argv[] = { "/bin/true", NULL };
        char *envp[] = { NULL };
        execve("/bin/true", argv, envp);
        execve("/usr/bin/true", argv, envp);
        _exit(127);
    }
    int status;
    pid_t r = waitpid(pid, &status, 0);
    TEST_SYSCALL((int)r, "waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        TEST_FAILF("child exited with status %d", WEXITSTATUS(status));
    TEST_PASS();
}
