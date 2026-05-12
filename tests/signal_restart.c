/* tests/signal_restart.c
 *
 * Smoke: sigaction SA_RESTART + SIGCHLD delivery + sigprocmask.
 *
 * Blocks SIGCHLD, forks a child that exits immediately, then unblocks.
 * The parent waits via sigsuspend() for handler delivery and confirms
 * clean child exit via waitpid().
 * Targets signal delivery / SA_RESTART (src/proc/signal.rs).
 */
#define _GNU_SOURCE
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include "test_helpers.h"

static volatile sig_atomic_t got_sigchld = 0;

static void sigchld_handler(int sig) { (void)sig; got_sigchld = 1; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    TEST_SYSCALL(sigaction(SIGCHLD, &sa, NULL), "sigaction");

    sigset_t mask, oldmask, empty;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    TEST_SYSCALL(sigprocmask(SIG_BLOCK, &mask, &oldmask), "sigprocmask block");

    pid_t pid = fork();
    TEST_SYSCALL((int)pid, "fork");
    if (pid == 0) _exit(0);

    TEST_SYSCALL(sigprocmask(SIG_SETMASK, &oldmask, NULL), "sigprocmask restore");

    sigemptyset(&empty);
    while (!got_sigchld)
        sigsuspend(&empty);

    int status;
    TEST_SYSCALL((int)waitpid(pid, &status, 0), "waitpid");

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        TEST_FAIL("child exited abnormally");

    TEST_PASS();
}
