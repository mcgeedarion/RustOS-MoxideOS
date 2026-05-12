/* tests/signal_restart.c
 *
 * Tests:
 *   - sigaction with SA_RESTART
 *   - SIGCHLD delivery and handler invocation
 *   - sigprocmask (block/unblock)
 *
 * Output: PASS / FAIL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdatomic.h>

static volatile sig_atomic_t got_sigchld = 0;

static void sigchld_handler(int sig) { (void)sig; got_sigchld = 1; }

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) != 0) { perror("sigaction"); return 1; }

    /* Block SIGCHLD, fork, unblock → handler must fire */
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, &oldmask) != 0) { perror("sigprocmask"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) { _exit(0); }

    /* Unblock — pending SIGCHLD should be delivered */
    if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0) { perror("sigprocmask restore"); return 1; }

    /* Spin briefly for delivery */
    for (int i = 0; i < 100000 && !got_sigchld; i++) ;

    int status;
    waitpid(pid, &status, 0);

    if (!got_sigchld) { puts("FAIL SIGCHLD not delivered"); return 1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { puts("FAIL child exit"); return 1; }

    puts("PASS");
    return 0;
}
