#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

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

    sigset_t mask, oldmask, empty;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, &oldmask) != 0) { perror("sigprocmask"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) { _exit(0); }

    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0) { perror("sigprocmask restore"); return 1; }

    while (!got_sigchld)
        sigsuspend(&empty);

    int status;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        puts("FAIL child exit");
        return 1;
    }

    puts("PASS");
    return 0;
}
