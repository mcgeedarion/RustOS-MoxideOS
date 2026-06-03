/* tests/shared/signal_restart.c
 *
 * Stress: SA_RESTART syscall restart after signal.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "test_helpers.h"

static pid_t main_tid;
static int   pfd[2];

static void handler(int sig) { (void)sig; }

static void *sender(void *arg) {
    (void)arg;
    struct timespec ts = { .tv_nsec = 5 * 1000000L };
    nanosleep(&ts, NULL);
    for (int i = 0; i < 3; i++) {
        syscall(234, getpid(), main_tid, SIGUSR1);
        nanosleep(&ts, NULL);
    }
    write(pfd[1], "done", 4);
    return NULL;
}

int main(void) {
    main_tid = (pid_t)syscall(186);
    TEST_SYSCALL(pipe(pfd), "pipe");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags   = SA_RESTART;
    TEST_SYSCALL(sigaction(SIGUSR1, &sa, NULL), "sigaction");
    pthread_t t;
    pthread_create(&t, NULL, sender, NULL);
    char buf[8];
    ssize_t r = read(pfd[0], buf, sizeof(buf));
    if (r <= 0)
        TEST_FAILF("read returned %zd (errno=%d)", r, errno);
    pthread_join(t, NULL);
    close(pfd[0]); close(pfd[1]);
    TEST_PASS();
}
