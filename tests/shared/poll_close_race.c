/* tests/shared/poll_close_race.c
 *
 * Stress: poll(2) vs close(2) race on the same fd.
 */
#define _GNU_SOURCE
#include <poll.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include "test_helpers.h"

#define ITERS 512

static int rfd = -1, wfd = -1;
static atomic_int stop = 0;

static void *poller(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        int fd = rfd;
        if (fd < 0) continue;
        struct pollfd pf = { .fd = fd, .events = POLLIN };
        poll(&pf, 1, 1);
    }
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, poller, NULL);
    for (int i = 0; i < ITERS; i++) {
        int pfd[2];
        TEST_SYSCALL(pipe(pfd), "pipe");
        rfd = pfd[0]; wfd = pfd[1];
        write(wfd, "x", 1);
        close(wfd); wfd = -1;
        close(rfd); rfd = -1;
    }
    atomic_store(&stop, 1);
    pthread_join(t, NULL);
    TEST_PASS();
}
