/* tests/poll_close_race.c
 *
 * Stress: poll(2) vs concurrent write-end close.
 *
 * Thread 1 calls poll() on the read end of a pipe (2s timeout).
 * Thread 2 spins until the poller is ready, then closes the write end.
 * Expected result: poll() returns POLLHUP (or EBADF) — not a hang.
 * Targets poll_wakeup / POLLHUP in src/fs/poll.rs and src/fs/pipe.rs.
 */
#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include "test_helpers.h"

static int        pfd[2];
static atomic_int poller_ready = 0;

static void *closer(void *arg) {
    (void)arg;
    while (!atomic_load(&poller_ready))
        sched_yield();
    usleep(5000); /* let poll() enter kernel before the close */
    close(pfd[1]);
    return NULL;
}

int main(void) {
    TEST_SYSCALL(pipe(pfd), "pipe");

    pthread_t t;
    pthread_create(&t, NULL, closer, NULL);

    struct pollfd pf = { .fd = pfd[0], .events = POLLIN | POLLHUP };
    atomic_store(&poller_ready, 1);
    int r = poll(&pf, 1, 2000);

    pthread_join(t, NULL);
    close(pfd[0]);

    if (r == 0)
        TEST_FAIL("poll timed out — likely hung");
    if (r < 0 && errno != EBADF)
        TEST_FAILF("poll error: %s", strerror(errno));
    if (r > 0 && !(pf.revents & (POLLHUP | EBADF)))
        TEST_FAILF("unexpected revents=0x%x", pf.revents);

    TEST_PASS();
}
