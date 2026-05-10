/* tests/poll_close_race.c
 *
 * Stress test: poll(2) vs concurrent write-end close — the canonical
 * poll-vs-close race.
 *
 * Thread 1 calls poll() on the read end of a pipe with a 2s timeout.
 * Thread 2 sleeps briefly then closes the write end.
 * Expected: poll() returns with POLLHUP (or EBADF) — NOT a hang or panic.
 *
 * Targets the fd lifetime / wakeup path in src/fs/poll.rs and
 * the pipe_poll POLLHUP logic in src/fs/pipe.rs.
 */
#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdatomic.h>
#include <errno.h>
#include <sched.h>

static int pfd[2];
static atomic_int poller_ready = 0;

static void *closer(void *arg) {
    (void)arg;
    while (!atomic_load(&poller_ready)) sched_yield();
    usleep(5000); /* small delay so poller is inside poll() */
    close(pfd[1]); /* closing write end should deliver POLLHUP to reader */
    return NULL;
}

int main(void) {
    if (pipe(pfd) != 0) {
        write(2, "pipe() failed\n", 14);
        return 1;
    }

    pthread_t t;
    pthread_create(&t, NULL, closer, NULL);

    struct pollfd pf = { .fd = pfd[0], .events = POLLIN | POLLHUP };
    atomic_store(&poller_ready, 1);

    int r = poll(&pf, 1, 2000);

    pthread_join(t, NULL);
    close(pfd[0]);

    if (r < 0 && errno == EBADF) {
        write(1, "POLL_CLOSE PASS (EBADF)\n", 24);
        return 0;
    }
    if (r > 0 && (pf.revents & POLLHUP)) {
        write(1, "POLL_CLOSE PASS (POLLHUP)\n", 26);
        return 0;
    }
    if (r == 0) {
        write(2, "POLL_CLOSE FAIL: poll timed out (likely hung)\n", 46);
        return 1;
    }
    dprintf(2, "POLL_CLOSE FAIL: r=%d revents=0x%x errno=%d\n",
            r, pf.revents, errno);
    return 1;
}
