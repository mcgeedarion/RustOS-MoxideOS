/* tests/shared/epoll_basic.c
 *
 * Smoke: epoll_create1 / epoll_ctl / epoll_wait correctness.
 *
 * Verifies that a pipe read-end reports no events before data arrives
 * (0-timeout poll) and exactly one EPOLLIN event after a write.
 * Targets epoll_create1 / epoll_ctl / epoll_wait (src/fs/epoll.rs).
 */
#define _GNU_SOURCE
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include "test_helpers.h"

int main(void) {
    int pipefd[2];
    TEST_SYSCALL(pipe(pipefd), "pipe");

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST_SYSCALL(epfd, "epoll_create1");

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = pipefd[0] };
    TEST_SYSCALL(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev), "epoll_ctl");

    /* No data yet — 0-timeout must return 0 events. */
    struct epoll_event events[4];
    int n = epoll_wait(epfd, events, 4, 0);
    if (n != 0)
        TEST_FAILF("expected 0 events before write, got %d", n);

    /* Write one byte — now readable. */
    TEST_SYSCALL((int)write(pipefd[1], "x", 1) - 1, "write");

    n = epoll_wait(epfd, events, 4, 100);
    if (n != 1)
        TEST_FAILF("expected 1 event after write, got %d", n);
    if (events[0].data.fd != pipefd[0])
        TEST_FAIL("wrong fd in epoll event");

    char buf[4];
    read(pipefd[0], buf, sizeof(buf));

    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);
    TEST_PASS();
}
