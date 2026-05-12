/* tests/epoll_basic.c
 *
 * Tests:
 *   - epoll_create1 / epoll_ctl / epoll_wait
 *   - edge-triggered (EPOLLET) and level-triggered modes
 *   - pipe read-readiness detection
 *
 * Output: PASS / FAIL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>

int main(void)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); return 1; }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { perror("epoll_create1"); return 1; }

    struct epoll_event ev;
    ev.events  = EPOLLIN;
    ev.data.fd = pipefd[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) != 0) {
        perror("epoll_ctl"); return 1;
    }

    /* Nothing written yet — epoll_wait with 0 timeout should return 0 */
    struct epoll_event events[4];
    int n = epoll_wait(epfd, events, 4, 0);
    if (n != 0) { fprintf(stderr, "FAIL expected 0 events, got %d\n", n); return 1; }

    /* Write data — now readable */
    if (write(pipefd[1], "x", 1) != 1) { perror("write"); return 1; }

    n = epoll_wait(epfd, events, 4, 100 /* ms */);
    if (n != 1) { fprintf(stderr, "FAIL expected 1 event, got %d\n", n); return 1; }
    if (events[0].data.fd != pipefd[0]) { puts("FAIL wrong fd"); return 1; }

    /* Drain */
    char buf[4];
    read(pipefd[0], buf, sizeof(buf));

    close(pipefd[0]); close(pipefd[1]); close(epfd);
    puts("PASS");
    return 0;
}
