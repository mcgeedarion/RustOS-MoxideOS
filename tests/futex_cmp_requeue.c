/* tests/futex_cmp_requeue.c
 *
 * Stress test: FUTEX_CMP_REQUEUE — the op underlying musl pthread_cond_broadcast.
 *
 * Wake 1 waiter on src, requeue N-1 onto dst. A subsequent FUTEX_WAKE(N)
 * on dst must release all N-1 requeued threads. Total woken must equal N.
 * Targets futex_requeue_inner (src/proc/futex.rs).
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <stdio.h>
#include <sched.h>

#define N 16
static int src = 0, dst = 0;
static atomic_int woken = 0;
static atomic_int staged = 0;

static void *waiter(void *arg) {
    (void)arg;
    atomic_fetch_add(&staged, 1);
    syscall(SYS_futex, &src, FUTEX_WAIT, 0, NULL, NULL, 0);
    atomic_fetch_add(&woken, 1);
    return NULL;
}

int main(void) {
    pthread_t t[N];
    for (int i = 0; i < N; i++)
        pthread_create(&t[i], NULL, waiter, NULL);

    while (atomic_load(&staged) < N)
        sched_yield();

    long r = syscall(SYS_futex, &src, FUTEX_CMP_REQUEUE,
                     1, (void*)(long)(N - 1), &dst, 0);
    if (r < 0) {
        dprintf(2, "FUTEX_CMPREQ FAIL: cmp_requeue syscall error\n");
        return 1;
    }

    syscall(SYS_futex, &dst, FUTEX_WAKE, N, NULL, NULL, 0);

    for (int i = 0; i < N; i++)
        pthread_join(t[i], NULL);

    int w = atomic_load(&woken);
    if (w == N) {
        puts("PASS");
        return 0;
    }
    dprintf(2, "FUTEX_CMPREQ FAIL: woken=%d expected=%d\n", w, N);
    return 1;
}
