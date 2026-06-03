/* tests/shared/futex_cmp_requeue.c
 *
 * Stress: FUTEX_CMP_REQUEUE correctness.
 *
 * 8 threads wait on futex A. Main thread requeues 4 of them onto futex B,
 * then wakes 1 from A and 4 from B. All 8 must unblock cleanly.
 * Targets futex_cmp_requeue (src/proc/futex.rs).
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdio.h>
#include "test_helpers.h"

#define N 8

static int        fa = 0, fb = 0;
static atomic_int ready = 0;
static atomic_int done  = 0;

static inline long xfutex(int *ua, int op, int val, int val2, int *ub, int val3) {
    return syscall(SYS_futex, ua, op, val, (void *)(long)val2, ub, val3);
}

static void *waiter(void *arg) {
    (void)arg;
    atomic_fetch_add(&ready, 1);
    xfutex(&fa, FUTEX_WAIT, 0, 0, NULL, 0);
    atomic_fetch_add(&done, 1);
    return NULL;
}

int main(void) {
    pthread_t t[N];
    for (int i = 0; i < N; i++) pthread_create(&t[i], NULL, waiter, NULL);
    while (atomic_load(&ready) < N) sched_yield();

    /* Requeue 4 waiters from fa → fb (keep 1 on fa). */
    xfutex(&fa, FUTEX_CMP_REQUEUE, 1, 4, &fb, 0);
    /* Wake the 1 left on fa. */
    xfutex(&fa, FUTEX_WAKE, 1, 0, NULL, 0);
    /* Wake the 4 on fb. */
    xfutex(&fb, FUTEX_WAKE, 4, 0, NULL, 0);
    /* Wake any remaining stragglers. */
    xfutex(&fa, FUTEX_WAKE, N, 0, NULL, 0);
    xfutex(&fb, FUTEX_WAKE, N, 0, NULL, 0);

    for (int i = 0; i < N; i++) pthread_join(t[i], NULL);
    int d = atomic_load(&done);
    if (d != N) TEST_FAILF("done=%d expected=%d", d, N);
    TEST_PASS();
}
