/* tests/shared/futex_thundering_herd.c
 *
 * Stress: FUTEX_WAIT/FUTEX_WAKE thundering herd.
 *
 * 32 threads all block on a single futex word. The main thread fires
 * FUTEX_WAKE(32). All 32 must unblock exactly once — no hangs, no
 * double-wakes. Targets the O(N²) reverse-index removal path in
 * futex_wake_bitset (src/proc/futex.rs).
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdio.h>
#include "test_helpers.h"

#define N_THREADS 32

static int         futex_word = 1;
static atomic_int  woken      = 0;
static atomic_int  ready      = 0;

static inline long xfutex(int *uaddr, int op, int val) {
    return syscall(SYS_futex, uaddr, op, val, NULL, NULL, 0);
}

static void *waiter(void *arg) {
    (void)arg;
    atomic_fetch_add(&ready, 1);
    xfutex(&futex_word, FUTEX_WAIT, 1);
    atomic_fetch_add(&woken, 1);
    return NULL;
}

int main(void) {
    pthread_t threads[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&threads[i], NULL, waiter, NULL);

    while (atomic_load(&ready) < N_THREADS)
        sched_yield();

    xfutex(&futex_word, FUTEX_WAKE, N_THREADS);

    for (int i = 0; i < N_THREADS; i++)
        pthread_join(threads[i], NULL);

    int w = atomic_load(&woken);
    if (w != N_THREADS)
        TEST_FAILF("woken=%d expected=%d", w, N_THREADS);

    TEST_PASS();
}
