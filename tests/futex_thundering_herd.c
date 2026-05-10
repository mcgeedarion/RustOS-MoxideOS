/* tests/futex_thundering_herd.c
 *
 * Stress test: FUTEX_WAIT/FUTEX_WAKE thundering herd.
 *
 * 32 threads all wait on a single futex word. The main thread fires
 * FUTEX_WAKE(32). All 32 must unblock exactly once — no hangs, no
 * double-wakes. Targets the O(N²) reverse-index removal path in
 * futex_wake_bitset (src/proc/futex.rs).
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <stdio.h>
#include <sched.h>

#define N_THREADS 32
static int futex_word = 1;
static atomic_int woken = 0;
static atomic_int ready = 0;

static inline long futex(int *uaddr, int op, int val,
                          void *timeout, int *uaddr2, int val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static void *waiter(void *arg) {
    (void)arg;
    atomic_fetch_add(&ready, 1);
    futex(&futex_word, FUTEX_WAIT, 1, NULL, NULL, 0);
    atomic_fetch_add(&woken, 1);
    return NULL;
}

int main(void) {
    pthread_t threads[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&threads[i], NULL, waiter, NULL);

    while (atomic_load(&ready) < N_THREADS)
        sched_yield();
    usleep(20000);

    futex(&futex_word, FUTEX_WAKE, N_THREADS, NULL, NULL, 0);

    for (int i = 0; i < N_THREADS; i++)
        pthread_join(threads[i], NULL);

    int w = atomic_load(&woken);
    if (w == N_THREADS) {
        write(1, "FUTEX_HERD PASS\n", 16);
        return 0;
    }
    dprintf(2, "FUTEX_HERD FAIL: woken=%d expected=%d\n", w, N_THREADS);
    return 1;
}
