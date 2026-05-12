/* tests/pthread_barrier.c
 *
 * Smoke: pthread_barrier_init / wait / destroy.
 *
 * N threads block on a barrier; all must reach the barrier before any
 * proceeds. Exactly one thread must receive PTHREAD_BARRIER_SERIAL_THREAD.
 * Targets barrier_wait futex logic (src/proc/futex.rs).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include "test_helpers.h"

#define N_THREADS 8

static pthread_barrier_t barrier;
static atomic_int serial_count = 0;
static atomic_int after_count  = 0;

static void *worker(void *arg) {
    (void)arg;
    int rc = pthread_barrier_wait(&barrier);
    if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
        atomic_fetch_add(&serial_count, 1);
    else if (rc != 0)
        return (void *)1; /* signal error to main */
    atomic_fetch_add(&after_count, 1);
    return NULL;
}

int main(void) {
    if (pthread_barrier_init(&barrier, NULL, N_THREADS) != 0)
        TEST_FAIL("pthread_barrier_init failed");

    pthread_t tids[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&tids[i], NULL, worker, NULL);

    for (int i = 0; i < N_THREADS; i++) {
        void *rv;
        pthread_join(tids[i], &rv);
        if (rv != NULL)
            TEST_FAIL("pthread_barrier_wait returned error in worker");
    }

    pthread_barrier_destroy(&barrier);

    if (atomic_load(&serial_count) != 1)
        TEST_FAILF("serial_count=%d expected 1", atomic_load(&serial_count));
    if (atomic_load(&after_count) != N_THREADS)
        TEST_FAILF("after_count=%d expected %d", atomic_load(&after_count), N_THREADS);

    TEST_PASS();
}
