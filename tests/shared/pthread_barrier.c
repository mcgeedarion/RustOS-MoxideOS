/* tests/shared/pthread_barrier.c
 *
 * Stress: pthread_barrier rendezvous under contention.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include "test_helpers.h"

#define N_THREADS  16
#define ROUNDS     1000

static pthread_barrier_t bar;
static atomic_long serial_count = 0;

static void *worker(void *arg) {
    (void)arg;
    for (int r = 0; r < ROUNDS; r++) {
        int rc = pthread_barrier_wait(&bar);
        if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
            atomic_fetch_add(&serial_count, 1);
        else if (rc != 0)
            TEST_FAILF("pthread_barrier_wait returned %d", rc);
    }
    return NULL;
}

int main(void) {
    TEST_SYSCALL(pthread_barrier_init(&bar, NULL, N_THREADS), "barrier_init");
    pthread_t t[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(t[i], NULL);
    pthread_barrier_destroy(&bar);
    long sc = atomic_load(&serial_count);
    if (sc != ROUNDS)
        TEST_FAILF("serial_count=%ld expected=%d", sc, ROUNDS);
    TEST_PASS();
}
