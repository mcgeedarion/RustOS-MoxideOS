/* tests/shared/pthread_test.c
 *
 * Smoke: basic pthread create / join.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include "test_helpers.h"

#define N_THREADS  8
#define INCREMENT  10000

static atomic_long counter = 0;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < INCREMENT; i++)
        atomic_fetch_add(&counter, 1);
    return NULL;
}

int main(void) {
    pthread_t t[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(t[i], NULL);
    long got = atomic_load(&counter);
    if (got != (long)N_THREADS * INCREMENT)
        TEST_FAILF("counter=%ld expected=%ld", got, (long)N_THREADS * INCREMENT);
    TEST_PASS();
}
