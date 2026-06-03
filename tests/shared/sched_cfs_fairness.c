/* tests/shared/sched_cfs_fairness.c
 *
 * Stress: SCHED_OTHER (CFS) vruntime fairness.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
#include <stdio.h>
#include "test_helpers.h"

#define N_THREADS  4
#define WINDOW_MS  300

static atomic_int  go      = 0;
static atomic_long counts[N_THREADS];

static void *spinner(void *arg) {
    int id = (int)(long)arg;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_nsec += WINDOW_MS * 1000000L;
    if (end.tv_nsec >= 1000000000L) { end.tv_sec++; end.tv_nsec -= 1000000000L; }

    while (!atomic_load(&go)) sched_yield();

    long c = 0;
    struct timespec now;
    do {
        c++;
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec < end.tv_sec ||
             (now.tv_sec == end.tv_sec && now.tv_nsec < end.tv_nsec));

    atomic_store(&counts[id], c);
    return NULL;
}

int main(void) {
    pthread_t threads[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&threads[i], NULL, spinner, (void *)(long)i);

    atomic_store(&go, 1);
    for (int i = 0; i < N_THREADS; i++) pthread_join(threads[i], NULL);

    long total = 0;
    for (int i = 0; i < N_THREADS; i++) total += atomic_load(&counts[i]);
    if (total == 0) TEST_SKIP("zero iterations");

    for (int i = 0; i < N_THREADS; i++) {
        long share = atomic_load(&counts[i]) * 100 / total;
        if (share < 10)
            TEST_FAILF("thread %d got only %ld%% of iterations", i, share);
    }
    TEST_PASS();
}
