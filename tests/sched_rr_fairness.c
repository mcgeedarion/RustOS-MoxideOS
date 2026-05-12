/* tests/sched_rr_fairness.c
 *
 * Stress: SCHED_RR round-robin fairness.
 *
 * N threads run at the same RR priority for RUN_SEC seconds, each
 * counting loop iterations. The max/min ratio must be < 2.0 — no thread
 * may be starved or over-scheduled.
 * Skips if SCHED_RR requires CAP_SYS_NICE (EPERM).
 * Targets the RR preemption path (src/proc/scheduler.rs).
 */
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include "test_helpers.h"

#define N       8
#define RUN_SEC 2

static atomic_long counters[N];
static atomic_int  go             = 0;
static atomic_int  priv_denied    = 0;

static void *runner(void *arg) {
    int id = (int)(long)arg;
    struct sched_param p = { .sched_priority = 10 };
    if (pthread_setschedparam(pthread_self(), SCHED_RR, &p) == EPERM)
        atomic_store(&priv_denied, 1);

    while (!atomic_load(&go))
        sched_yield();

    struct timespec dl, now;
    clock_gettime(CLOCK_MONOTONIC, &dl);
    dl.tv_sec += RUN_SEC;

    do {
        atomic_fetch_add(&counters[id], 1);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec < dl.tv_sec ||
             (now.tv_sec == dl.tv_sec && now.tv_nsec < dl.tv_nsec));
    return NULL;
}

int main(void) {
    pthread_t t[N];
    for (int i = 0; i < N; i++)
        pthread_create(&t[i], NULL, runner, (void *)(long)i);

    atomic_store(&go, 1);
    for (int i = 0; i < N; i++)
        pthread_join(t[i], NULL);

    if (atomic_load(&priv_denied))
        TEST_SKIP("SCHED_RR requires CAP_SYS_NICE");

    long mn = atomic_load(&counters[0]);
    long mx = mn;
    for (int i = 1; i < N; i++) {
        long v = atomic_load(&counters[i]);
        if (v < mn) mn = v;
        if (v > mx) mx = v;
    }

    if (mn <= 0 || (double)mx / (double)mn >= 2.0)
        TEST_FAILF("min=%ld max=%ld ratio=%.2f",
                   mn, mx, mn > 0 ? (double)mx / (double)mn : 0.0);

    TEST_PASS();
}
