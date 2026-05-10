/* tests/sched_rr_fairness.c
 *
 * Stress test: SCHED_RR round-robin fairness.
 *
 * N threads run at the same RR priority for RUN_SEC seconds, each
 * counting loop iterations. The max/min ratio must be < 2.0 — no thread
 * may be starved or over-scheduled. Will catch the extra free-tick bug
 * in the RR preemption path (src/proc/scheduler.rs).
 */
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define N       8
#define RUN_SEC 2

static atomic_long counters[N];
static atomic_int  go = 0;

static void *runner(void *arg) {
    int id = (int)(long)arg;
    struct sched_param p = { .sched_priority = 10 };
    pthread_setschedparam(pthread_self(), SCHED_RR, &p);

    while (!atomic_load(&go)) sched_yield();

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += RUN_SEC;

    struct timespec now;
    do {
        atomic_fetch_add(&counters[id], 1);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec < deadline.tv_sec ||
             (now.tv_sec == deadline.tv_sec &&
              now.tv_nsec < deadline.tv_nsec));
    return NULL;
}

int main(void) {
    pthread_t t[N];
    for (int i = 0; i < N; i++)
        pthread_create(&t[i], NULL, runner, (void*)(long)i);

    atomic_store(&go, 1);
    for (int i = 0; i < N; i++) pthread_join(t[i], NULL);

    long mn = atomic_load(&counters[0]);
    long mx = mn;
    for (int i = 1; i < N; i++) {
        long v = atomic_load(&counters[i]);
        if (v < mn) mn = v;
        if (v > mx) mx = v;
    }
    for (int i = 0; i < N; i++)
        dprintf(2, "  rr thread %d: %ld\n", i, (long)atomic_load(&counters[i]));

    if (mn > 0 && (double)mx / (double)mn < 2.0) {
        write(1, "SCHED_RR PASS\n", 14);
        return 0;
    }
    dprintf(2, "SCHED_RR FAIL: min=%ld max=%ld ratio=%.2f\n",
            mn, mx, mn > 0 ? (double)mx / (double)mn : 0.0);
    return 1;
}
