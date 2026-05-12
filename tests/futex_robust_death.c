/* tests/futex_robust_death.c
 *
 * Stress: robust futex owner-death cleanup.
 *
 * A thread acquires a PTHREAD_MUTEX_ROBUST mutex and exits without
 * releasing it. The kernel must walk the robust list, mark
 * FUTEX_OWNER_DIED, and wake one waiter. The parent must receive
 * EOWNERDEAD and recover via pthread_mutex_consistent.
 * Targets robust_list_on_exit / wake_robust_futex (src/proc/futex.rs).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include "test_helpers.h"

static pthread_mutex_t mtx;

static void *killer(void *arg) {
    (void)arg;
    pthread_mutex_lock(&mtx);
    return NULL; /* exits holding lock — triggers robust list cleanup */
}

int main(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&mtx, &attr);
    pthread_mutexattr_destroy(&attr);

    pthread_t t;
    pthread_create(&t, NULL, killer, NULL);
    pthread_join(t, NULL);

    int r = pthread_mutex_lock(&mtx);
    if (r != EOWNERDEAD)
        TEST_FAILF("expected EOWNERDEAD(%d), got %d", EOWNERDEAD, r);

    pthread_mutex_consistent(&mtx);
    pthread_mutex_unlock(&mtx);
    TEST_PASS();
}
