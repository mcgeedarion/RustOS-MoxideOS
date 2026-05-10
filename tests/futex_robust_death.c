/* tests/futex_robust_death.c
 *
 * Stress test: robust futex owner-death cleanup.
 *
 * A thread acquires a PTHREAD_MUTEX_ROBUST mutex and exits without
 * releasing it. The kernel must walk the robust list, write
 * FUTEX_OWNER_DIED (0x40000000) only — NOT preserving FUTEX_WAITERS —
 * and wake one waiter. The parent must receive EOWNERDEAD from
 * pthread_mutex_lock and successfully recover via pthread_mutex_consistent.
 *
 * Targets robust_list_on_exit / wake_robust_futex (src/proc/futex.rs).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

static pthread_mutex_t mtx;

static void *killer(void *arg) {
    (void)arg;
    pthread_mutex_lock(&mtx);
    /* Exit without unlocking — triggers robust list kernel cleanup */
    return NULL;
}

int main(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&mtx, &attr);
    pthread_mutexattr_destroy(&attr);

    pthread_t t;
    pthread_create(&t, NULL, killer, NULL);
    pthread_join(t, NULL); /* thread exited holding lock */

    int r = pthread_mutex_lock(&mtx);
    if (r == EOWNERDEAD) {
        pthread_mutex_consistent(&mtx);
        pthread_mutex_unlock(&mtx);
        write(1, "FUTEX_ROBUST PASS\n", 18);
        return 0;
    }
    dprintf(2, "FUTEX_ROBUST FAIL: lock returned %d (expected EOWNERDEAD=%d)\n",
            r, EOWNERDEAD);
    return 1;
}
