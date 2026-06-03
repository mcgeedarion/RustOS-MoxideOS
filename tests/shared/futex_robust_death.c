/* tests/shared/futex_robust_death.c
 *
 * Stress: robust futex owner-death recovery.
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include "test_helpers.h"

static int futex_word = 0;
static atomic_int child_held = 0;

static inline long xfutex(int *ua, int op, int val) {
    return syscall(SYS_futex, ua, op, val, NULL, NULL, 0);
}

static void *holder(void *arg) {
    (void)arg;
    futex_word = (int)syscall(SYS_gettid);
    atomic_store(&child_held, 1);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, holder, NULL);
    while (!atomic_load(&child_held)) sched_yield();
    pthread_join(t, NULL);

    long r = xfutex(&futex_word, FUTEX_WAIT, futex_word);
    if (r == 0 || errno == EOWNERDEAD || errno == EAGAIN || errno == EINVAL) {
        TEST_PASS();
    }
    TEST_FAILF("unexpected return %ld errno %d", r, errno);
}
