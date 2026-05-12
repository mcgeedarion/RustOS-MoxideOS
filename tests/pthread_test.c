/* tests/pthread_test.c
 *
 * Smoke: pthread_create / pthread_join / return value.
 *
 * Exercises the clone(CLONE_VM|CLONE_THREAD|...) → TID futex → join
 * path that musl uses for all thread lifecycle operations.
 * Targets clear_child_tid / FUTEX_WAKE on exit (src/proc/process.rs).
 */
#include <pthread.h>
#include <stdio.h>
#include "test_helpers.h"

static void *worker(void *arg) {
    (void)arg;
    return (void *)42;
}

int main(void) {
    pthread_t t;
    void *ret = NULL;

    if (pthread_create(&t, NULL, worker, NULL) != 0)
        TEST_FAIL("pthread_create failed");
    if (pthread_join(t, &ret) != 0)
        TEST_FAIL("pthread_join failed");
    if ((long)ret != 42)
        TEST_FAILF("expected retval 42, got %ld", (long)ret);

    TEST_PASS();
}
