/*
 * pthread_test.c — minimal static musl pthread smoke test.
 */
#include <pthread.h>
#include <stdio.h>

static void *worker(void *arg)
{
    (void)arg;
    return (void *)42;
}

int main(void)
{
    pthread_t t;
    void *ret = (void *)0;

    if (pthread_create(&t, NULL, worker, NULL) != 0) {
        puts("FAIL");
        return 1;
    }

    if (pthread_join(t, &ret) != 0) {
        puts("FAIL");
        return 1;
    }

    if ((long)ret == 42) {
        puts("PASS");
        return 0;
    }

    puts("FAIL");
    return 1;
}
