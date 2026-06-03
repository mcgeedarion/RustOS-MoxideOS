/* tests/shared/pipe_stress.c
 *
 * Stress: concurrent pipe producer / consumer correctness.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "test_helpers.h"

#define N_PROD     4
#define N_CONS     4
#define MSG_SIZE   64
#define MSGS_EACH  1024
#define TOTAL_BYTES ((long)(N_PROD) * MSGS_EACH * MSG_SIZE)

static int pfd[2];
static atomic_long bytes_read = 0;

static void *producer(void *arg) {
    (void)arg;
    char buf[MSG_SIZE];
    memset(buf, 0xAB, MSG_SIZE);
    for (int i = 0; i < MSGS_EACH; i++) {
        ssize_t w = write(pfd[1], buf, MSG_SIZE);
        if (w != MSG_SIZE)
            TEST_FAILF("write returned %zd", w);
    }
    return NULL;
}

static void *consumer(void *arg) {
    (void)arg;
    char buf[MSG_SIZE * 4];
    ssize_t r;
    while ((r = read(pfd[0], buf, sizeof(buf))) > 0)
        atomic_fetch_add(&bytes_read, r);
    return NULL;
}

int main(void) {
    TEST_SYSCALL(pipe(pfd), "pipe");
    pthread_t prod[N_PROD], cons[N_CONS];
    for (int i = 0; i < N_CONS; i++) pthread_create(&cons[i], NULL, consumer, NULL);
    for (int i = 0; i < N_PROD; i++) pthread_create(&prod[i], NULL, producer, NULL);
    for (int i = 0; i < N_PROD; i++) pthread_join(prod[i], NULL);
    close(pfd[1]);
    for (int i = 0; i < N_CONS; i++) pthread_join(cons[i], NULL);
    close(pfd[0]);
    long got = atomic_load(&bytes_read);
    if (got != TOTAL_BYTES)
        TEST_FAILF("bytes_read=%ld expected=%ld", got, TOTAL_BYTES);
    TEST_PASS();
}
