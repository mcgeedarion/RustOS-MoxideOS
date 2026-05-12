/* tests/pthread_barrier.c
 *
 * Tests:
 *   - pthread_barrier_init / wait / destroy
 *   - All N threads must reach barrier before any proceeds
 *   - Exactly one thread receives PTHREAD_BARRIER_SERIAL_THREAD
 *
 * Output: PASS / FAIL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#define N_THREADS 8

static pthread_barrier_t barrier;
static atomic_int before_count = 0;
static atomic_int serial_count = 0;
static atomic_int after_count  = 0;

static void *worker(void *arg) {
    (void)arg;
    atomic_fetch_add(&before_count, 1);
    int rc = pthread_barrier_wait(&barrier);
    if (rc == PTHREAD_BARRIER_SERIAL_THREAD)
        atomic_fetch_add(&serial_count, 1);
    else if (rc != 0) {
        fputs("FAIL pthread_barrier_wait error\n", stderr);
        return (void*)1;
    }
    atomic_fetch_add(&after_count, 1);
    return NULL;
}

int main(void)
{
    pthread_t tids[N_THREADS];
    if (pthread_barrier_init(&barrier, NULL, N_THREADS) != 0) {
        perror("barrier_init"); return 1;
    }
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&tids[i], NULL, worker, NULL);
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(tids[i], NULL);

    pthread_barrier_destroy(&barrier);

    if (before_count != N_THREADS) { puts("FAIL before_count"); return 1; }
    if (serial_count != 1)         { puts("FAIL serial_count != 1"); return 1; }
    if (after_count  != N_THREADS) { puts("FAIL after_count"); return 1; }
    puts("PASS");
    return 0;
}
