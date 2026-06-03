/* tests/shared/vfs_concurrent_creat.c
 *
 * Stress: concurrent O_CREAT | O_EXCL on the same path.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "test_helpers.h"

#define N_THREADS 16

static char path[64];
static atomic_int created = 0;
static atomic_int eexist  = 0;
static atomic_int go      = 0;

static void *creator(void *arg) {
    (void)arg;
    while (!atomic_load(&go)) ;
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd >= 0) { atomic_fetch_add(&created, 1); close(fd); }
    else if (errno == EEXIST) atomic_fetch_add(&eexist, 1);
    else TEST_FAILF("open: unexpected errno %d", errno);
    return NULL;
}

int main(void) {
    snprintf(path, sizeof(path), "/tmp/rustos_creat_%d", (int)getpid());
    unlink(path);
    pthread_t t[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) pthread_create(&t[i], NULL, creator, NULL);
    atomic_store(&go, 1);
    for (int i = 0; i < N_THREADS; i++) pthread_join(t[i], NULL);
    unlink(path);
    int c = atomic_load(&created), e = atomic_load(&eexist);
    if (c != 1) TEST_FAILF("expected 1 creator, got %d", c);
    if (c + e != N_THREADS) TEST_FAILF("created+eexist=%d expected=%d", c + e, N_THREADS);
    TEST_PASS();
}
