/* tests/shared/vfs_rename_unlink.c
 *
 * Stress: concurrent rename(2) + unlink(2) on overlapping paths.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <errno.h>
#include "test_helpers.h"

#define N_THREADS  8
#define N_FILES    4
#define ITERS      256

static char paths[N_FILES][64];
static atomic_int go = 0;

static void make_files(void) {
    for (int i = 0; i < N_FILES; i++) {
        int fd = open(paths[i], O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (fd >= 0) close(fd);
    }
}

static void *renamer(void *arg) {
    (void)arg;
    while (!atomic_load(&go)) ;
    for (int i = 0; i < ITERS; i++) {
        int a = i % N_FILES, b = (i + 1) % N_FILES;
        rename(paths[a], paths[b]);
    }
    return NULL;
}

static void *unlinker(void *arg) {
    (void)arg;
    while (!atomic_load(&go)) ;
    for (int i = 0; i < ITERS; i++) {
        unlink(paths[i % N_FILES]);
        int fd = open(paths[i % N_FILES], O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (fd >= 0) close(fd);
    }
    return NULL;
}

int main(void) {
    pid_t pid = getpid();
    for (int i = 0; i < N_FILES; i++)
        snprintf(paths[i], sizeof(paths[i]), "/tmp/rustos_ren_%d_%d", pid, i);
    make_files();
    pthread_t rt[N_THREADS], ut[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) pthread_create(&rt[i], NULL, renamer,  NULL);
    for (int i = 0; i < N_THREADS; i++) pthread_create(&ut[i], NULL, unlinker, NULL);
    atomic_store(&go, 1);
    for (int i = 0; i < N_THREADS; i++) pthread_join(rt[i], NULL);
    for (int i = 0; i < N_THREADS; i++) pthread_join(ut[i], NULL);
    for (int i = 0; i < N_FILES; i++) unlink(paths[i]);
    TEST_PASS();
}
