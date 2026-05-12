/* tests/vfs_concurrent_creat.c
 *
 * Stress: concurrent open/write/read-back/unlink under high contention.
 *
 * 16 threads race to create, write, verify, and delete files, mixing
 * shared and unique names to maximise VFS lock contention.
 * Targets the alloc_fd TOCTOU race in proc_fd_open
 * (src/fs/process_fd.rs).
 *
 * Set TEST_TMPDIR to override the directory used for temp files.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "test_helpers.h"

#define N_THREADS  16
#define ITERATIONS 200

static atomic_int errors  = 0;
static const char *tmpdir = ".";

static void *worker(void *arg) {
    int id = (int)(long)arg;
    char path[128];

    for (int i = 0; i < ITERATIONS; i++) {
        if (i % 4 == 0)
            snprintf(path, sizeof(path), "%s/shared_%d", tmpdir, i % 8);
        else
            snprintf(path, sizeof(path), "%s/thr%d_%d", tmpdir, id, i);

        int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (fd < 0) { atomic_fetch_add(&errors, 1); continue; }

        uint8_t wbuf[16], rbuf[16];
        memset(wbuf, (uint8_t)(id ^ i), sizeof(wbuf));

        if ((int)write(fd, wbuf, sizeof(wbuf)) != (int)sizeof(wbuf)) {
            atomic_fetch_add(&errors, 1);
            close(fd); unlink(path);
            continue;
        }
        lseek(fd, 0, SEEK_SET);
        if ((int)read(fd, rbuf, sizeof(rbuf)) != (int)sizeof(rbuf) ||
            memcmp(wbuf, rbuf, sizeof(wbuf)) != 0)
            atomic_fetch_add(&errors, 1);

        close(fd);
        unlink(path);
    }
    return NULL;
}

int main(void) {
    const char *env = getenv("TEST_TMPDIR");
    if (env && *env) tmpdir = env;

    pthread_t t[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&t[i], NULL, worker, (void *)(long)i);
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(t[i], NULL);

    int e = atomic_load(&errors);
    if (e != 0)
        TEST_FAILF("%d I/O errors across %d threads x %d iterations",
                   e, N_THREADS, ITERATIONS);

    TEST_PASS();
}
