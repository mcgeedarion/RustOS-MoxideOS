/* tests/vfs_concurrent_creat.c
 *
 * Stress test: concurrent open/write/read/close/unlink on /tmp.
 *
 * 16 threads race to create, write, read-back, and delete files in /tmp,
 * mixing unique and shared filenames to maximise lock contention. Each
 * write/readback must be byte-perfect. Targets the alloc_fd TOCTOU race in
 * proc_fd_open (src/fs/process_fd.rs) where the linear scan releases
 * PROC_FD_TABLES before inserting, allowing two threads to claim the
 * same fd slot.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>

#define N_THREADS  16
#define ITERATIONS 200

static atomic_int errors = 0;

static void *worker(void *arg) {
    int id = (int)(long)arg;
    char path[64];

    for (int i = 0; i < ITERATIONS; i++) {
        /* Alternate between shared and unique paths for contention */
        if (i % 4 == 0)
            snprintf(path, sizeof(path), "/tmp/shared_%d", i % 8);
        else
            snprintf(path, sizeof(path), "/tmp/thr%d_%d", id, i);

        int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (fd < 0) {
            atomic_fetch_add(&errors, 1);
            continue;
        }

        uint8_t wbuf[16], rbuf[16];
        memset(wbuf, (uint8_t)(id ^ i), sizeof(wbuf));

        if ((int)write(fd, wbuf, sizeof(wbuf)) != (int)sizeof(wbuf)) {
            atomic_fetch_add(&errors, 1);
            close(fd); unlink(path);
            continue;
        }
        lseek(fd, 0, SEEK_SET);
        int r = (int)read(fd, rbuf, sizeof(rbuf));
        if (r != (int)sizeof(rbuf) || memcmp(wbuf, rbuf, sizeof(wbuf)) != 0)
            atomic_fetch_add(&errors, 1);

        close(fd);
        unlink(path);
    }
    return NULL;
}

int main(void) {
    pthread_t t[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&t[i], NULL, worker, (void*)(long)i);
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(t[i], NULL);

    int e = atomic_load(&errors);
    if (e == 0) {
        write(1, "VFS_CREAT PASS\n", 15);
        return 0;
    }
    dprintf(2, "VFS_CREAT FAIL: %d errors\n", e);
    return 1;
}
