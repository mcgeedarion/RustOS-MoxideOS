/* tests/pipe_stress.c
 *
 * Stress test: pipe ring-buffer integrity under concurrent producer/consumer.
 *
 * Writer sends 1 MiB in 4 KiB chunks with a deterministic byte pattern.
 * Reader reconstructs and verifies every byte. Tests PipeInner read_bytes /
 * write_bytes and the yield-spin blocking model (src/fs/pipe.rs).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define TOTAL  (1 << 20)   /* 1 MiB */
#define CHUNK  4096

static int pfd[2];

static void *writer(void *arg) {
    (void)arg;
    uint8_t buf[CHUNK];
    int sent = 0;
    while (sent < TOTAL) {
        int n = (TOTAL - sent < CHUNK) ? (TOTAL - sent) : CHUNK;
        for (int i = 0; i < n; i++)
            buf[i] = (uint8_t)((sent + i) & 0xFF);
        int w = (int)write(pfd[1], buf, (size_t)n);
        if (w <= 0) return NULL;
        sent += w;
    }
    close(pfd[1]);
    return NULL;
}

int main(void) {
    if (pipe(pfd) != 0) {
        write(2, "pipe() failed\n", 14);
        return 1;
    }

    pthread_t t;
    pthread_create(&t, NULL, writer, NULL);

    uint8_t buf[CHUNK];
    int received = 0;
    int corrupt  = 0;

    while (received < TOTAL) {
        int r = (int)read(pfd[0], buf, sizeof(buf));
        if (r <= 0) break;
        for (int i = 0; i < r; i++) {
            uint8_t expected = (uint8_t)((received + i) & 0xFF);
            if (buf[i] != expected) corrupt++;
        }
        received += r;
    }
    close(pfd[0]);
    pthread_join(t, NULL);

    if (received == TOTAL && corrupt == 0) {
        write(1, "PIPE_STRESS PASS\n", 17);
        return 0;
    }
    dprintf(2, "PIPE_STRESS FAIL: received=%d/%d corrupt=%d\n",
            received, TOTAL, corrupt);
    return 1;
}
