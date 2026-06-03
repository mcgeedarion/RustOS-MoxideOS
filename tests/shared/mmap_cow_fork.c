/* tests/shared/mmap_cow_fork.c
 *
 * Smoke: copy-on-write fork page separation.
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include "test_helpers.h"

int main(void) {
    int *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_SYSCALL((int)(long)p, "mmap");
    *p = 0xDEAD;
    pid_t pid = fork();
    TEST_SYSCALL(pid, "fork");
    if (pid == 0) { *p = 0xBEEF; _exit(0); }
    int status;
    waitpid(pid, &status, 0);
    if (*p != 0xDEAD)
        TEST_FAILF("CoW broken: parent saw 0x%x", *p);
    munmap(p, 4096);
    TEST_PASS();
}
