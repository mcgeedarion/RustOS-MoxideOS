/* tests/mmap_cow_fork.c
 *
 * Smoke: anonymous mmap/munmap + copy-on-write across fork().
 *
 * Parent writes 0xAB into a private anon page, forks, child writes 0xCD.
 * After child exits the parent's mapping must still read 0xAB (COW).
 * Targets mmap/munmap and COW page fault handling (src/mm/mmap.rs).
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "test_helpers.h"

#define MAP_SIZE 4096

int main(void) {
    char *p = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        TEST_FAIL("mmap failed");

    memset(p, 0xAB, MAP_SIZE);

    pid_t pid = fork();
    TEST_SYSCALL((int)pid, "fork");

    if (pid == 0) {
        memset(p, 0xCD, MAP_SIZE);
        _exit((unsigned char)p[0] == 0xCD ? 0 : 1);
    }

    int status;
    TEST_SYSCALL((int)waitpid(pid, &status, 0), "waitpid");

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        TEST_FAIL("child COW write failed");
    if ((unsigned char)p[0] != 0xAB)
        TEST_FAIL("COW violated: parent page was modified by child");

    TEST_SYSCALL(munmap(p, MAP_SIZE), "munmap");
    TEST_PASS();
}
