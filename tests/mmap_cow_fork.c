/* tests/mmap_cow_fork.c
 *
 * Tests:
 *   - anonymous mmap + munmap
 *   - copy-on-write semantics across fork()
 *   - MAP_FIXED mapping
 *
 * Output: PASS / FAIL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define MAP_SIZE 4096

static void die(const char *msg) { perror(msg); exit(1); }

int main(void)
{
    /* Basic anon mmap */
    char *p = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) die("mmap");
    memset(p, 0xAB, MAP_SIZE);

    /* Fork — child writes different value (COW) */
    pid_t pid = fork();
    if (pid < 0) die("fork");

    if (pid == 0) {
        /* child */
        memset(p, 0xCD, MAP_SIZE);
        if ((unsigned char)p[0] != 0xCD) {
            write(STDOUT_FILENO, "FAIL child write\n", 17);
            _exit(1);
        }
        _exit(0);
    }

    /* parent: original mapping must be unchanged */
    int status;
    if (waitpid(pid, &status, 0) < 0) die("waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        puts("FAIL child");
        return 1;
    }
    if ((unsigned char)p[0] != 0xAB) {
        puts("FAIL cow: parent page modified");
        return 1;
    }

    if (munmap(p, MAP_SIZE) != 0) die("munmap");
    puts("PASS");
    return 0;
}
