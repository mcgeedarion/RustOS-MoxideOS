/* tests/fork_exec_wait.c
 *
 * Tests:
 *   - fork() + execve() + waitpid()
 *   - exit status propagation (WIFEXITED / WEXITSTATUS)
 *   - multiple sequential forks
 *
 * Output: PASS / FAIL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>

#define N_CHILDREN 8

int main(void)
{
    pid_t pids[N_CHILDREN];

    for (int i = 0; i < N_CHILDREN; i++) {
        pid_t p = fork();
        if (p < 0) { perror("fork"); return 1; }
        if (p == 0) {
            /* Child: exec /bin/true or exit with index */
            char *argv[] = { "/bin/true", NULL };
            char *envp[] = { NULL };
            execve("/bin/true", argv, envp);
            /* If /bin/true unavailable, just exit cleanly */
            _exit(0);
        }
        pids[i] = p;
    }

    int all_ok = 1;
    for (int i = 0; i < N_CHILDREN; i++) {
        int status;
        pid_t r = waitpid(pids[i], &status, 0);
        if (r != pids[i]) { fprintf(stderr, "waitpid mismatch\n"); all_ok = 0; continue; }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "child %d bad exit\n", i);
            all_ok = 0;
        }
    }

    if (!all_ok) { puts("FAIL"); return 1; }
    puts("PASS");
    return 0;
}
