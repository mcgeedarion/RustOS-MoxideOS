/*
 * userspace/init/init.c — PID 1 init process for rustos
 *
 * This is the first userspace process exec'd by the kernel after boot.
 * It is compiled as a static musl-libc binary so it has no dynamic
 * linker dependency. The kernel loads it directly via elf64::load().
 *
 * Responsibilities:
 *   1. Write a boot message to stdout (fd 1) via the write syscall.
 *   2. Optionally exec a shell or further init stages.
 *   3. Never return — loop forever or call exit(0).
 *
 * Syscalls used (must be implemented in src/syscall/stubs.rs):
 *   write(1, buf, len)  — SYS_write = 1
 *   exit(0)             — SYS_exit  = 60
 */

#include <unistd.h>
#include <stdlib.h>

/* A small helper so we don't need printf (avoids pulling in more of musl). */
static void puts_fd(int fd, const char *s) {
    const char *p = s;
    while (*p) p++;
    write(fd, s, (size_t)(p - s));
    write(fd, "\n", 1);
}

int main(void) {
    puts_fd(1, "[init] rustos userspace init started");
    puts_fd(1, "[init] PID 1 running under musl-libc");
    puts_fd(1, "[init] TEST PASS: userspace_init");

    /* In a real kernel you would exec /bin/sh here:
     *   char *argv[] = { "/bin/sh", NULL };
     *   char *envp[] = { "HOME=/", "PATH=/bin", NULL };
     *   execve("/bin/sh", argv, envp);
     */

    /* For now, spin so the process stays alive and the kernel idle loop runs. */
    for (;;) {
        /* yield — SYS_sched_yield = 24.  Gracefully gives back the CPU. */
        syscall(24);
    }

    return 0; /* unreachable */
}
