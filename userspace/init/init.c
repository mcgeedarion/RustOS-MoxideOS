/*
 * userspace/init/init.c — PID 1 init process for rustos
 *
 * This is the first userspace process exec'd by the kernel after boot.
 * It is compiled as a static musl-libc binary so it has no dynamic
 * linker dependency. The kernel loads it directly via elf64::load().
 *
 * Responsibilities:
 *   1. Write a boot message to stdout (fd 1) via the write syscall.
 *   2. Launch the Wayland compositor as a supervised child process.
 *   3. Wait for children via waitpid(); restart the compositor if it exits.
 *   4. Never return — loop forever supervising children.
 *
 * Wayland compositor launch
 * ─────────────────────────
 * The compositor (/usr/bin/rustos-compositor) is a privileged userspace
 * process (ring 3, UID 0).  init owns its lifecycle:
 *
 *   1. Open /dev/dri/card0  (O_RDWR)           → drm_fd
 *   2. Open /dev/input/event0 (O_RDONLY|O_NONBLOCK) → input_fd
 *   3. fork() + execve("/usr/bin/rustos-compositor")
 *      The child inherits drm_fd and input_fd; their numbers are
 *      communicated via the environment variables:
 *        WAYLAND_DRM_FD=<n>
 *        WAYLAND_INPUT_FD=<n>
 *   4. waitpid() in a loop.  If the compositor exits for any reason
 *      (crash, clean exit) init closes the old fds, waits one second,
 *      re-opens the device nodes, and re-launches.
 *
 * Why init, not the kernel?
 * ─────────────────────────
 * A Wayland compositor does not need kernel privileges.  It only needs
 * an open fd to /dev/dri/card0 (DRM master) and /dev/input/event0.
 * Running the launch from PID 1 means:
 *   - The kernel Wayland code is reduced to a thin vblank pass-through.
 *   - Compositor crashes are handled as ordinary SIGCHLD, not kernel panics.
 *   - The compositor binary is restricted by a seccomp filter to < 15
 *     syscalls; init enforces this restart policy without kernel changes.
 *
 * Syscalls used (must be implemented in src/syscall/stubs.rs):
 *   write(1, buf, len)          — SYS_write       =  1
 *   open(path, flags)           — SYS_open         =  2
 *   close(fd)                   — SYS_close        =  3
 *   fork()                      — SYS_fork         = 57
 *   execve(path, argv, envp)    — SYS_execve       = 59
 *   exit(0)                     — SYS_exit         = 60
 *   waitpid(pid, status, 0)     — SYS_wait4        = 61
 *   nanosleep(ts, NULL)         — SYS_nanosleep    = 35
 *   sched_yield()               — SYS_sched_yield  = 24
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#define COMPOSITOR_BIN      "/usr/bin/rustos-compositor"
#define DRM_DEV             "/dev/dri/card0"
#define INPUT_DEV           "/dev/input/event0"
#define RESTART_DELAY_SEC   1

static void puts_fd(int fd, const char *s)
{
    const char *p = s;
    while (*p) p++;
    write(fd, s, (size_t)(p - s));
    write(fd, "\n", 1);
}

static void putint_fd(int fd, int n)
{
    char buf[24];
    int  neg = 0;
    int  i   = 22;
    buf[23]  = '\0';
    if (n == 0) { write(fd, "0", 1); return; }
    if (n < 0)  { neg = 1; n = -n; }
    while (n > 0) { buf[i--] = (char)('0' + n % 10); n /= 10; }
    if (neg) buf[i--] = '-';
    write(fd, buf + i + 1, (size_t)(22 - i));
}

static void sleep_sec(int s)
{
    struct timespec ts = { .tv_sec = s, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
}

/* Build "KEY=VALUE" into buf (at most buf_len bytes incl. NUL). */
static void fmt_env(char *buf, size_t buf_len,
                    const char *key, int val)
{
    size_t k = 0;
    while (key[k] && k < buf_len - 1) { buf[k] = key[k]; k++; }
    if (k < buf_len - 1) buf[k++] = '=';
    char digits[16]; int d = 0;
    if (val == 0) { digits[d++] = '0'; }
    else { int v = val; while (v > 0) { digits[d++] = (char)('0' + v % 10); v /= 10; } }
    for (int r = d - 1; r >= 0 && k < buf_len - 1; r--) buf[k++] = digits[r];
    buf[k] = '\0';
}

/*
 * spawn_compositor — open device fds, fork, exec the compositor.
 *
 * The two device fds are opened fresh on every call so that after a
 * compositor crash the DRM master lease is cleanly released (the fds
 * were closed when the child exited) and reacquired here.
 *
 * Returns the child PID on success, -1 on error.
 */
static pid_t spawn_compositor(void)
{
    int drm_fd = open(DRM_DEV, O_RDWR);
    if (drm_fd < 0) {
        puts_fd(2, "[init] WARNING: cannot open " DRM_DEV " — compositor not started");
        return -1;
    }

    int input_fd = open(INPUT_DEV, O_RDONLY | O_NONBLOCK);
    /* input_fd may be -1 on headless boots; the compositor handles that */

    pid_t pid = fork();
    if (pid < 0) {
        puts_fd(2, "[init] ERROR: fork() failed");
        close(drm_fd);
        if (input_fd >= 0) close(input_fd);
        return -1;
    }

    if (pid == 0) {
        /* ── child ────────────────────────────────────────────────────── */

        char drm_env[32];
        char input_env[32];
        fmt_env(drm_env,   sizeof(drm_env),   "WAYLAND_DRM_FD",   drm_fd);
        fmt_env(input_env, sizeof(input_env),  "WAYLAND_INPUT_FD", input_fd);

        char *argv[] = { COMPOSITOR_BIN, NULL };
        char *envp[] = {
            "HOME=/root",
            "PATH=/usr/bin:/bin",
            "XDG_RUNTIME_DIR=/run",
            "WAYLAND_DISPLAY=wayland-0",
            drm_env,
            input_env,
            NULL
        };

        execve(COMPOSITOR_BIN, argv, envp);

        puts_fd(2, "[init] ERROR: execve(" COMPOSITOR_BIN ") failed");
        _exit(1);
    }

    /*
     * Close our copies of the device fds — the child has its own.
     * The DRM master fd must be held by exactly one process; keeping a
     * duplicate open here would prevent the child from acquiring master.
     */
    close(drm_fd);
    if (input_fd >= 0) close(input_fd);

    puts_fd(1, "[init] Wayland compositor spawned, PID=");
    putint_fd(1, (int)pid);
    write(1, "\n", 1);

    return pid;
}

int main(void)
{
    puts_fd(1, "[init] rustos userspace init started");
    puts_fd(1, "[init] PID 1 running under musl-libc");
    puts_fd(1, "[init] TEST PASS: userspace_init");

    /*
     * Initial compositor launch.
     * If the binary is missing (e.g. headless CI) spawn_compositor returns
     * -1 and we fall through to the idle loop below.
     */
    pid_t compositor_pid = spawn_compositor();

    /*
     * Supervisor loop.
     *
     * We wait for any child.  If the compositor crashes or exits cleanly we
     * log the event, sleep RESTART_DELAY_SEC, and re-launch.  Any other
     * unexpected child (none expected in the current design) is reaped and
     * ignored.
     */
    for (;;) {
        int   status = 0;
        pid_t exited = waitpid(-1, &status, 0);

        if (exited < 0) {
            /*
             * waitpid returned an error.  This happens when there are no
             * children left (ECHILD).  Yield and retry — there is nothing
             * else for PID 1 to do.
             */
            syscall(24 /* SYS_sched_yield */);
            continue;
        }

        if (exited == compositor_pid) {
            if (WIFEXITED(status)) {
                puts_fd(2, "[init] compositor exited, code=");
                putint_fd(2, WEXITSTATUS(status));
                write(2, "\n", 1);
            } else if (WIFSIGNALED(status)) {
                puts_fd(2, "[init] compositor killed by signal=");
                putint_fd(2, WTERMSIG(status));
                write(2, "\n", 1);
            }

            puts_fd(1, "[init] restarting compositor in " \
                       RESTART_DELAY_SEC == 1 ? "1" : "?" " second...");
            sleep_sec(RESTART_DELAY_SEC);
            compositor_pid = spawn_compositor();
        }
        /* Any other child: reaped, nothing to do. */
    }

    return 0; /* unreachable */
}
