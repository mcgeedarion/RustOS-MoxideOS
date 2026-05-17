/*
 * userspace/shell/shell.c — minimal interactive shell for RustOS
 *
 * Compiled as a static musl binary; no dynamic linker.
 * Syscalls used (all must be live in src/syscall/mod.rs):
 *
 *   read(0, buf, n)              SYS_read      =  0
 *   write(fd, buf, n)            SYS_write     =  1
 *   open(path, flags)            SYS_open      =  2
 *   close(fd)                    SYS_close     =  3
 *   execve(path, argv, envp)     SYS_execve    = 59
 *   exit(code)                   SYS_exit      = 60
 *   fork()                       SYS_fork      = 57
 *   waitpid(pid, st, 0)          SYS_wait4     = 61
 *   getcwd(buf, n)               SYS_getcwd    = 79
 *   chdir(path)                  SYS_chdir     = 80
 *
 * Built-in commands: exit, cd, pwd, echo, help
 * External commands: fork + execve from PATH entries /bin and /usr/bin
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

/* ─── tunables ────────────────────────────────────────────────────────── */
#define LINE_MAX   512
#define ARG_MAX     64
#define CWD_MAX    256

/* ─── tiny write helpers (avoid printf / libc buffering) ────────────── */
static void ws(const char *s)
{
    const char *p = s;
    while (*p) p++;
    write(STDOUT_FILENO, s, (size_t)(p - s));
}
static void ws2(const char *s)
{
    const char *p = s;
    while (*p) p++;
    write(STDERR_FILENO, s, (size_t)(p - s));
}
static void wsnl(const char *s) { ws(s);  write(STDOUT_FILENO, "\n", 1); }
static void ws2nl(const char *s){ ws2(s); write(STDERR_FILENO, "\n", 1); }

/* ─── read one line from stdin ──────────────────────────────────────── */
/*
 * Returns number of chars in *buf (excluding NUL), or -1 on EOF/error.
 * Strips the trailing newline.
 */
static int readline(char *buf, int max)
{
    int n = 0;
    while (n < max - 1) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) return -1;          /* EOF or error */
        if (c == '\n') break;
        buf[n++] = c;
    }
    buf[n] = '\0';
    return n;
}

/* ─── tokenise a line into argv[] ───────────────────────────────────── */
/*
 * Splits on spaces/tabs.  Modifies buf in-place.
 * Returns argc (0 for blank lines).
 */
static int tokenise(char *buf, char *argv[], int argv_max)
{
    int argc = 0;
    char *p = buf;
    while (*p) {
        /* skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (argc >= argv_max - 1) break;
        argv[argc++] = p;
        /* scan to end of token */
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = '\0';
    }
    argv[argc] = NULL;
    return argc;
}

/* ─── PATH search: try /bin/<cmd> then /usr/bin/<cmd> ──────────────── */
static const char *path_dirs[] = { "/bin", "/usr/bin", NULL };

static int find_exe(const char *cmd, char *out, int out_len)
{
    /* Absolute path — use directly */
    if (cmd[0] == '/') {
        int n = 0;
        while (cmd[n] && n < out_len - 1) { out[n] = cmd[n]; n++; }
        out[n] = '\0';
        return 0;
    }
    for (int i = 0; path_dirs[i]; i++) {
        int n = 0;
        const char *d = path_dirs[i];
        while (d[n] && n < out_len - 2) { out[n] = d[n]; n++; }
        out[n++] = '/';
        int c = 0;
        while (cmd[c] && n < out_len - 1) { out[n++] = cmd[c++]; }
        out[n] = '\0';
        /* access(2) would need kernel support; use open as a probe */
        int fd = open(out, O_RDONLY);
        if (fd >= 0) { close(fd); return 0; }
    }
    return -1;
}

/* ─── built-in: pwd ─────────────────────────────────────────────────── */
static void builtin_pwd(void)
{
    char cwd[CWD_MAX];
    if (getcwd(cwd, sizeof(cwd))) wsnl(cwd);
    else ws2nl("shell: pwd: getcwd failed");
}

/* ─── built-in: cd ──────────────────────────────────────────────────── */
static void builtin_cd(char *argv[])
{
    const char *target = argv[1] ? argv[1] : "/";
    if (chdir(target) < 0) {
        ws2("shell: cd: ");
        ws2nl(target);
    }
}

/* ─── built-in: echo ────────────────────────────────────────────────── */
static void builtin_echo(char *argv[])
{
    for (int i = 1; argv[i]; i++) {
        ws(argv[i]);
        if (argv[i + 1]) write(STDOUT_FILENO, " ", 1);
    }
    write(STDOUT_FILENO, "\n", 1);
}

/* ─── built-in: help ────────────────────────────────────────────────── */
static void builtin_help(void)
{
    wsnl("rustos-shell built-ins:");
    wsnl("  exit [code]   — exit the shell");
    wsnl("  cd [dir]      — change directory (default /)");
    wsnl("  pwd           — print working directory");
    wsnl("  echo [args…]  — print arguments");
    wsnl("  help          — this text");
    wsnl("External commands are searched in /bin and /usr/bin.");
}

/* ─── run an external command via fork+execve ───────────────────────── */
static void run_external(char *argv[], char *envp[])
{
    char exe[CWD_MAX + 64];
    if (find_exe(argv[0], exe, (int)sizeof(exe)) < 0) {
        ws2("shell: not found: ");
        ws2nl(argv[0]);
        return;
    }

    pid_t pid = fork();
    if (pid < 0) { ws2nl("shell: fork failed"); return; }

    if (pid == 0) {
        execve(exe, argv, envp);
        ws2("shell: exec failed: ");
        ws2nl(exe);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        ws2("shell: killed by signal ");
        /* small itoa */
        int sig = WTERMSIG(status);
        char d = (char)('0' + sig % 10);
        if (sig >= 10) {
            char d2 = (char)('0' + sig / 10);
            write(STDERR_FILENO, &d2, 1);
        }
        write(STDERR_FILENO, &d, 1);
        write(STDERR_FILENO, "\n", 1);
    }
}

/* ─── main ──────────────────────────────────────────────────────────── */
int main(void)
{
    char *default_envp[] = {
        "HOME=/root",
        "PATH=/bin:/usr/bin",
        "TERM=vt100",
        NULL
    };

    wsnl("rustos-shell 0.1  (type 'help' for built-ins)");

    char  line[LINE_MAX];
    char *argv[ARG_MAX];

    for (;;) {
        /* prompt */
        char cwd[CWD_MAX];
        ws(getcwd(cwd, sizeof(cwd)) ? cwd : "?");
        ws(" $ ");

        int n = readline(line, LINE_MAX);
        if (n < 0) {
            wsnl("\n[shell] EOF — exiting");
            break;
        }
        if (n == 0) continue;

        int argc = tokenise(line, argv, ARG_MAX);
        if (argc == 0) continue;

        /* ── dispatch ──────────────────────────────────────────────── */
        if (strcmp(argv[0], "exit") == 0) {
            int code = argv[1] ? (int)(argv[1][0] - '0') : 0;
            _exit(code);
        } else if (strcmp(argv[0], "cd") == 0) {
            builtin_cd(argv);
        } else if (strcmp(argv[0], "pwd") == 0) {
            builtin_pwd();
        } else if (strcmp(argv[0], "echo") == 0) {
            builtin_echo(argv);
        } else if (strcmp(argv[0], "help") == 0) {
            builtin_help();
        } else {
            run_external(argv, default_envp);
        }
    }

    return 0;
}
