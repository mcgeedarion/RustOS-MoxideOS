/*
 * userspace/libc-shim/shim.h — minimal libc shim for RustOS userspace
 *
 * Used by binaries that are NOT linked against musl (e.g. bare Rust
 * userspace crates compiled with #![no_std]).  Provides just enough C
 * surface area for init and shell to link against without a full libc:
 *
 *   - Raw syscall wrappers (x86_64 and riscv64)
 *   - write / read / open / close / exit / fork / execve / waitpid
 *   - nanosleep / sched_yield / getcwd / chdir
 *   - A tiny string library: strlen, strcmp, memcpy, memset
 *
 * Include shim.h and compile shim.c alongside your binary:
 *
 *     musl-gcc -static -nostdlib -o init init.c ../libc-shim/shim.c
 *
 * When musl IS available, do NOT include this file — musl already
 * provides all of these with full POSIX semantics.
 */

#pragma once

#include <stddef.h>   /* size_t */
#include <stdint.h>   /* int64_t, uint64_t */

/* ─── types ─────────────────────────────────────────────────────────── */
typedef int            pid_t;
typedef unsigned int   mode_t;
typedef long           ssize_t;

/* ─── syscall numbers (x86_64 Linux / RustOS ABI) ───────────────────── */
#define SYS_READ        0
#define SYS_WRITE       1
#define SYS_OPEN        2
#define SYS_CLOSE       3
#define SYS_NANOSLEEP  35
#define SYS_FORK       57
#define SYS_EXECVE     59
#define SYS_EXIT       60
#define SYS_WAIT4      61
#define SYS_SCHED_YIELD 24
#define SYS_GETCWD     79
#define SYS_CHDIR      80

/* ─── raw syscall (x86_64) ──────────────────────────────────────────── */
/*
 * Declared here; defined in shim.c (or shim_asm.s for the asm version).
 * Returns the raw kernel value; negative means -errno.
 */
long shim_syscall(long nr,
                  long a1, long a2, long a3,
                  long a4, long a5, long a6);

/* ─── POSIX-compatible wrappers ─────────────────────────────────────── */
ssize_t shim_write(int fd, const void *buf, size_t n);
ssize_t shim_read (int fd,       void *buf, size_t n);
int     shim_open (const char *path, int flags, mode_t mode);
int     shim_close(int fd);
void    shim_exit (int code) __attribute__((noreturn));
pid_t   shim_fork (void);
int     shim_execve(const char *path, char *const argv[], char *const envp[]);
int     shim_waitpid(pid_t pid, int *status, int options);
int     shim_nanosleep(long sec, long nsec);
int     shim_sched_yield(void);
char   *shim_getcwd(char *buf, size_t size);
int     shim_chdir(const char *path);

/* ─── minimal string library ─────────────────────────────────────────── */
size_t shim_strlen (const char *s);
int    shim_strcmp (const char *a, const char *b);
void  *shim_memcpy (void *dst, const void *src, size_t n);
void  *shim_memset (void *dst, int c, size_t n);

/*
 * Convenience macros so callers can use the un-prefixed POSIX names
 * without conflicting with musl when musl is present.  Guard with
 * __rustos_shim__ so musl-linked translation units are unaffected.
 */
#ifdef __rustos_shim__
#  define write(fd,buf,n)         shim_write((fd),(buf),(n))
#  define read(fd,buf,n)          shim_read((fd),(buf),(n))
#  define open(path,flags,...)    shim_open((path),(flags),0)
#  define close(fd)               shim_close(fd)
#  define _exit(c)                shim_exit(c)
#  define fork()                  shim_fork()
#  define execve(p,a,e)           shim_execve((p),(a),(e))
#  define waitpid(p,s,o)          shim_waitpid((p),(s),(o))
#  define getcwd(b,n)             shim_getcwd((b),(n))
#  define chdir(p)                shim_chdir(p)
#  define strlen(s)               shim_strlen(s)
#  define strcmp(a,b)             shim_strcmp((a),(b))
#  define memcpy(d,s,n)           shim_memcpy((d),(s),(n))
#  define memset(d,c,n)           shim_memset((d),(c),(n))
#endif /* __rustos_shim__ */
