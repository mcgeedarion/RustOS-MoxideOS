/* tests/test_helpers.h — shared macros for the rustos test suite.
 *
 * Conventions (mirrors userspace/init/init.c):
 *   - Diagnostic detail  → stderr  (fd 2)
 *   - Runner token       → stdout  (fd 1)  matched by run_tests.sh *PASS*/*FAIL*/*SKIP*
 *   - No printf in main paths; test macros use puts() + fprintf(stderr)
 *   - exit() is acceptable here (tests run in a fully-initialized musl env)
 *   - _exit() is used in fork() children (consistent with init.c)
 *
 * Syscalls exercised by these macros:
 *   write(1, ...)   — SYS_write = 1
 *   write(2, ...)   — SYS_write = 1
 *   exit(n)         — SYS_exit  = 60
 */
#ifndef RUSTOS_TEST_HELPERS_H
#define RUSTOS_TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ── Pass / skip ────────────────────────────────────────────────────────── */

/* Emit PASS token to stdout and exit 0. */
#define TEST_PASS() \
    do { puts("PASS"); exit(0); } while (0)

/* Emit SKIP token to stdout with reason and exit 0. */
#define TEST_SKIP(reason) \
    do { puts("SKIP: " reason); exit(0); } while (0)

/* ── Failure ────────────────────────────────────────────────────────────── */

/*
 * All TEST_FAIL* macros:
 *   1. Write the diagnostic reason to stderr so run_tests.sh captures it
 *      on the rerun pass ("$bin || true").
 *   2. Write the bare FAIL token to stdout so the runner's *FAIL* glob fires.
 *   3. exit(1).
 */

/* Emit FAIL with a fixed string reason. */
#define TEST_FAIL(reason) \
    do { fprintf(stderr, "  detail: " reason "\n"); \
         puts("FAIL"); exit(1); } while (0)

/* Emit FAIL with a printf-style formatted reason. */
#define TEST_FAILF(fmt, ...) \
    do { fprintf(stderr, "  detail: " fmt "\n", ##__VA_ARGS__); \
         puts("FAIL"); exit(1); } while (0)

/* ── Assertion helpers ──────────────────────────────────────────────────── */

/* Fail with message if condition is false. */
#define TEST_ASSERT(cond, reason) \
    do { if (!(cond)) TEST_FAIL(reason); } while (0)

/*
 * Fail with a perror-style message if rc < 0.
 * Prints:  detail: <name>: <strerror(errno)>
 */
#define TEST_SYSCALL(rc, name) \
    do { if ((rc) < 0) TEST_FAILF("%s: %s", name, strerror(errno)); } while (0)

#endif /* RUSTOS_TEST_HELPERS_H */
