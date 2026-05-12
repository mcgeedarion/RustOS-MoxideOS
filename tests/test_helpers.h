/* tests/test_helpers.h
 *
 * Shared macros for the rustos test suite.
 *
 * All tests:
 *   - print "PASS", "FAIL: <reason>", or "SKIP: <reason>" to stdout
 *   - return 0 on PASS or SKIP, 1 on FAIL
 *   - are compiled with musl-gcc -static via tests/run_tests.sh
 */
#ifndef RUSTOS_TEST_HELPERS_H
#define RUSTOS_TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Emit PASS and exit 0. */
#define TEST_PASS() do { puts("PASS"); exit(0); } while (0)

/* Emit SKIP with reason and exit 0. */
#define TEST_SKIP(reason) do { puts("SKIP: " reason); exit(0); } while (0)

/* Emit FAIL with reason and exit 1. */
#define TEST_FAIL(reason) do { puts("FAIL: " reason); exit(1); } while (0)

/* Emit FAIL with formatted message and exit 1. */
#define TEST_FAILF(fmt, ...) \
    do { fprintf(stdout, "FAIL: " fmt "\n", ##__VA_ARGS__); exit(1); } while (0)

/* Check condition; FAIL with message if false. */
#define TEST_ASSERT(cond, reason) \
    do { if (!(cond)) TEST_FAIL(reason); } while (0)

/* Check syscall return; FAIL with perror-style message if rc < 0. */
#define TEST_SYSCALL(rc, name) \
    do { if ((rc) < 0) TEST_FAILF("%s: %s", name, strerror(errno)); } while (0)

#endif /* RUSTOS_TEST_HELPERS_H */
