/*
 * userspace/kmtest/kmtest.c
 *
 * Userspace runner for the RustOS kernel test harness.
 *
 * Usage:
 *   kmtest                  -- run all kernel tests
 *   kmtest <name> [name...] -- run only the named tests
 *
 * Exit status:
 *   0   all tests passed
 *   1   one or more tests failed
 *   2   usage / syscall error
 *
 * The runner communicates with the kernel via two private syscalls:
 *
 *   SYS_KMTEST_LIST (0x80000000)
 *     a0 = 0, a1 = 0   -> returns total test count
 *     a0 = buf, a1 = len -> fills buf with NUL-terminated names, returns
 *                           the number of names written
 *
 *   SYS_KMTEST_RUN (0x80000001)
 *     a0 = index        -> run one test by index; returns 0=pass, 1=fail
 *     a0 = ~0UL         -> run all tests; returns failure count
 *
 * The kernel streams KMTEST lines to the serial console; this binary
 * prints a human-readable summary to stdout so it is also visible in
 * the QEMU monitor / virtio console.
 *
 * Serial output (kernel side, already streamed by the kernel):
 *   KMTEST  PASS  <name>
 *   KMTEST  FAIL  <name> -- <reason>
 *   KMTEST  DONE  <passed>/<total> passed
 *
 * This binary additionally prints a compact summary table.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ── Private syscall numbers ──────────────────────────────────────────────── */
#define SYS_KMTEST_LIST  0x80000000UL
#define SYS_KMTEST_RUN   0x80000001UL

/* Run all tests when passed as the index argument to SYS_KMTEST_RUN. */
#define KMTEST_RUN_ALL   (~(unsigned long)0)

/* Maximum number of tests we support listing. */
#define MAX_TESTS        512
/* Maximum length of a single test name (NUL-terminated). */
#define NAME_MAX_LEN     128
/* Total name buffer: worst case all tests have 127-char names. */
#define NAME_BUF_SIZE    (MAX_TESTS * NAME_MAX_LEN)

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static void write_str(const char *s) {
    write(STDOUT_FILENO, s, strlen(s));
}

static void write_line(const char *s) {
    write_str(s);
    write_str("\n");
}

/*
 * Print a decimal integer n into buf (must be at least 21 bytes).
 * Returns a pointer to the start of the number within buf.
 */
static char *fmt_ul(char *buf, unsigned long n) {
    char *end = buf + 20;
    *end = '\0';
    if (n == 0) { *--end = '0'; return end; }
    while (n) { *--end = '0' + (n % 10); n /= 10; }
    return end;
}

/* ── Core logic ───────────────────────────────────────────────────────────── */

/*
 * Query the kernel for how many tests exist and fill names[] with their
 * NUL-terminated name strings.  Returns the test count, or -1 on error.
 */
static long list_tests(char names[][NAME_MAX_LEN], long max) {
    /* Step 1: get the count. */
    long count = syscall(SYS_KMTEST_LIST, 0UL, 0UL);
    if (count < 0) {
        write_line("kmtest: SYS_KMTEST_LIST failed");
        return -1;
    }
    if (count == 0) {
        write_line("kmtest: no tests registered in kernel");
        return 0;
    }
    if (count > max) count = max;

    /* Step 2: fetch names into a flat byte buffer. */
    static char raw[NAME_BUF_SIZE];
    long written = syscall(SYS_KMTEST_LIST, (unsigned long)raw,
                           (unsigned long)sizeof(raw));
    if (written < 0) {
        write_line("kmtest: SYS_KMTEST_LIST (names) failed");
        return -1;
    }

    /* Parse NUL-terminated strings out of the flat buffer. */
    char *p = raw;
    char *end = raw + sizeof(raw);
    long i = 0;
    while (i < written && p < end) {
        size_t len = strnlen(p, (size_t)(end - p));
        if (len == 0) break;
        if (len >= NAME_MAX_LEN) len = NAME_MAX_LEN - 1;
        memcpy(names[i], p, len);
        names[i][len] = '\0';
        p += len + 1;  /* skip the NUL */
        i++;
    }
    return i;
}

/*
 * Find the index of a test by name.  Returns -1 if not found.
 */
static long find_test(char names[][NAME_MAX_LEN], long count,
                      const char *target) {
    for (long i = 0; i < count; i++) {
        if (strcmp(names[i], target) == 0) return i;
    }
    return -1;
}

/*
 * Run a single test by index.  Prints one PASS/FAIL line to stdout.
 * Returns 0 on pass, 1 on fail.
 */
static int run_one(long idx, const char *name) {
    long ret = syscall(SYS_KMTEST_RUN, (unsigned long)idx);
    char line[NAME_MAX_LEN + 16];
    if (ret == 0) {
        snprintf(line, sizeof(line), "  PASS  %s", name);
    } else {
        snprintf(line, sizeof(line), "  FAIL  %s", name);
    }
    write_line(line);
    return (ret != 0) ? 1 : 0;
}

int main(int argc, char **argv) {
    static char names[MAX_TESTS][NAME_MAX_LEN];

    long count = list_tests(names, MAX_TESTS);
    if (count < 0) return 2;
    if (count == 0) return 0;  /* nothing to run is a pass */

    /* Print header. */
    char numbuf[21];
    write_str("kmtest: ");
    write_str(fmt_ul(numbuf, (unsigned long)count));
    write_line(" test(s) registered");
    write_line("----");

    long failures = 0;
    long ran      = 0;

    if (argc <= 1) {
        /* Run all tests in order. */
        for (long i = 0; i < count; i++) {
            failures += run_one(i, names[i]);
            ran++;
        }
    } else {
        /* Run only the tests named on the command line. */
        for (int a = 1; a < argc; a++) {
            long idx = find_test(names, count, argv[a]);
            if (idx < 0) {
                char msg[NAME_MAX_LEN + 32];
                snprintf(msg, sizeof(msg),
                         "kmtest: unknown test '%s' (skipped)", argv[a]);
                write_line(msg);
                continue;
            }
            failures += run_one(idx, names[idx]);
            ran++;
        }
    }

    /* Summary line. */
    write_line("----");
    {
        char buf[64];
        long passed = ran - failures;
        snprintf(buf, sizeof(buf), "kmtest: %ld/%ld passed", passed, ran);
        write_line(buf);
    }

    return (failures > 0) ? 1 : 0;
}
