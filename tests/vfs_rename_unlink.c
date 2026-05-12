/* tests/vfs_rename_unlink.c
 *
 * Smoke: atomic rename, unlink+ENOENT, symlink+readlink.
 *
 * Creates a file, renames it, verifies the source is gone (ENOENT),
 * verifies the destination has the correct size, creates a symlink and
 * confirms readlink returns the expected target.
 * Targets rename / unlink / symlink in src/fs/vfs.rs.
 *
 * Set TEST_TMPDIR to override the directory used for temp files.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "test_helpers.h"

static const char *tmpdir_path(void) {
    const char *p = getenv("TEST_TMPDIR");
    return (p && *p) ? p : ".";
}

int main(void) {
    char a[256], b[256], sl[256];
    const char *td = tmpdir_path();
    snprintf(a,  sizeof(a),  "%s/rustos_vfs_a",  td);
    snprintf(b,  sizeof(b),  "%s/rustos_vfs_b",  td);
    snprintf(sl, sizeof(sl), "%s/rustos_vfs_sl", td);

    /* Clean up any leftovers from a previous run. */
    unlink(a); unlink(b); unlink(sl);

    /* Create file A. */
    int fd = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    TEST_SYSCALL(fd, "open");
    TEST_SYSCALL((int)write(fd, "hello", 5) - 5, "write");
    close(fd);

    /* Rename A → B (must be atomic). */
    TEST_SYSCALL(rename(a, b), "rename");

    /* A must no longer exist. */
    struct stat st;
    errno = 0;
    if (stat(a, &st) == 0)
        TEST_FAIL("source still exists after rename");
    if (errno != ENOENT)
        TEST_FAILF("expected ENOENT after stat(A), got errno=%d", errno);

    /* B must have the correct size. */
    TEST_SYSCALL(stat(b, &st), "stat B");
    if (st.st_size != 5)
        TEST_FAILF("size mismatch: expected 5, got %ld", (long)st.st_size);

    /* Symlink SL → B, verify with readlink. */
    TEST_SYSCALL(symlink(b, sl), "symlink");
    char target[256] = {0};
    ssize_t len = readlink(sl, target, sizeof(target) - 1);
    TEST_SYSCALL((int)len, "readlink");
    target[len] = '\0';
    if (strcmp(target, b) != 0)
        TEST_FAILF("symlink target mismatch: got '%s' expected '%s'", target, b);

    /* Clean up. */
    TEST_SYSCALL(unlink(b),  "unlink B");
    TEST_SYSCALL(unlink(sl), "unlink SL");

    TEST_PASS();
}
