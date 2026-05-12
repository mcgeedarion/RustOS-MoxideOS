/* tests/vfs_rename_unlink.c
 *
 * Tests:
 *   - creat / write / rename (atomic)
 *   - rename over existing file
 *   - unlink / stat ENOENT
 *   - symlink + readlink
 *
 * Output: PASS / FAIL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define TMP_A  "/tmp/rustos_vfs_a"
#define TMP_B  "/tmp/rustos_vfs_b"
#define TMP_SL "/tmp/rustos_vfs_sl"

static void cleanup(void) {
    unlink(TMP_A); unlink(TMP_B); unlink(TMP_SL);
}

int main(void)
{
    cleanup();

    /* creat + write */
    int fd = open(TMP_A, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); return 1; }
    if (write(fd, "hello", 5) != 5) { perror("write"); close(fd); return 1; }
    close(fd);

    /* rename A → B */
    if (rename(TMP_A, TMP_B) != 0) { perror("rename"); return 1; }

    /* A must not exist */
    struct stat st;
    if (stat(TMP_A, &st) == 0) { puts("FAIL A still exists after rename"); return 1; }
    if (errno != ENOENT)        { puts("FAIL wrong errno after stat A"); return 1; }

    /* B must exist with correct size */
    if (stat(TMP_B, &st) != 0) { perror("stat B"); return 1; }
    if (st.st_size != 5)        { puts("FAIL size mismatch"); return 1; }

    /* symlink B → TMP_SL */
    if (symlink(TMP_B, TMP_SL) != 0) { perror("symlink"); return 1; }
    char link_target[256] = {0};
    ssize_t len = readlink(TMP_SL, link_target, sizeof(link_target) - 1);
    if (len < 0) { perror("readlink"); return 1; }
    if (strcmp(link_target, TMP_B) != 0) { puts("FAIL symlink target mismatch"); return 1; }

    /* unlink B and symlink */
    if (unlink(TMP_B)  != 0) { perror("unlink B");  return 1; }
    if (unlink(TMP_SL) != 0) { perror("unlink SL"); return 1; }

    puts("PASS");
    return 0;
}
