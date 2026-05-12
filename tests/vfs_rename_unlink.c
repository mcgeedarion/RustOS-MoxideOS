#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

static const char *tmpdir(void) {
    const char *p = getenv("TEST_TMPDIR");
    return (p && *p) ? p : ".";
}

int main(void)
{
    char a[256], b[256], sl[256];
    snprintf(a, sizeof(a), "%s/rustos_vfs_a", tmpdir());
    snprintf(b, sizeof(b), "%s/rustos_vfs_b", tmpdir());
    snprintf(sl, sizeof(sl), "%s/rustos_vfs_sl", tmpdir());

    unlink(a); unlink(b); unlink(sl);

    int fd = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); return 1; }
    if (write(fd, "hello", 5) != 5) { perror("write"); close(fd); return 1; }
    close(fd);

    if (rename(a, b) != 0) { perror("rename"); return 1; }

    struct stat st;
    errno = 0;
    if (stat(a, &st) == 0) { puts("FAIL A still exists after rename"); return 1; }
    if (errno != ENOENT)   { puts("FAIL wrong errno after stat A"); return 1; }

    if (stat(b, &st) != 0) { perror("stat B"); return 1; }
    if (st.st_size != 5)   { puts("FAIL size mismatch"); return 1; }

    if (symlink(b, sl) != 0) { perror("symlink"); return 1; }
    char link_target[256] = {0};
    ssize_t len = readlink(sl, link_target, sizeof(link_target) - 1);
    if (len < 0) { perror("readlink"); return 1; }
    link_target[len] = '\0';
    if (strcmp(link_target, b) != 0) { puts("FAIL symlink target mismatch"); return 1; }

    if (unlink(b) != 0)  { perror("unlink B"); return 1; }
    if (unlink(sl) != 0) { perror("unlink SL"); return 1; }

    puts("PASS");
    return 0;
}
