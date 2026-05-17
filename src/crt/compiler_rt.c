#include <stddef.h>

/* Forward declarations */
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
void *memmove(void *dst, const void *src, size_t n);

/*
 * Fortified variants emitted by clang/gcc when _FORTIFY_SOURCE is set.
 * We skip the length check — the kernel controls its own memory.
 */
void *__memcpy_chk(void *dst, const void *src, size_t n, size_t dstlen)
{
    (void)dstlen;
    return memcpy(dst, src, n);
}

void *__memset_chk(void *s, int c, size_t n, size_t slen)
{
    (void)slen;
    return memset(s, c, n);
}

void *__memmove_chk(void *dst, const void *src, size_t n, size_t dstlen)
{
    (void)dstlen;
    return memmove(dst, src, n);
}

/*
 * __stack_chk_fail — called on stack-smashing detection.
 * A real implementation would panic; stub loops forever for now.
 */
void __stack_chk_fail(void)
{
    for (;;) {}
}

/* Provide a dummy stack canary value */
__attribute__((weak)) unsigned long __stack_chk_guard = 0xdeadbeefcafe0000UL;
