#include <stddef.h>
#include <stdint.h>

#ifndef CRT_ASSERT
#define CRT_ASSERT(x) ((void)0)
#endif

/*
 * Copy n bytes from src to dst.
 *
 * The source and destination ranges must not overlap.
 * Use memmove for overlapping regions.
 */
void *memcpy(void *__restrict__ dst, const void *__restrict__ src, size_t n)
{
#if defined(KDEBUG)
    if (n != 0) {
        CRT_ASSERT(dst != NULL);
        CRT_ASSERT(src != NULL);

        uintptr_t d = (uintptr_t)dst;
        uintptr_t s = (uintptr_t)src;

        /*
         * Avoid d + n / s + n because those can wrap.
         * Ranges do not overlap iff their distance is at least n.
         */
        CRT_ASSERT(d <= s ? (s - d) >= n : (d - s) >= n);
    }
#endif

    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dst;
}
