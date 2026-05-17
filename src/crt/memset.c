#include <stddef.h>

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    unsigned char val = (unsigned char)c;

    while (n--) {
        *p++ = val;
    }
    return s;
}
