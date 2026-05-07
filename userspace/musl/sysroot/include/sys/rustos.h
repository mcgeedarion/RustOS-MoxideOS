/*
 * <sys/rustos.h> — RustOS-specific extensions for musl userspace.
 *
 * Included automatically when __rustos__ is defined by the build system.
 * Provides:
 *   - rustos_version()        — kernel version query (syscall 500)
 *   - rustos_debug_print()    — write string to kernel log (syscall 501, debug)
 *   - AT_RUSTOS_*             — RustOS aux-vector entries
 *   - RUSTOS_MAP_*            — mmap flag extensions
 */
#ifndef _SYS_RUSTOS_H
#define _SYS_RUSTOS_H

#include <sys/types.h>
#include <sys/syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Aux-vector tags (Linux-compatible range 32-47 reserved for OS use) ── */
#define AT_RUSTOS_VERSION    32   /* kernel version word: major<<16|minor */
#define AT_RUSTOS_FEATURES   33   /* feature bitmask (see below) */

/* Feature bits returned in AT_RUSTOS_FEATURES */
#define RUSTOS_FEAT_VDSO     (1UL << 0)  /* vDSO page present */
#define RUSTOS_FEAT_PTI      (1UL << 1)  /* PTI active */
#define RUSTOS_FEAT_SMP      (1UL << 2)  /* SMP enabled, ncpus > 1 */

/* ── mmap flag extensions ─────────────────────────────────────────────── */
/* Standard Linux flags are reused; these are RustOS-only bits */
#define RUSTOS_MAP_HUGE2M    0x40000  /* hint: back with 2 MiB pages */
#define RUSTOS_MAP_FIXED_NOREPLACE 0x100000  /* MAP_FIXED without clobbering */

/* ── Syscall: rustos_version ─────────────────────────────────────────── */
/*
 * Returns a version word: (major << 16) | minor.
 * Syscall number 500 (above the Linux table, RustOS-private range).
 */
static inline unsigned long rustos_version(void)
{
    return (unsigned long)syscall(500);
}

/* ── Syscall: rustos_debug_print ─────────────────────────────────────── */
/*
 * Write a NUL-terminated string to the kernel debug log.
 * Only available in debug builds (returns -ENOSYS in release).
 */
static inline int rustos_debug_print(const char *msg)
{
    return (int)syscall(501, msg);
}

#ifdef __cplusplus
}
#endif
#endif /* _SYS_RUSTOS_H */
