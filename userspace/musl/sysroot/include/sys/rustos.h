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

/* ── Hybrid service-plane syscalls ───────────────────────────────────── */
static inline long rustos_driver_bind(unsigned int bdf, unsigned int cap_flags)
{
    return syscall(SYS_RUSTOS_DRIVER_BIND, bdf, cap_flags);
}

static inline long rustos_dma_alloc(unsigned long handle, unsigned long size,
                                    unsigned long align, unsigned long *phys_out)
{
    return syscall(SYS_RUSTOS_DMA_ALLOC, handle, size, align, phys_out);
}

static inline long rustos_irq_subscribe(unsigned long handle, unsigned int irq,
                                        unsigned long endpoint)
{
    return syscall(SYS_RUSTOS_IRQ_SUBSCRIBE, handle, irq, endpoint);
}

static inline long rustos_irq_ack(unsigned long handle, unsigned int irq)
{
    return syscall(SYS_RUSTOS_IRQ_ACK, handle, irq);
}

static inline long rustos_scheme_register(const char *name, unsigned long len,
                                          unsigned long endpoint)
{
    return syscall(SYS_RUSTOS_SCHEME_REGISTER, name, len, endpoint);
}

static inline long rustos_scheme_unregister(const char *name, unsigned long len)
{
    return syscall(SYS_RUSTOS_SCHEME_UNREGISTER, name, len);
}

static inline unsigned long rustos_ipc_endpoint_create(void)
{
    return (unsigned long)syscall(SYS_RUSTOS_IPC_ENDPOINT_CREATE);
}

static inline long rustos_ipc_recv(unsigned long endpoint, void *buf, unsigned long len)
{
    return syscall(SYS_RUSTOS_IPC_RECV, endpoint, buf, len);
}

static inline long rustos_ipc_send(unsigned long endpoint, const void *buf, unsigned long len)
{
    return syscall(SYS_RUSTOS_IPC_SEND, endpoint, buf, len);
}

#ifdef __cplusplus
}
#endif
#endif /* _SYS_RUSTOS_H */
