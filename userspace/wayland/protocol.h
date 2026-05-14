/*
 * userspace/wayland/protocol.h — Wayland wire-protocol constants and helpers
 *
 * All opcodes, object-ID conventions, fixed-point macros, and SCM_RIGHTS
 * ancillary-data helpers used by compositor.c are centralised here so
 * compositor.c stays focused on logic, not magic numbers.
 *
 * Naming convention
 * -----------------
 *   WL_<INTERFACE>_EVT_<NAME>   — event opcode  (compositor → client)
 *   WL_<INTERFACE>_REQ_<NAME>   — request opcode (client → compositor)
 *   WL_<INTERFACE>_VERSION      — maximum advertised version
 *
 * All opcodes are uint16_t; they start at 0 for each interface.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* ── wl_display (object id = 1, always) ────────────────────────────────── */
#define WL_DISPLAY_ID                   1u
#define WL_DISPLAY_REQ_SYNC             0u   /* → new wl_callback id */
#define WL_DISPLAY_REQ_GET_REGISTRY     1u   /* → new wl_registry id */
#define WL_DISPLAY_EVT_ERROR            0u
#define WL_DISPLAY_EVT_DELETE_ID        1u

/* ── wl_registry (object id assigned by client) ────────────────────────── */
#define WL_REGISTRY_REQ_BIND            0u
#define WL_REGISTRY_EVT_GLOBAL          0u
#define WL_REGISTRY_EVT_GLOBAL_REMOVE   1u

/* ── wl_callback ────────────────────────────────────────────────────────── */
#define WL_CALLBACK_EVT_DONE            0u

/* ── wl_compositor ──────────────────────────────────────────────────────── */
#define WL_COMPOSITOR_VERSION           5u
#define WL_COMPOSITOR_REQ_CREATE_SURFACE 0u
#define WL_COMPOSITOR_REQ_CREATE_REGION  1u

/* ── wl_shm ─────────────────────────────────────────────────────────────── */
#define WL_SHM_VERSION                  1u
#define WL_SHM_REQ_CREATE_POOL          0u
#define WL_SHM_EVT_FORMAT               0u
/* Pixel formats */
#define WL_SHM_FORMAT_ARGB8888          0u
#define WL_SHM_FORMAT_XRGB8888          1u

/* ── wl_shm_pool ─────────────────────────────────────────────────────────── */
#define WL_SHM_POOL_REQ_CREATE_BUFFER   0u
#define WL_SHM_POOL_REQ_DESTROY         1u
#define WL_SHM_POOL_REQ_RESIZE          2u

/* ── wl_buffer ───────────────────────────────────────────────────────────── */
#define WL_BUFFER_REQ_DESTROY           0u
#define WL_BUFFER_EVT_RELEASE           0u

/* ── wl_surface ──────────────────────────────────────────────────────────── */
#define WL_SURFACE_VERSION              5u
#define WL_SURFACE_REQ_DESTROY          0u
#define WL_SURFACE_REQ_ATTACH           1u
#define WL_SURFACE_REQ_DAMAGE           2u
#define WL_SURFACE_REQ_FRAME            3u
#define WL_SURFACE_REQ_SET_OPAQUE       4u
#define WL_SURFACE_REQ_SET_INPUT        5u
#define WL_SURFACE_REQ_COMMIT           6u
#define WL_SURFACE_REQ_SET_BUFFER_TRANSFORM 7u
#define WL_SURFACE_REQ_SET_BUFFER_SCALE 8u
#define WL_SURFACE_REQ_DAMAGE_BUFFER    9u
#define WL_SURFACE_EVT_ENTER            0u
#define WL_SURFACE_EVT_LEAVE            1u

/* ── wl_seat ─────────────────────────────────────────────────────────────── */
#define WL_SEAT_VERSION                 7u
#define WL_SEAT_REQ_GET_POINTER         0u
#define WL_SEAT_REQ_GET_KEYBOARD        1u
#define WL_SEAT_REQ_GET_TOUCH           2u
#define WL_SEAT_REQ_RELEASE             3u
#define WL_SEAT_EVT_CAPABILITIES        0u
#define WL_SEAT_EVT_NAME                1u
#define WL_SEAT_CAP_POINTER             1u
#define WL_SEAT_CAP_KEYBOARD            2u
#define WL_SEAT_CAP_TOUCH               4u

/* ── wl_keyboard opcodes (events) ───────────────────────────────────────── */
#define WL_KEYBOARD_EVT_KEYMAP          0u
#define WL_KEYBOARD_EVT_ENTER           1u
#define WL_KEYBOARD_EVT_LEAVE           2u
#define WL_KEYBOARD_EVT_KEY             4u
#define WL_KEYBOARD_EVT_MODIFIERS       5u

/* ── wl_pointer opcodes (events) ────────────────────────────────────────── */
#define WL_POINTER_EVT_ENTER            0u
#define WL_POINTER_EVT_LEAVE            1u
#define WL_POINTER_EVT_MOTION           2u
#define WL_POINTER_EVT_BUTTON           3u
#define WL_POINTER_EVT_AXIS             4u

/* ── wl_output ───────────────────────────────────────────────────────────── */
#define WL_OUTPUT_VERSION               3u
#define WL_OUTPUT_EVT_GEOMETRY          0u
#define WL_OUTPUT_EVT_MODE              1u
#define WL_OUTPUT_EVT_DONE              2u
#define WL_OUTPUT_EVT_SCALE             3u
#define WL_OUTPUT_MODE_CURRENT          0x1u
#define WL_OUTPUT_MODE_PREFERRED        0x2u
#define WL_OUTPUT_SUBPIXEL_UNKNOWN      0u
#define WL_OUTPUT_TRANSFORM_NORMAL      0u

/* ── Well-known global registry names (uint32, 1-based) ─────────────────── */
#define WL_GLOBAL_NAME_COMPOSITOR       1u
#define WL_GLOBAL_NAME_SHM              2u
#define WL_GLOBAL_NAME_SEAT             3u
#define WL_GLOBAL_NAME_OUTPUT           4u

/* ── Wire format helpers ─────────────────────────────────────────────────── */

/* Wayland fixed-point 24.8: integer n → fixed */
static inline int32_t wl_fixed_from_int(int32_t n) { return n * 256; }
/* Wayland fixed-point 24.8: double d → fixed */
static inline int32_t wl_fixed_from_double(double d) { return (int32_t)(d * 256.0); }

/* Read a little-endian uint32 from a byte buffer at offset off. */
static inline uint32_t wl_read_u32(const uint8_t *buf, size_t off) {
    uint32_t v; memcpy(&v, buf + off, 4); return v;
}

/* Read a little-endian int32 from a byte buffer at offset off. */
static inline int32_t wl_read_i32(const uint8_t *buf, size_t off) {
    int32_t v; memcpy(&v, buf + off, 4); return v;
}

/*
 * wl_send — send a Wayland message to client fd.
 *
 *   fd      — connected client socket
 *   obj     — object id (uint32)
 *   opcode  — message opcode (uint16)
 *   payload — additional payload bytes after the 8-byte header
 *   plen    — payload length in bytes
 *
 * Wire layout:
 *   [0..3]  uint32  object_id
 *   [4..5]  uint16  opcode
 *   [6..7]  uint16  total message size (header + payload)
 */
static inline void wl_send(int fd, uint32_t obj, uint16_t opcode,
                            const void *payload, uint16_t plen) {
    uint8_t  buf[4096];
    uint16_t total = (uint16_t)(8u + plen);
    memcpy(buf,     &obj,    4);
    memcpy(buf + 4, &opcode, 2);
    memcpy(buf + 6, &total,  2);
    if (plen && payload) memcpy(buf + 8, payload, plen);
    write(fd, buf, total);
}

/*
 * wl_send_str — encode a Wayland string (uint32 length + padded chars)
 * into *out and return the number of bytes written.  The caller must
 * ensure out has enough space (strlen(s) + 8 bytes is always enough).
 */
static inline size_t wl_encode_str(uint8_t *out, const char *s) {
    uint32_t ilen    = (uint32_t)strlen(s);
    uint32_t ipadded = (ilen + 3u) & ~3u;
    memcpy(out, &ilen, 4);
    memset(out + 4, 0, ipadded);      /* zero-pad including NUL */
    memcpy(out + 4, s, ilen);
    return 4u + ipadded;
}

/*
 * recv_with_fd — receive a message from fd, extracting any SCM_RIGHTS
 * file descriptors passed as ancillary data.  Stores up to max_fds
 * received fds into fds[] and sets *nfds to the count received.
 * Returns number of data bytes read, or -1 on error.
 */
static inline ssize_t recv_with_fd(int sock, void *buf, size_t len,
                                    int *fds, int max_fds, int *nfds) {
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    char cmsg_buf[CMSG_SPACE(sizeof(int) * (size_t)max_fds)];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    struct msghdr mh = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    ssize_t n = recvmsg(sock, &mh, MSG_DONTWAIT);
    *nfds = 0;
    if (n <= 0) return n;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm;
         cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET &&
            cm->cmsg_type  == SCM_RIGHTS) {
            int cnt = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            if (cnt > max_fds) cnt = max_fds;
            memcpy(fds, CMSG_DATA(cm), (size_t)cnt * sizeof(int));
            *nfds = cnt;
        }
    }
    return n;
}
