/*
 * userspace/wayland/protocol.h — Wayland wire-protocol constants and helpers
 *
 * All opcodes, object-ID conventions, fixed-point macros, and SCM_RIGHTS
 * ancillary-data helpers used by compositor.c are centralised here so
 * compositor.c stays focused on logic, not magic numbers.
 *
 * Naming convention
 * -----------------
 *   WL_<INTERFACE>_EVT_<NAME>    — event opcode  (compositor → client)
 *   WL_<INTERFACE>_REQ_<NAME>    — request opcode (client → compositor)
 *   XDG_<INTERFACE>_EVT_<NAME>   — xdg-shell event
 *   XDG_<INTERFACE>_REQ_<NAME>   — xdg-shell request
 *   ZWL_LAYER_*                  — wlr-layer-shell-unstable-v1
 *   WL_<INTERFACE>_VERSION       — maximum advertised version
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
#include <errno.h>

/* ── wl_display (object id = 1, always) ──────────────────────────────────── */
#define WL_DISPLAY_ID                   1u
#define WL_DISPLAY_REQ_SYNC             0u
#define WL_DISPLAY_REQ_GET_REGISTRY     1u
#define WL_DISPLAY_EVT_ERROR            0u
#define WL_DISPLAY_EVT_DELETE_ID        1u

/* ── wl_registry ─────────────────────────────────────────────────────────── */
#define WL_REGISTRY_REQ_BIND            0u
#define WL_REGISTRY_EVT_GLOBAL          0u
#define WL_REGISTRY_EVT_GLOBAL_REMOVE   1u

/* ── wl_callback ─────────────────────────────────────────────────────────── */
#define WL_CALLBACK_EVT_DONE            0u

/* ── wl_compositor ───────────────────────────────────────────────────────── */
#define WL_COMPOSITOR_VERSION           5u
#define WL_COMPOSITOR_REQ_CREATE_SURFACE 0u
#define WL_COMPOSITOR_REQ_CREATE_REGION  1u

/* ── wl_shm ──────────────────────────────────────────────────────────────── */
#define WL_SHM_VERSION                  1u
#define WL_SHM_REQ_CREATE_POOL          0u
#define WL_SHM_EVT_FORMAT               0u
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

/* ── wl_subcompositor ────────────────────────────────────────────────────── */
#define WL_SUBCOMPOSITOR_VERSION        1u
#define WL_GLOBAL_NAME_SUBCOMPOSITOR    6u
#define WL_SUBCOMPOSITOR_REQ_DESTROY    0u
#define WL_SUBCOMPOSITOR_REQ_GET_SUBSURFACE 1u

/* ── wl_subsurface ───────────────────────────────────────────────────────── */
#define WL_SUBSURFACE_VERSION           1u
#define WL_SUBSURFACE_REQ_DESTROY       0u
#define WL_SUBSURFACE_REQ_SET_POSITION  1u
#define WL_SUBSURFACE_REQ_PLACE_ABOVE   2u
#define WL_SUBSURFACE_REQ_PLACE_BELOW   3u
#define WL_SUBSURFACE_REQ_SET_SYNC      4u
#define WL_SUBSURFACE_REQ_SET_DESYNC    5u

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

/* ── wl_keyboard ─────────────────────────────────────────────────────────── */
#define WL_KEYBOARD_EVT_KEYMAP          0u
#define WL_KEYBOARD_EVT_ENTER           1u
#define WL_KEYBOARD_EVT_LEAVE           2u
#define WL_KEYBOARD_EVT_KEY             4u
#define WL_KEYBOARD_EVT_MODIFIERS       5u
#define WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 1u

/* ── wl_pointer ──────────────────────────────────────────────────────────── */
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

/* ── xdg_wm_base ─────────────────────────────────────────────────────────── */
#define XDG_WM_BASE_VERSION             2u
#define XDG_WM_BASE_REQ_DESTROY         0u
#define XDG_WM_BASE_REQ_CREATE_POSITIONER 1u
#define XDG_WM_BASE_REQ_GET_XDG_SURFACE 2u
#define XDG_WM_BASE_REQ_PONG            3u
#define XDG_WM_BASE_EVT_PING            0u

/* ── xdg_surface ─────────────────────────────────────────────────────────── */
#define XDG_SURFACE_REQ_DESTROY         0u
#define XDG_SURFACE_REQ_GET_TOPLEVEL    1u
#define XDG_SURFACE_REQ_GET_POPUP       2u
#define XDG_SURFACE_REQ_SET_WINDOW_GEOMETRY 3u
#define XDG_SURFACE_REQ_ACK_CONFIGURE   4u
#define XDG_SURFACE_EVT_CONFIGURE       0u

/* ── xdg_toplevel ────────────────────────────────────────────────────────── */
#define XDG_TOPLEVEL_REQ_DESTROY        0u
#define XDG_TOPLEVEL_REQ_SET_PARENT     1u
#define XDG_TOPLEVEL_REQ_SET_TITLE      2u
#define XDG_TOPLEVEL_REQ_SET_APP_ID     3u
#define XDG_TOPLEVEL_REQ_SHOW_WINDOW_MENU 4u
#define XDG_TOPLEVEL_REQ_MOVE           5u
#define XDG_TOPLEVEL_REQ_RESIZE         6u
#define XDG_TOPLEVEL_REQ_SET_MAX_SIZE   7u
#define XDG_TOPLEVEL_REQ_SET_MIN_SIZE   8u
#define XDG_TOPLEVEL_REQ_SET_MAXIMIZED  9u
#define XDG_TOPLEVEL_REQ_UNSET_MAXIMIZED 10u
#define XDG_TOPLEVEL_REQ_SET_FULLSCREEN 11u
#define XDG_TOPLEVEL_REQ_UNSET_FULLSCREEN 12u
#define XDG_TOPLEVEL_REQ_SET_MINIMIZED  13u
#define XDG_TOPLEVEL_EVT_CONFIGURE      0u
#define XDG_TOPLEVEL_EVT_CLOSE          1u
/* xdg_toplevel state atoms (sent inside configure's wl_array) */
#define XDG_TOPLEVEL_STATE_MAXIMIZED    1u
#define XDG_TOPLEVEL_STATE_FULLSCREEN   2u
#define XDG_TOPLEVEL_STATE_RESIZING     3u
#define XDG_TOPLEVEL_STATE_ACTIVATED    4u

/* ── zwlr_layer_shell_v1 (wlr-layer-shell-unstable-v1) ──────────────────── */
#define ZWL_LAYER_SHELL_VERSION         4u
#define WL_GLOBAL_NAME_LAYER_SHELL      7u
#define ZWL_LAYER_SHELL_REQ_GET_LAYER_SURFACE  0u
#define ZWL_LAYER_SHELL_REQ_DESTROY            1u

/* layer_surface requests */
#define ZWL_LAYER_SURFACE_REQ_SET_SIZE          0u
#define ZWL_LAYER_SURFACE_REQ_SET_ANCHOR        1u
#define ZWL_LAYER_SURFACE_REQ_SET_EXCLUSIVE_ZONE 2u
#define ZWL_LAYER_SURFACE_REQ_SET_MARGIN        3u
#define ZWL_LAYER_SURFACE_REQ_SET_KEYBOARD_INTERACTIVITY 4u
#define ZWL_LAYER_SURFACE_REQ_GET_POPUP         5u
#define ZWL_LAYER_SURFACE_REQ_ACK_CONFIGURE     6u
#define ZWL_LAYER_SURFACE_REQ_DESTROY           7u
#define ZWL_LAYER_SURFACE_REQ_SET_LAYER         8u
/* layer_surface events */
#define ZWL_LAYER_SURFACE_EVT_CONFIGURE         0u
#define ZWL_LAYER_SURFACE_EVT_CLOSED            1u

/* Layer enum */
#define ZWL_LAYER_BACKGROUND    0u
#define ZWL_LAYER_BOTTOM        1u
#define ZWL_LAYER_TOP           2u
#define ZWL_LAYER_OVERLAY       3u

/* Anchor bitfield */
#define ZWL_ANCHOR_TOP          1u
#define ZWL_ANCHOR_BOTTOM       2u
#define ZWL_ANCHOR_LEFT         4u
#define ZWL_ANCHOR_RIGHT        8u

/* ── Well-known global registry names (uint32, 1-based) ─────────────────── */
#define WL_GLOBAL_NAME_COMPOSITOR       1u
#define WL_GLOBAL_NAME_SHM              2u
#define WL_GLOBAL_NAME_SEAT             3u
#define WL_GLOBAL_NAME_OUTPUT           4u
#define WL_GLOBAL_NAME_XDG_WM_BASE      5u
/* 6 = WL_GLOBAL_NAME_SUBCOMPOSITOR, 7 = WL_GLOBAL_NAME_LAYER_SHELL */

/* ── Wire format helpers ─────────────────────────────────────────────────── */

static inline int32_t wl_fixed_from_int(int32_t n)    { return n * 256; }
static inline int32_t wl_fixed_from_double(double d)  { return (int32_t)(d * 256.0); }

static inline uint32_t wl_read_u32(const uint8_t *buf, size_t off) {
    uint32_t v; memcpy(&v, buf + off, 4); return v;
}
static inline int32_t wl_read_i32(const uint8_t *buf, size_t off) {
    int32_t v; memcpy(&v, buf + off, 4); return v;
}

/*
 * wl_send — send a Wayland message to client fd.
 *
 * Wire layout:
 *   [0..3]  uint32  object_id
 *   [4..5]  uint16  opcode
 *   [6..7]  uint16  total message size (header + payload)
 */
static inline int wl_write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static inline void wl_send(int fd, uint32_t obj, uint16_t opcode,
                            const void *payload, uint16_t plen) {
    uint8_t  buf[4096];
    uint16_t total = (uint16_t)(8u + plen);
    if (total > sizeof(buf)) return;
    memcpy(buf,     &obj,    4);
    memcpy(buf + 4, &opcode, 2);
    memcpy(buf + 6, &total,  2);
    if (plen && payload) memcpy(buf + 8, payload, plen);
    (void)wl_write_all(fd, buf, total);
}

/*
 * wl_send_with_fd — send a Wayland message carrying one fd via SCM_RIGHTS.
 * Used to deliver the keymap fd in wl_keyboard.keymap.
 */
static inline void wl_send_with_fd(int sock, uint32_t obj, uint16_t opcode,
                                    const void *payload, uint16_t plen,
                                    int send_fd) {
    uint8_t  hdr[8];
    uint16_t total = (uint16_t)(8u + plen);
    memcpy(hdr,     &obj,    4);
    memcpy(hdr + 4, &opcode, 2);
    memcpy(hdr + 6, &total,  2);

    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len  = 8;
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len  = plen;

    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    struct msghdr mh = {
        .msg_iov        = iov,
        .msg_iovlen     = (plen > 0) ? 2 : 1,
        .msg_control    = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type  = SCM_RIGHTS;
    cm->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &send_fd, sizeof(int));
    while (sendmsg(sock, &mh, MSG_NOSIGNAL) < 0 && errno == EINTR) { }
}

/* wl_encode_str — encode a Wayland wire string into *out; returns bytes written */
static inline size_t wl_encode_str(uint8_t *out, const char *s) {
    uint32_t ilen    = (uint32_t)(s ? strlen(s) : 0);
    uint32_t ipadded = (ilen + 3u) & ~3u;
    memcpy(out, &ilen, 4);
    memset(out + 4, 0, ipadded);
    if (ilen) memcpy(out + 4, s, ilen);
    return 4u + ipadded;
}

/*
 * recv_with_fd — recvmsg wrapper that drains SCM_RIGHTS ancillary data.
 * Returns bytes read, or -1 on error.
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
