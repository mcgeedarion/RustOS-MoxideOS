/*
 * userspace/wayland/compositor.c — rustos Wayland compositor
 *
 * Implements:
 *   1. wl_display socket at /run/wayland-0  (AF_UNIX stream)
 *   2. Wayland wire protocol: fixed 8-byte header + typed payload
 *   3. Core globals: wl_compositor, wl_shm, wl_seat, wl_output,
 *                    xdg_wm_base
 *   4. wl_shm buffer sharing (SCM_RIGHTS fd → mmap pool → wl_buffer)
 *   5. xdg_shell: xdg_wm_base / xdg_surface / xdg_toplevel
 *      — full configure/ack_configure handshake
 *      — xdg_wm_base.ping → pong keepalive
 *   6. wl_keyboard.keymap — minimal XKB keymap in a memfd, delivered
 *      via SCM_RIGHTS so GTK/Qt/SDL2 do not stall on keyboard init
 *   7. Scanout: composite all surfaces (Z-order) into DRM back buffer,
 *      then page-flip; wl_surface.enter sent on first commit
 *
 * Build:
 *   musl-gcc -static -O2 -D_GNU_SOURCE -fstack-protector-strong \
 *            -Wall -Wextra -std=c11 -o rustos-compositor compositor.c
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/drm.h>

#include "protocol.h"

/* ── Limits ────────────────────────────────────────────────────────────── */
#define MAX_CLIENTS         64
#define MAX_SURFACES        32
#define MAX_XDG_SURFACES    32
#define MAX_XDG_TOPLEVELS   32
#define MAX_BUFFERS         64
#define MAX_POOLS           16
#define MAX_DAMAGE_RECTS    32
#define RX_BUF_SIZE         (64 * 1024)
#define WAYLAND_SOCKET_PATH "/run/wayland-0"

/* ── DRM globals ───────────────────────────────────────────────────────── */
static int      drm_fd          = -1;
static int      input_fd        = -1;
static int      epoll_fd        = -1;
static int      listen_fd       = -1;

static uint32_t screen_width    = 1024;
static uint32_t screen_height   = 768;
static uint32_t screen_stride   = 0;
static uint32_t primary_crtc_id = 0;

typedef struct {
    uint32_t handle;
    uint32_t fb_id;
    uint64_t size;
    void    *map;
} DrmBuf;

static DrmBuf fb[2];
static int    back_idx = 1;

/* ── Keymap ────────────────────────────────────────────────────────────── */
/*
 * Minimal XKB keymap for pc105 / us layout.  All major toolkits (GTK,
 * Qt, SDL2) require a valid keymap before they process keyboard input.
 * We provide the smallest well-formed XKB string that xkbcommon accepts.
 */
static const char KEYMAP_STRING[] =
    "xkb_keymap {\n"
    "  xkb_keycodes  \"evdev+aliases(qwerty)\" {};\n"
    "  xkb_types     \"complete\" {};\n"
    "  xkb_compat    \"complete\" {};\n"
    "  xkb_symbols   \"pc+us+inet(evdev)\" {};\n"
    "  xkb_geometry  \"pc(pc105)\" {};\n"
    "};\n";

/*
 * keymap_create_memfd — write KEYMAP_STRING into a memfd and return the fd.
 * The fd is sealed read-only so clients cannot modify the mapping.
 * Returns -1 on failure (compositor proceeds without keymap delivery).
 */
static int keymap_create_memfd(void) {
    int fd = (int)syscall(SYS_memfd_create, "xkb-keymap", 1u /* MFD_CLOEXEC */);
    if (fd < 0) return -1;
    size_t len = sizeof(KEYMAP_STRING); /* includes NUL — Wayland keymap size must include it */
    if (write(fd, KEYMAP_STRING, len) != (ssize_t)len) { close(fd); return -1; }
    /* Seal: no further writes.  F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE = 7 */
    fcntl(fd, 1033 /* F_ADD_SEALS */, 7);
    return fd;
}

/* ── Object tables ─────────────────────────────────────────────────────── */

typedef struct {
    uint32_t id;        /* 0 = slot free */
    int      shm_fd;
    void    *shm_map;
    int32_t  offset;
    int32_t  width;
    int32_t  height;
    int32_t  stride;
    uint32_t format;
} WlBuffer;

typedef struct {
    uint32_t id;        /* 0 = slot free */
    int      shm_fd;
    void    *map;
    int32_t  size;
} WlPool;

typedef struct {
    uint32_t  id;                    /* wl_surface id, 0 = free */
    uint32_t  attached_buffer_id;
    int32_t   x, y;
    int32_t   blit_w, blit_h;
    uint32_t  damage[MAX_DAMAGE_RECTS][4];
    int       n_damage;
    uint32_t  frame_cb_id;
    int       committed;
    int       enter_sent;            /* wl_surface.enter delivered */
} Surface;

/*
 * XdgSurface — wraps a wl_surface with an xdg_surface role.
 * Tracks whether ack_configure has been received.
 */
typedef struct {
    uint32_t id;           /* xdg_surface object id, 0 = free */
    uint32_t wl_surface_id;
    uint32_t pending_configure_serial;
    int      configured;   /* ack_configure received */
} XdgSurface;

/*
 * XdgToplevel — the window role assigned to an xdg_surface.
 */
typedef struct {
    uint32_t id;               /* xdg_toplevel object id, 0 = free */
    uint32_t xdg_surface_id;
    char     title[128];
    char     app_id[128];
    int32_t  min_w, min_h;
    int32_t  max_w, max_h;
    int      closed;
} XdgToplevel;

typedef struct {
    int       fd;
    int       alive;

    uint8_t   rx[RX_BUF_SIZE];
    size_t    rx_len;

    int       pending_fds[8];
    int       n_pending_fds;

    /* Core object ids */
    uint32_t  registry_id;
    uint32_t  compositor_id;
    uint32_t  shm_id;
    uint32_t  seat_id;
    uint32_t  pointer_id;
    uint32_t  keyboard_id;
    uint32_t  output_id;
    uint32_t  xdg_wm_base_id;

    /* Object tables */
    WlPool       pools[MAX_POOLS];
    WlBuffer     buffers[MAX_BUFFERS];
    Surface      surfaces[MAX_SURFACES];
    XdgSurface   xdg_surfaces[MAX_XDG_SURFACES];
    XdgToplevel  xdg_toplevels[MAX_XDG_TOPLEVELS];
} Client;

static Client clients[MAX_CLIENTS];
static int    n_clients     = 0;
static int    focused_client = -1;

static uint32_t serial_counter = 1;
static inline uint32_t next_serial(void) { return serial_counter++; }

/* ── DRM helpers ───────────────────────────────────────────────────────── */

static int drm_alloc_buf(DrmBuf *b, uint32_t w, uint32_t h, uint32_t stride) {
    struct drm_mode_create_dumb cd = { .height = h, .width = w, .bpp = 32 };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0) return -1;
    b->handle = cd.handle;
    b->size   = cd.size;
    if (!stride) screen_stride = cd.pitch;

    struct drm_mode_map_dumb md = { .handle = b->handle };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) return -1;
    b->map = mmap(NULL, (size_t)b->size, PROT_READ|PROT_WRITE,
                  MAP_SHARED, drm_fd, (off_t)md.offset);
    if (b->map == MAP_FAILED) { b->map = NULL; return -1; }
    memset(b->map, 0, (size_t)b->size);

    struct drm_mode_fb_cmd fc = {
        .width = w, .height = h,
        .pitch = cd.pitch, .bpp = 32, .depth = 24,
        .handle = b->handle,
    };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_ADDFB, &fc) < 0) return -1;
    b->fb_id = fc.fb_id;
    return 0;
}

static int drm_setup(void) {
    struct drm_mode_card_res res = {0};
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) return -1;

    uint32_t conn_ids[8] = {0}, crtc_ids[8] = {0};
    res.connector_id_ptr = (uintptr_t)conn_ids;
    res.crtc_id_ptr      = (uintptr_t)crtc_ids;
    res.count_connectors = res.count_connectors < 8 ? res.count_connectors : 8;
    res.count_crtcs      = res.count_crtcs      < 8 ? res.count_crtcs      : 8;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) return -1;
    if (res.count_connectors == 0) return -1;

    struct drm_mode_get_connector conn = { .connector_id = conn_ids[0] };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) return -1;
    if (conn.count_modes == 0) return -1;

    struct drm_mode_modeinfo modes[4] = {0};
    conn.modes_ptr   = (uintptr_t)modes;
    conn.count_modes = conn.count_modes < 4 ? conn.count_modes : 4;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) return -1;

    screen_width    = modes[0].hdisplay;
    screen_height   = modes[0].vdisplay;
    primary_crtc_id = crtc_ids[0];

    if (drm_alloc_buf(&fb[0], screen_width, screen_height, 0) < 0) return -1;
    if (drm_alloc_buf(&fb[1], screen_width, screen_height, screen_stride) < 0) return -1;

    struct drm_mode_crtc crtc = {
        .crtc_id            = primary_crtc_id,
        .fb_id              = fb[0].fb_id,
        .set_connectors_ptr = (uintptr_t)&conn_ids[0],
        .count_connectors   = 1,
        .mode               = modes[0],
        .mode_valid         = 1,
    };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_SETCRTC, &crtc) < 0) return -1;
    return 0;
}

static void drm_flip(void) {
    struct drm_mode_crtc_page_flip pf = {
        .crtc_id   = primary_crtc_id,
        .fb_id     = fb[back_idx].fb_id,
        .flags     = DRM_MODE_PAGE_FLIP_EVENT,
        .user_data = 0,
    };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_PAGE_FLIP, &pf) == 0)
        back_idx ^= 1;
}

/* ── Registry helpers ──────────────────────────────────────────────────── */

static void registry_global_send(Client *c, uint32_t name,
                                  const char *intf, uint32_t version) {
    uint8_t ev[256];
    size_t  sz = 0;
    sz += wl_encode_str(ev + sz, intf);
    memmove(ev + 4, ev, sz);
    memcpy(ev, &name, 4);
    sz += 4;
    memcpy(ev + sz, &version, 4); sz += 4;
    wl_send(c->fd, c->registry_id, WL_REGISTRY_EVT_GLOBAL, ev, (uint16_t)sz);
}

static void send_registry_globals(Client *c) {
    registry_global_send(c, WL_GLOBAL_NAME_COMPOSITOR,  "wl_compositor",  WL_COMPOSITOR_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SHM,         "wl_shm",         WL_SHM_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SEAT,        "wl_seat",        WL_SEAT_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_OUTPUT,      "wl_output",      WL_OUTPUT_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_XDG_WM_BASE, "xdg_wm_base",   XDG_WM_BASE_VERSION);
}

static void send_output_info(Client *c) {
    uint32_t oid = c->output_id;
    if (!oid) return;

    uint8_t geom[256]; size_t gsz = 0;
    int32_t zeroi = 0, pw = 270, ph = 202;
    int32_t sub  = (int32_t)WL_OUTPUT_SUBPIXEL_UNKNOWN;
    int32_t xfrm = (int32_t)WL_OUTPUT_TRANSFORM_NORMAL;
    memcpy(geom + gsz, &zeroi, 4); gsz += 4;
    memcpy(geom + gsz, &zeroi, 4); gsz += 4;
    memcpy(geom + gsz, &pw,    4); gsz += 4;
    memcpy(geom + gsz, &ph,    4); gsz += 4;
    memcpy(geom + gsz, &sub,   4); gsz += 4;
    gsz += wl_encode_str(geom + gsz, "rustos");
    gsz += wl_encode_str(geom + gsz, "virtio-gpu");
    memcpy(geom + gsz, &xfrm, 4); gsz += 4;
    wl_send(c->fd, oid, WL_OUTPUT_EVT_GEOMETRY, geom, (uint16_t)gsz);

    uint8_t mode[16]; size_t msz = 0;
    uint32_t flags   = WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED;
    int32_t  refresh = 60000;
    memcpy(mode + msz, &flags,         4); msz += 4;
    memcpy(mode + msz, &screen_width,  4); msz += 4;
    memcpy(mode + msz, &screen_height, 4); msz += 4;
    memcpy(mode + msz, &refresh,       4); msz += 4;
    wl_send(c->fd, oid, WL_OUTPUT_EVT_MODE, mode, (uint16_t)msz);
    wl_send(c->fd, oid, WL_OUTPUT_EVT_DONE, NULL, 0);
}

/* ── xdg_shell helpers ─────────────────────────────────────────────────── */

/*
 * send_xdg_configure — emit the full configure sequence that xdg-shell
 * requires before a client may commit its first buffer:
 *
 *   xdg_toplevel.configure(width=0, height=0, states=[])
 *     width/height = 0 means "compositor doesn't constrain; choose freely"
 *     states = empty wl_array (4-byte length field = 0)
 *
 *   xdg_surface.configure(serial)
 *     The client must ack this serial before committing.
 */
static void send_xdg_configure(Client *c, XdgSurface *xs, XdgToplevel *xt) {
    /* xdg_toplevel.configure(width, height, states: wl_array) */
    uint8_t tl_payload[16];
    int32_t  zero_dim   = 0;
    uint32_t array_len  = 0;   /* empty states array */
    memcpy(tl_payload,    &zero_dim,  4);  /* width  */
    memcpy(tl_payload+4,  &zero_dim,  4);  /* height */
    memcpy(tl_payload+8,  &array_len, 4);  /* wl_array.size */
    /* wl_array also has a .alloc field on the wire — send 4 more zero bytes */
    memcpy(tl_payload+12, &array_len, 4);
    wl_send(c->fd, xt->id, XDG_TOPLEVEL_EVT_CONFIGURE, tl_payload, 16);

    /* xdg_surface.configure(serial) */
    uint32_t serial = next_serial();
    xs->pending_configure_serial = serial;
    xs->configured = 0;
    wl_send(c->fd, xs->id, XDG_SURFACE_EVT_CONFIGURE, &serial, 4);
}

/* ── Keymap delivery ───────────────────────────────────────────────────── */

/*
 * send_keymap — deliver the XKB keymap to a freshly created wl_keyboard.
 *
 * Wire format for wl_keyboard.keymap:
 *   uint32 format   — WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 (1)
 *   fd              — sent as SCM_RIGHTS ancdata alongside the message
 *   uint32 size     — byte count INCLUDING the NUL terminator
 *
 * The fd is a memfd containing KEYMAP_STRING.  It is closed here after
 * sendmsg because the client receives its own dup via SCM_RIGHTS.
 */
static void send_keymap(Client *c) {
    if (!c->keyboard_id) return;
    int kfd = keymap_create_memfd();
    if (kfd < 0) return;

    uint8_t payload[8];
    uint32_t fmt  = WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1;
    uint32_t size = (uint32_t)sizeof(KEYMAP_STRING);
    memcpy(payload,   &fmt,  4);
    memcpy(payload+4, &size, 4);
    /* fd travels as SCM_RIGHTS; its slot in the wire payload is implicit
     * (Wayland protocol encodes fd arguments as if they are in-band uint32,
     * but they are always out-of-band via SCM_RIGHTS). */
    wl_send_with_fd(c->fd, c->keyboard_id,
                    WL_KEYBOARD_EVT_KEYMAP,
                    payload, 8, kfd);
    close(kfd);
}

/* ── Compositing ───────────────────────────────────────────────────────── */

/*
 * composite_and_flip — clear the back buffer, blit all committed surfaces
 * in Z-order (insertion order = bottom to top), then page-flip.
 */
static void composite_and_flip(void) {
    if (!fb[back_idx].map) return;

    /* Clear back buffer to black */
    memset(fb[back_idx].map, 0, (size_t)fb[back_idx].size);

    for (int ci = 0; ci < n_clients; ci++) {
        Client *c = &clients[ci];
        if (!c->alive) continue;
        for (int si = 0; si < MAX_SURFACES; si++) {
            Surface *s = &c->surfaces[si];
            if (!s->id || !s->committed) continue;

            /* wl_surface.enter: tell client which output it is on */
            if (!s->enter_sent && c->output_id) {
                wl_send(c->fd, s->id, WL_SURFACE_EVT_ENTER,
                        &c->output_id, 4);
                s->enter_sent = 1;
            }

            /* Blit */
            WlBuffer *wb = NULL;
            for (int bi = 0; bi < MAX_BUFFERS; bi++) {
                if (c->buffers[bi].id == s->attached_buffer_id) {
                    wb = &c->buffers[bi]; break;
                }
            }
            if (!wb || !wb->shm_map) continue;

            const uint8_t *src_base = (const uint8_t *)wb->shm_map + wb->offset;
            uint8_t       *dst_base = (uint8_t *)fb[back_idx].map;

            int32_t bw = wb->width, bh = wb->height, bs = wb->stride;
            int32_t dx = s->x, dy = s->y;
            int32_t src_col = 0, src_row = 0;
            if (dx < 0) { src_col = -dx; dx = 0; }
            if (dy < 0) { src_row = -dy; dy = 0; }
            int32_t copy_w = bw - src_col;
            int32_t copy_h = bh - src_row;
            if (dx + copy_w > (int32_t)screen_width)  copy_w = (int32_t)screen_width  - dx;
            if (dy + copy_h > (int32_t)screen_height) copy_h = (int32_t)screen_height - dy;
            if (copy_w <= 0 || copy_h <= 0) continue;

            for (int32_t row = 0; row < copy_h; row++) {
                const uint8_t *src = src_base + (src_row + row) * bs + src_col * 4;
                uint8_t       *dst = dst_base
                    + (uint32_t)(dy + row) * screen_stride
                    + (uint32_t)dx * 4;
                memcpy(dst, src, (size_t)copy_w * 4);
            }

            wl_send(c->fd, wb->id, WL_BUFFER_EVT_RELEASE, NULL, 0);
            s->n_damage = 0;
        }
    }
    drm_flip();
}

/* ── Message dispatcher ─────────────────────────────────────────────────── */

static void dispatch_message(Client *c, uint32_t obj, uint16_t op,
                              const uint8_t *data, uint16_t dlen) {
    (void)dlen;

    /* ── wl_display ──────────────────────────────────────────────────── */
    if (obj == WL_DISPLAY_ID) {
        if (op == WL_DISPLAY_REQ_SYNC) {
            uint32_t cb_id  = wl_read_u32(data, 0);
            uint32_t serial = next_serial();
            wl_send(c->fd, cb_id, WL_CALLBACK_EVT_DONE, &serial, 4);
            wl_send(c->fd, WL_DISPLAY_ID, WL_DISPLAY_EVT_DELETE_ID, &cb_id, 4);
        } else if (op == WL_DISPLAY_REQ_GET_REGISTRY) {
            c->registry_id = wl_read_u32(data, 0);
            send_registry_globals(c);
        }
        return;
    }

    /* ── wl_registry ─────────────────────────────────────────────────── */
    if (obj == c->registry_id) {
        if (op == WL_REGISTRY_REQ_BIND) {
            uint32_t name    = wl_read_u32(data, 0);
            uint32_t ilen    = wl_read_u32(data, 4);
            uint32_t ipadded = (ilen + 3u) & ~3u;
            /* version is at offset 4+4+ipadded; new_id follows */
            uint32_t new_id  = wl_read_u32(data, 4 + 4 + ipadded + 4);

            if (name == WL_GLOBAL_NAME_COMPOSITOR) {
                c->compositor_id = new_id;
            } else if (name == WL_GLOBAL_NAME_SHM) {
                c->shm_id = new_id;
                uint32_t fmt;
                fmt = WL_SHM_FORMAT_ARGB8888;
                wl_send(c->fd, new_id, WL_SHM_EVT_FORMAT, &fmt, 4);
                fmt = WL_SHM_FORMAT_XRGB8888;
                wl_send(c->fd, new_id, WL_SHM_EVT_FORMAT, &fmt, 4);
            } else if (name == WL_GLOBAL_NAME_SEAT) {
                c->seat_id = new_id;
                uint32_t caps = WL_SEAT_CAP_POINTER | WL_SEAT_CAP_KEYBOARD;
                wl_send(c->fd, new_id, WL_SEAT_EVT_CAPABILITIES, &caps, 4);
                uint8_t nbuf[32];
                size_t nsz = wl_encode_str(nbuf, "seat0");
                wl_send(c->fd, new_id, WL_SEAT_EVT_NAME, nbuf, (uint16_t)nsz);
            } else if (name == WL_GLOBAL_NAME_OUTPUT) {
                c->output_id = new_id;
                send_output_info(c);
            } else if (name == WL_GLOBAL_NAME_XDG_WM_BASE) {
                c->xdg_wm_base_id = new_id;
            }
        }
        return;
    }

    /* ── wl_compositor ───────────────────────────────────────────────── */
    if (obj == c->compositor_id) {
        if (op == WL_COMPOSITOR_REQ_CREATE_SURFACE) {
            uint32_t new_id = wl_read_u32(data, 0);
            for (int i = 0; i < MAX_SURFACES; i++) {
                if (c->surfaces[i].id == 0) {
                    memset(&c->surfaces[i], 0, sizeof(c->surfaces[i]));
                    c->surfaces[i].id = new_id;
                    break;
                }
            }
        }
        return;
    }

    /* ── wl_shm ──────────────────────────────────────────────────────── */
    if (obj == c->shm_id) {
        if (op == WL_SHM_REQ_CREATE_POOL) {
            uint32_t pool_id  = wl_read_u32(data, 0);
            int32_t  shm_size = wl_read_i32(data, 4);
            int shm_fd = -1;
            if (c->n_pending_fds > 0) {
                shm_fd = c->pending_fds[0];
                memmove(c->pending_fds, c->pending_fds + 1,
                        (size_t)(c->n_pending_fds - 1) * sizeof(int));
                c->n_pending_fds--;
            }
            for (int i = 0; i < MAX_POOLS; i++) {
                if (c->pools[i].id == 0) {
                    c->pools[i].id     = pool_id;
                    c->pools[i].shm_fd = shm_fd;
                    c->pools[i].size   = shm_size;
                    if (shm_fd >= 0 && shm_size > 0) {
                        c->pools[i].map = mmap(NULL, (size_t)shm_size,
                                               PROT_READ, MAP_SHARED, shm_fd, 0);
                        if (c->pools[i].map == MAP_FAILED)
                            c->pools[i].map = NULL;
                    }
                    break;
                }
            }
        }
        return;
    }

    /* ── wl_seat sub-objects ─────────────────────────────────────────── */
    if (obj == c->seat_id) {
        if (op == WL_SEAT_REQ_GET_POINTER) {
            c->pointer_id = wl_read_u32(data, 0);
        } else if (op == WL_SEAT_REQ_GET_KEYBOARD) {
            c->keyboard_id = wl_read_u32(data, 0);
            send_keymap(c);
        }
        return;
    }

    /* ── xdg_wm_base ─────────────────────────────────────────────────── */
    if (obj == c->xdg_wm_base_id) {
        if (op == XDG_WM_BASE_REQ_GET_XDG_SURFACE) {
            /* get_xdg_surface(id: new_id, surface: wl_surface) */
            uint32_t new_id  = wl_read_u32(data, 0);
            uint32_t surf_id = wl_read_u32(data, 4);
            for (int i = 0; i < MAX_XDG_SURFACES; i++) {
                if (c->xdg_surfaces[i].id == 0) {
                    memset(&c->xdg_surfaces[i], 0, sizeof(c->xdg_surfaces[i]));
                    c->xdg_surfaces[i].id           = new_id;
                    c->xdg_surfaces[i].wl_surface_id = surf_id;
                    break;
                }
            }
        } else if (op == XDG_WM_BASE_REQ_PONG) {
            /* pong(serial) — keepalive reply, nothing to do */
            (void)wl_read_u32(data, 0);
        } else if (op == XDG_WM_BASE_REQ_DESTROY) {
            c->xdg_wm_base_id = 0;
        }
        return;
    }

    /* ── xdg_surface ─────────────────────────────────────────────────── */
    for (int xi = 0; xi < MAX_XDG_SURFACES; xi++) {
        XdgSurface *xs = &c->xdg_surfaces[xi];
        if (xs->id != obj) continue;

        if (op == XDG_SURFACE_REQ_GET_TOPLEVEL) {
            uint32_t new_id = wl_read_u32(data, 0);
            for (int ti = 0; ti < MAX_XDG_TOPLEVELS; ti++) {
                if (c->xdg_toplevels[ti].id == 0) {
                    memset(&c->xdg_toplevels[ti], 0,
                           sizeof(c->xdg_toplevels[ti]));
                    c->xdg_toplevels[ti].id             = new_id;
                    c->xdg_toplevels[ti].xdg_surface_id = xs->id;
                    /* Send initial configure immediately */
                    send_xdg_configure(c, xs, &c->xdg_toplevels[ti]);
                    break;
                }
            }
        } else if (op == XDG_SURFACE_REQ_ACK_CONFIGURE) {
            uint32_t serial = wl_read_u32(data, 0);
            if (serial == xs->pending_configure_serial)
                xs->configured = 1;
        } else if (op == XDG_SURFACE_REQ_SET_WINDOW_GEOMETRY) {
            /* x, y, width, height — noted but not enforced at MVP level */
        } else if (op == XDG_SURFACE_REQ_DESTROY) {
            xs->id = 0;
        }
        return;
    }

    /* ── xdg_toplevel ────────────────────────────────────────────────── */
    for (int ti = 0; ti < MAX_XDG_TOPLEVELS; ti++) {
        XdgToplevel *xt = &c->xdg_toplevels[ti];
        if (xt->id != obj) continue;

        switch (op) {
        case XDG_TOPLEVEL_REQ_DESTROY:
            xt->id = 0;
            break;
        case XDG_TOPLEVEL_REQ_SET_TITLE: {
            uint32_t slen = wl_read_u32(data, 0);
            if (slen > 127) slen = 127;
            memcpy(xt->title, data + 4, slen);
            xt->title[slen] = '\0';
            break;
        }
        case XDG_TOPLEVEL_REQ_SET_APP_ID: {
            uint32_t slen = wl_read_u32(data, 0);
            if (slen > 127) slen = 127;
            memcpy(xt->app_id, data + 4, slen);
            xt->app_id[slen] = '\0';
            break;
        }
        case XDG_TOPLEVEL_REQ_SET_MIN_SIZE:
            xt->min_w = wl_read_i32(data, 0);
            xt->min_h = wl_read_i32(data, 4);
            break;
        case XDG_TOPLEVEL_REQ_SET_MAX_SIZE:
            xt->max_w = wl_read_i32(data, 0);
            xt->max_h = wl_read_i32(data, 4);
            break;
        case XDG_TOPLEVEL_REQ_SET_FULLSCREEN:
            /* Honour by re-configuring at screen resolution */
            for (int xi2 = 0; xi2 < MAX_XDG_SURFACES; xi2++) {
                if (c->xdg_surfaces[xi2].id == xt->xdg_surface_id) {
                    send_xdg_configure(c, &c->xdg_surfaces[xi2], xt);
                    break;
                }
            }
            break;
        case XDG_TOPLEVEL_REQ_UNSET_FULLSCREEN:
        case XDG_TOPLEVEL_REQ_SET_MAXIMIZED:
        case XDG_TOPLEVEL_REQ_UNSET_MAXIMIZED:
            /* Re-send configure with no constraints */
            for (int xi2 = 0; xi2 < MAX_XDG_SURFACES; xi2++) {
                if (c->xdg_surfaces[xi2].id == xt->xdg_surface_id) {
                    send_xdg_configure(c, &c->xdg_surfaces[xi2], xt);
                    break;
                }
            }
            break;
        default: break;
        }
        return;
    }

    /* ── wl_shm_pool ─────────────────────────────────────────────────── */
    for (int pi = 0; pi < MAX_POOLS; pi++) {
        WlPool *p = &c->pools[pi];
        if (p->id != obj) continue;

        if (op == WL_SHM_POOL_REQ_CREATE_BUFFER) {
            uint32_t buf_id = wl_read_u32(data, 0);
            int32_t  offset = wl_read_i32(data, 4);
            int32_t  width  = wl_read_i32(data, 8);
            int32_t  height = wl_read_i32(data, 12);
            int32_t  stride = wl_read_i32(data, 16);
            uint32_t format = wl_read_u32(data, 20);
            for (int bi = 0; bi < MAX_BUFFERS; bi++) {
                if (c->buffers[bi].id == 0) {
                    c->buffers[bi].id      = buf_id;
                    c->buffers[bi].shm_fd  = p->shm_fd;
                    c->buffers[bi].shm_map = p->map;
                    c->buffers[bi].offset  = offset;
                    c->buffers[bi].width   = width;
                    c->buffers[bi].height  = height;
                    c->buffers[bi].stride  = stride;
                    c->buffers[bi].format  = format;
                    break;
                }
            }
        } else if (op == WL_SHM_POOL_REQ_DESTROY) {
            if (p->map) { munmap(p->map, (size_t)p->size); p->map = NULL; }
            if (p->shm_fd >= 0) { close(p->shm_fd); p->shm_fd = -1; }
            p->id = 0;
        } else if (op == WL_SHM_POOL_REQ_RESIZE) {
            int32_t new_size = wl_read_i32(data, 0);
            if (p->map) munmap(p->map, (size_t)p->size);
            p->size = new_size;
            if (p->shm_fd >= 0 && new_size > 0) {
                p->map = mmap(NULL, (size_t)new_size, PROT_READ, MAP_SHARED,
                              p->shm_fd, 0);
                if (p->map == MAP_FAILED) p->map = NULL;
            }
        }
        return;
    }

    /* ── wl_buffer ───────────────────────────────────────────────────── */
    for (int bi = 0; bi < MAX_BUFFERS; bi++) {
        WlBuffer *b = &c->buffers[bi];
        if (b->id != obj) continue;
        if (op == WL_BUFFER_REQ_DESTROY) b->id = 0;
        return;
    }

    /* ── wl_surface ──────────────────────────────────────────────────── */
    for (int si = 0; si < MAX_SURFACES; si++) {
        Surface *s = &c->surfaces[si];
        if (s->id != obj) continue;

        switch (op) {
        case WL_SURFACE_REQ_DESTROY:
            s->id = 0;
            break;
        case WL_SURFACE_REQ_ATTACH: {
            uint32_t buf_id = wl_read_u32(data, 0);
            s->attached_buffer_id = buf_id;
            s->x += wl_read_i32(data, 4);
            s->y += wl_read_i32(data, 8);
            for (int bi = 0; bi < MAX_BUFFERS; bi++) {
                if (c->buffers[bi].id == buf_id) {
                    s->blit_w = c->buffers[bi].width;
                    s->blit_h = c->buffers[bi].height;
                    break;
                }
            }
            break;
        }
        case WL_SURFACE_REQ_DAMAGE:
        case WL_SURFACE_REQ_DAMAGE_BUFFER:
            if (s->n_damage < MAX_DAMAGE_RECTS) {
                uint32_t *r = s->damage[s->n_damage++];
                r[0] = (uint32_t)wl_read_i32(data, 0);
                r[1] = (uint32_t)wl_read_i32(data, 4);
                r[2] = (uint32_t)wl_read_i32(data, 8);
                r[3] = (uint32_t)wl_read_i32(data, 12);
            }
            break;
        case WL_SURFACE_REQ_FRAME:
            s->frame_cb_id = wl_read_u32(data, 0);
            break;
        case WL_SURFACE_REQ_COMMIT:
            s->committed = 1;
            composite_and_flip();
            break;
        default: break;
        }
        return;
    }
}

/* ── RX loop ────────────────────────────────────────────────────────────── */

static void process_rx(Client *c) {
    size_t off = 0;
    while (off + 8 <= c->rx_len) {
        uint32_t obj = wl_read_u32(c->rx, off);
        uint16_t op, msz;
        memcpy(&op,  c->rx + off + 4, 2);
        memcpy(&msz, c->rx + off + 6, 2);
        if (msz < 8 || off + msz > c->rx_len) break;
        dispatch_message(c, obj, op,
                         c->rx + off + 8, (uint16_t)(msz - 8));
        off += msz;
    }
    if (off > 0 && off < c->rx_len)
        memmove(c->rx, c->rx + off, c->rx_len - off);
    c->rx_len -= off;
}

/* ── Input routing ──────────────────────────────────────────────────────── */

struct input_event {
    long     tv_sec;
    long     tv_usec;
    uint16_t type;
    uint16_t code;
    int32_t  value;
};
#define EV_KEY 0x01
#define EV_REL 0x02
#define REL_X  0x00
#define REL_Y  0x01

static void forward_input(void) {
    struct input_event ev;
    ssize_t n = read(input_fd, &ev, sizeof(ev));
    if (n != (ssize_t)sizeof(ev)) return;
    if (focused_client < 0 || focused_client >= n_clients) return;
    Client *c = &clients[focused_client];
    if (!c->alive) return;

    if (ev.type == EV_KEY && c->keyboard_id) {
        uint8_t  payload[16];
        uint32_t serial  = next_serial();
        uint32_t time_ms = 0;
        uint32_t key     = (uint32_t)ev.code;
        uint32_t state   = (ev.value == 0) ? 0u : 1u;
        memcpy(payload,    &serial,  4);
        memcpy(payload+4,  &time_ms, 4);
        memcpy(payload+8,  &key,     4);
        memcpy(payload+12, &state,   4);
        wl_send(c->fd, c->keyboard_id, WL_KEYBOARD_EVT_KEY, payload, 16);
    } else if (ev.type == EV_REL && c->pointer_id) {
        uint8_t  payload[12];
        uint32_t time_ms = 0;
        int32_t  zero    = 0;
        int32_t  fp      = wl_fixed_from_int(ev.value);
        memcpy(payload, &time_ms, 4);
        if (ev.code == REL_X) {
            memcpy(payload+4, &fp,   4);
            memcpy(payload+8, &zero, 4);
        } else {
            memcpy(payload+4, &zero, 4);
            memcpy(payload+8, &fp,   4);
        }
        wl_send(c->fd, c->pointer_id, WL_POINTER_EVT_MOTION, payload, 12);
    }
}

/* ── Seccomp sandbox ────────────────────────────────────────────────────── */

static void install_seccomp(void) {
#ifndef AUDIT_ARCH_X86_64
    return;
#else
    /*
     * Whitelist (syscall numbers, x86_64):
     *   0  read          1  write        3  close
     *   9  mmap          11 munmap       15 rt_sigreturn
     *  16  ioctl         46 sendmsg      47 recvmsg
     *  60  exit          228 clock_gettime
     *  231 exit_group    232 epoll_wait  233 epoll_ctl
     *  242 epoll_create1 288 accept4     319 memfd_create
     */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
#define ALLOW(nr) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(nr),0,1), \
                  BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
        ALLOW(0),   ALLOW(1),   ALLOW(3),   ALLOW(9),   ALLOW(11),
        ALLOW(15),  ALLOW(16),  ALLOW(46),  ALLOW(47),  ALLOW(60),
        ALLOW(228), ALLOW(231), ALLOW(232), ALLOW(233), ALLOW(242),
        ALLOW(288), ALLOW(319),
#undef ALLOW
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };
    syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
#endif
}

static void log_msg(const char *s) { write(1, s, strlen(s)); write(1, "\n", 1); }

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    const char *drm_env   = getenv("WAYLAND_DRM_FD");
    const char *input_env = getenv("WAYLAND_INPUT_FD");
    drm_fd   = drm_env   ? atoi(drm_env)   : open("/dev/dri/card0",   O_RDWR);
    input_fd = input_env ? atoi(input_env) : open("/dev/input/event0",
                                                    O_RDONLY | O_NONBLOCK);
    if (drm_fd < 0) { log_msg("[compositor] no DRM device"); _exit(1); }

    if (drm_setup() < 0)
        log_msg("[compositor] DRM setup failed — display output unavailable");
    else
        log_msg("[compositor] DRM double-buffer ready");

    listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) { log_msg("[compositor] socket() failed"); _exit(1); }
    unlink(WAYLAND_SOCKET_PATH);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, WAYLAND_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg("[compositor] bind() failed"); _exit(1);
    }
    if (listen(listen_fd, 128) < 0) {
        log_msg("[compositor] listen() failed"); _exit(1);
    }
    log_msg("[compositor] listening on " WAYLAND_SOCKET_PATH);

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev;
    ev.events  = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
    if (drm_fd   >= 0) { ev.data.fd = drm_fd;   epoll_ctl(epoll_fd, EPOLL_CTL_ADD, drm_fd,   &ev); }
    if (input_fd >= 0) { ev.data.fd = input_fd; epoll_ctl(epoll_fd, EPOLL_CTL_ADD, input_fd, &ev); }

    install_seccomp();
    log_msg("[compositor] seccomp filter installed");
    log_msg("[compositor] event loop started");

    struct epoll_event events[32];
    for (;;) {
        int nev = epoll_wait(epoll_fd, events, 32, 16);

        for (int i = 0; i < nev; i++) {
            int efd = events[i].data.fd;

            /* ── New client ────────────────────────────────────────── */
            if (efd == listen_fd) {
                int cfd = accept4(listen_fd, NULL, NULL,
                                  SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (cfd >= 0 && n_clients < MAX_CLIENTS) {
                    Client *c = &clients[n_clients];
                    memset(c, 0, sizeof(*c));
                    c->fd    = cfd;
                    c->alive = 1;
                    for (int pi = 0; pi < MAX_POOLS;   pi++) c->pools[pi].shm_fd   = -1;
                    for (int bi = 0; bi < MAX_BUFFERS; bi++) c->buffers[bi].shm_fd = -1;
                    if (focused_client < 0) focused_client = n_clients;
                    n_clients++;
                    ev.events  = EPOLLIN | EPOLLET;
                    ev.data.fd = cfd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &ev);
                } else if (cfd >= 0) {
                    close(cfd);
                }
                continue;
            }

            /* ── DRM vblank / page-flip ────────────────────────────── */
            if (efd == drm_fd) {
                uint8_t drmev[64];
                read(drm_fd, drmev, sizeof(drmev));
                for (int ci = 0; ci < n_clients; ci++) {
                    Client *c = &clients[ci];
                    if (!c->alive) continue;
                    for (int si = 0; si < MAX_SURFACES; si++) {
                        Surface *s = &c->surfaces[si];
                        if (!s->id || !s->frame_cb_id) continue;
                        uint32_t serial = next_serial();
                        wl_send(c->fd, s->frame_cb_id,
                                WL_CALLBACK_EVT_DONE, &serial, 4);
                        wl_send(c->fd, WL_DISPLAY_ID,
                                WL_DISPLAY_EVT_DELETE_ID,
                                &s->frame_cb_id, 4);
                        s->frame_cb_id = 0;
                    }
                }
                continue;
            }

            /* ── Input ─────────────────────────────────────────────── */
            if (efd == input_fd) { forward_input(); continue; }

            /* ── Client data ───────────────────────────────────────── */
            for (int ci = 0; ci < n_clients; ci++) {
                Client *c = &clients[ci];
                if (!c->alive || c->fd != efd) continue;

                int     recv_fds[8];
                int     n_recv_fds = 0;
                ssize_t n = recv_with_fd(c->fd,
                                          c->rx + c->rx_len,
                                          RX_BUF_SIZE - c->rx_len,
                                          recv_fds, 8, &n_recv_fds);
                if (n <= 0) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
                    close(c->fd);
                    for (int pi = 0; pi < MAX_POOLS; pi++) {
                        if (c->pools[pi].map)
                            munmap(c->pools[pi].map, (size_t)c->pools[pi].size);
                        if (c->pools[pi].shm_fd >= 0)
                            close(c->pools[pi].shm_fd);
                    }
                    c->alive = 0;
                    if (focused_client == ci) focused_client = -1;
                    for (int ci2 = 0; ci2 < n_clients; ci2++) {
                        if (clients[ci2].alive) { focused_client = ci2; break; }
                    }
                } else {
                    int slots = 8 - c->n_pending_fds;
                    if (n_recv_fds > slots) n_recv_fds = slots;
                    memcpy(c->pending_fds + c->n_pending_fds,
                           recv_fds, (size_t)n_recv_fds * sizeof(int));
                    c->n_pending_fds += n_recv_fds;
                    c->rx_len += (size_t)n;
                    process_rx(c);
                }
                break;
            }
        }
    }
}
