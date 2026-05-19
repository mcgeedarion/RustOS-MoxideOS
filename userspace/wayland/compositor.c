/*
 * userspace/wayland/compositor.c — rustos Wayland compositor
 *
 * Implements:
 *   1. wl_display socket at /run/wayland-0  (AF_UNIX stream)
 *   2. Wayland wire protocol: fixed 8-byte header + typed payload
 *   3. Core globals: wl_compositor, wl_shm, wl_seat, wl_output,
 *                    xdg_wm_base, wl_subcompositor, zwlr_layer_shell_v1
 *   4. wl_shm buffer sharing (SCM_RIGHTS fd → mmap pool → wl_buffer)
 *   5. xdg_shell: xdg_wm_base / xdg_surface / xdg_toplevel
 *      — full configure/ack_configure handshake
 *      — xdg_wm_base.ping → pong keepalive
 *   6. wl_keyboard.keymap — minimal XKB keymap in a memfd, delivered
 *      via SCM_RIGHTS so GTK/Qt/SDL2 do not stall on keyboard init
 *   7. Damage-region partial scanout: only dirty rectangles are repainted
 *      into the DRM back buffer before page-flip.
 *   8. wl_subsurface — sub-surface positioning, sync/desync, Z-order
 *      (place_above / place_below relative to parent).
 *   9. zwlr_layer_shell_v1 — BACKGROUND / BOTTOM / TOP / OVERLAY layers
 *      with anchor bitfield, exclusive-zone, margin; surfaces are
 *      composited in layer order below and above regular windows.
 *  10. Server-side decorations (SSD) — title-bar + border painted
 *      directly into the DRM back buffer for xdg_toplevel windows that
 *      have not opted into client-side decorations.
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
#define MAX_SUBSURFACES     32
#define MAX_LAYER_SURFACES  32
#define MAX_XDG_SURFACES    32
#define MAX_XDG_TOPLEVELS   32
#define MAX_BUFFERS         64
#define MAX_POOLS           16
#define MAX_DAMAGE_RECTS    32
#define RX_BUF_SIZE         (64 * 1024)
#define WAYLAND_SOCKET_PATH "/run/wayland-0"

/* SSD geometry */
#define SSD_TITLEBAR_H      24
#define SSD_BORDER_W        2
#define SSD_TITLEBAR_COLOR  0xFF404040u  /* dark grey, ARGB */
#define SSD_BORDER_COLOR    0xFF606060u
#define SSD_FOCUSED_COLOR   0xFF2255AAu  /* blue titlebar when focused */

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

/*
 * Damage accumulator for the back buffer.
 * Each rect: [x, y, w, h] in screen-space pixels.
 * full_damage=1 means skip rect tracking and repaint everything.
 */
#define MAX_SCREEN_DAMAGE 64
typedef struct { int32_t x, y, w, h; } Rect;
static Rect   screen_damage[MAX_SCREEN_DAMAGE];
static int    n_screen_damage = 0;
static int    full_damage     = 1;   /* start with full repaint */

static inline void damage_add(int32_t x, int32_t y, int32_t w, int32_t h) {
    if (full_damage) return;
    /* clamp to screen */
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int32_t)screen_width)  w = (int32_t)screen_width  - x;
    if (y + h > (int32_t)screen_height) h = (int32_t)screen_height - y;
    if (w <= 0 || h <= 0) return;
    if (n_screen_damage >= MAX_SCREEN_DAMAGE) { full_damage = 1; return; }
    screen_damage[n_screen_damage++] = (Rect){x, y, w, h};
}

static inline void damage_clear(void) {
    n_screen_damage = 0;
    full_damage     = 0;
}

/*
 * rect_intersects — true if the blit area [bx,by,bw,bh] overlaps
 * damage rect d.  Used for partial-repaint culling.
 */
static inline int rect_intersects(const Rect *d,
                                   int32_t bx, int32_t by,
                                   int32_t bw, int32_t bh) {
    return !(bx >= d->x + d->w || bx + bw <= d->x ||
             by >= d->y + d->h || by + bh <= d->y);
}

/* ── Keymap ────────────────────────────────────────────────────────────── */
static const char KEYMAP_STRING[] =
    "xkb_keymap {\n"
    "  xkb_keycodes  \"evdev+aliases(qwerty)\" {};\n"
    "  xkb_types     \"complete\" {};\n"
    "  xkb_compat    \"complete\" {};\n"
    "  xkb_symbols   \"pc+us+inet(evdev)\" {};\n"
    "  xkb_geometry  \"pc(pc105)\" {};\n"
    "};\n";

static int keymap_create_memfd(void) {
    int fd = (int)syscall(SYS_memfd_create, "xkb-keymap", 1u);
    if (fd < 0) return -1;
    size_t len = sizeof(KEYMAP_STRING);
    if (write(fd, KEYMAP_STRING, len) != (ssize_t)len) { close(fd); return -1; }
    fcntl(fd, 1033 /* F_ADD_SEALS */, 7);
    return fd;
}

/* ── Object tables ─────────────────────────────────────────────────────── */

typedef struct {
    uint32_t id;
    int      shm_fd;
    void    *shm_map;
    int32_t  offset;
    int32_t  width;
    int32_t  height;
    int32_t  stride;
    uint32_t format;
} WlBuffer;

typedef struct {
    uint32_t id;
    int      shm_fd;
    void    *map;
    int32_t  size;
} WlPool;

typedef struct {
    uint32_t  id;                    /* wl_surface id, 0 = free */
    uint32_t  attached_buffer_id;
    int32_t   x, y;                  /* screen position (root surfaces) */
    int32_t   blit_w, blit_h;
    uint32_t  damage[MAX_DAMAGE_RECTS][4]; /* pending surface-space damage */
    int       n_damage;
    uint32_t  frame_cb_id;
    int       committed;
    int       enter_sent;
    /* subsurface link: 0 if this is a root surface */
    uint32_t  parent_surface_id;
} Surface;

/*
 * Subsurface — a wl_subsurface object binding a child surface to a parent.
 * Position is relative to the parent's top-left corner.
 * sync=1 means pending state is committed together with the parent;
 * sync=0 (desync) means commits take effect immediately.
 */
typedef struct {
    uint32_t id;               /* wl_subsurface object id, 0 = free */
    uint32_t surface_id;       /* child wl_surface */
    uint32_t parent_id;        /* parent wl_surface */
    int32_t  rel_x, rel_y;     /* position relative to parent */
    int      sync;             /* 1 = sync, 0 = desync */
    int      above;            /* 1 = above parent in Z; 0 = below */
} Subsurface;

/*
 * LayerSurface — zwlr_layer_surface_v1 binding a wl_surface to a layer.
 */
typedef struct {
    uint32_t id;               /* zwlr_layer_surface_v1 object id */
    uint32_t surface_id;       /* associated wl_surface */
    uint32_t layer;            /* ZWL_LAYER_* */
    uint32_t anchor;           /* ZWL_ANCHOR_* bitfield */
    int32_t  exclusive_zone;   /* pixels to reserve from screen edge */
    int32_t  margin_top, margin_right, margin_bottom, margin_left;
    int32_t  req_width, req_height;  /* 0 = stretch to anchored edges */
    /* computed geometry after layout */
    int32_t  x, y, w, h;
    uint32_t pending_serial;
    int      configured;       /* ack_configure received */
} LayerSurface;

typedef struct {
    uint32_t id;               /* xdg_surface object id */
    uint32_t wl_surface_id;
    uint32_t pending_configure_serial;
    int      configured;
} XdgSurface;

typedef struct {
    uint32_t id;
    uint32_t xdg_surface_id;
    char     title[128];
    char     app_id[128];
    int32_t  min_w, min_h;
    int32_t  max_w, max_h;
    int      closed;
    int      has_csd;          /* client declared client-side decorations */
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
    uint32_t  subcompositor_id;
    uint32_t  shm_id;
    uint32_t  seat_id;
    uint32_t  pointer_id;
    uint32_t  keyboard_id;
    uint32_t  output_id;
    uint32_t  xdg_wm_base_id;
    uint32_t  layer_shell_id;

    WlPool        pools[MAX_POOLS];
    WlBuffer      buffers[MAX_BUFFERS];
    Surface       surfaces[MAX_SURFACES];
    Subsurface    subsurfaces[MAX_SUBSURFACES];
    LayerSurface  layer_surfaces[MAX_LAYER_SURFACES];
    XdgSurface    xdg_surfaces[MAX_XDG_SURFACES];
    XdgToplevel   xdg_toplevels[MAX_XDG_TOPLEVELS];
} Client;

static Client clients[MAX_CLIENTS];
static int    n_clients      = 0;
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

/* ── Layer layout ──────────────────────────────────────────────────────── */
/*
 * Compute the screen-space geometry for a layer surface from its anchor
 * bitfield, requested size, exclusive-zone and margins.
 * Results are written back into ls->x/y/w/h.
 */
static void layer_surface_layout(LayerSurface *ls) {
    int32_t sw = (int32_t)screen_width;
    int32_t sh = (int32_t)screen_height;
    int32_t x = ls->margin_left;
    int32_t y = ls->margin_top;
    int32_t w = ls->req_width  ? ls->req_width  : sw - ls->margin_left - ls->margin_right;
    int32_t h = ls->req_height ? ls->req_height : sh - ls->margin_top  - ls->margin_bottom;

    uint32_t a = ls->anchor;
    int anchored_h = (a & ZWL_ANCHOR_LEFT) && (a & ZWL_ANCHOR_RIGHT);
    int anchored_v = (a & ZWL_ANCHOR_TOP)  && (a & ZWL_ANCHOR_BOTTOM);

    if (anchored_h) w = sw - ls->margin_left - ls->margin_right;
    if (anchored_v) h = sh - ls->margin_top  - ls->margin_bottom;

    /* Single-edge anchors: pin to that edge */
    if ((a & ZWL_ANCHOR_RIGHT) && !(a & ZWL_ANCHOR_LEFT))
        x = sw - w - ls->margin_right;
    if ((a & ZWL_ANCHOR_BOTTOM) && !(a & ZWL_ANCHOR_TOP))
        y = sh - h - ls->margin_bottom;

    ls->x = x; ls->y = y; ls->w = w; ls->h = h;
}

/*
 * layer_surface_configure — send zwlr_layer_surface_v1.configure(serial, w, h)
 */
static void layer_surface_configure(Client *c, LayerSurface *ls) {
    layer_surface_layout(ls);
    uint8_t payload[12];
    uint32_t serial = next_serial();
    uint32_t w = (uint32_t)ls->w;
    uint32_t h = (uint32_t)ls->h;
    memcpy(payload,   &serial, 4);
    memcpy(payload+4, &w,      4);
    memcpy(payload+8, &h,      4);
    ls->pending_serial = serial;
    ls->configured     = 0;
    wl_send(c->fd, ls->id, ZWL_LAYER_SURFACE_EVT_CONFIGURE, payload, 12);
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
    registry_global_send(c, WL_GLOBAL_NAME_COMPOSITOR,    "wl_compositor",             WL_COMPOSITOR_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SHM,           "wl_shm",                    WL_SHM_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SEAT,          "wl_seat",                   WL_SEAT_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_OUTPUT,        "wl_output",                 WL_OUTPUT_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_XDG_WM_BASE,  "xdg_wm_base",               XDG_WM_BASE_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SUBCOMPOSITOR, "wl_subcompositor",          WL_SUBCOMPOSITOR_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_LAYER_SHELL,   "zwlr_layer_shell_v1",       ZWL_LAYER_SHELL_VERSION);
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

static void send_xdg_configure(Client *c, XdgSurface *xs, XdgToplevel *xt) {
    uint8_t tl_payload[16];
    int32_t  zero_dim   = 0;
    uint32_t array_len  = 0;
    memcpy(tl_payload,    &zero_dim,  4);
    memcpy(tl_payload+4,  &zero_dim,  4);
    memcpy(tl_payload+8,  &array_len, 4);
    memcpy(tl_payload+12, &array_len, 4);
    wl_send(c->fd, xt->id, XDG_TOPLEVEL_EVT_CONFIGURE, tl_payload, 16);

    uint32_t serial = next_serial();
    xs->pending_configure_serial = serial;
    xs->configured = 0;
    wl_send(c->fd, xs->id, XDG_SURFACE_EVT_CONFIGURE, &serial, 4);
}

/* ── Keymap delivery ───────────────────────────────────────────────────── */

static void send_keymap(Client *c) {
    if (!c->keyboard_id) return;
    int kfd = keymap_create_memfd();
    if (kfd < 0) return;

    uint8_t payload[8];
    uint32_t fmt  = WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1;
    uint32_t size = (uint32_t)sizeof(KEYMAP_STRING);
    memcpy(payload,   &fmt,  4);
    memcpy(payload+4, &size, 4);
    wl_send_with_fd(c->fd, c->keyboard_id,
                    WL_KEYBOARD_EVT_KEYMAP,
                    payload, 8, kfd);
    close(kfd);
}

/* ── SSD helpers ───────────────────────────────────────────────────────── */

/*
 * ssd_fill_rect — paint a solid color rectangle into the DRM back buffer.
 * Clips to screen bounds automatically.
 */
static void ssd_fill_rect(int32_t rx, int32_t ry, int32_t rw, int32_t rh,
                           uint32_t color) {
    if (!fb[back_idx].map) return;
    if (rx < 0) { rw += rx; rx = 0; }
    if (ry < 0) { rh += ry; ry = 0; }
    if (rx + rw > (int32_t)screen_width)  rw = (int32_t)screen_width  - rx;
    if (ry + rh > (int32_t)screen_height) rh = (int32_t)screen_height - ry;
    if (rw <= 0 || rh <= 0) return;

    uint32_t *dst = (uint32_t *)fb[back_idx].map;
    for (int32_t row = 0; row < rh; row++) {
        uint32_t *line = dst + (uint32_t)(ry + row) * (screen_stride / 4) + (uint32_t)rx;
        for (int32_t col = 0; col < rw; col++)
            line[col] = color;
    }
}

/*
 * ssd_draw_decorations — paint title bar + borders for an xdg_toplevel
 * surface at (sx, sy) with content size (sw, sh).
 * focused=1 uses the highlight title-bar colour.
 */
static void ssd_draw_decorations(int32_t sx, int32_t sy, int32_t sw, int32_t sh,
                                  int focused) {
    uint32_t tbar_col = focused ? SSD_FOCUSED_COLOR : SSD_TITLEBAR_COLOR;
    int32_t  full_x   = sx - SSD_BORDER_W;
    int32_t  full_y   = sy - SSD_TITLEBAR_H - SSD_BORDER_W;
    int32_t  full_w   = sw + SSD_BORDER_W * 2;

    /* Top border + title bar */
    ssd_fill_rect(full_x, full_y, full_w, SSD_BORDER_W,    SSD_BORDER_COLOR);
    ssd_fill_rect(full_x, full_y + SSD_BORDER_W, full_w,
                  SSD_TITLEBAR_H, tbar_col);
    /* Left border */
    ssd_fill_rect(full_x, sy, SSD_BORDER_W, sh, SSD_BORDER_COLOR);
    /* Right border */
    ssd_fill_rect(sx + sw, sy, SSD_BORDER_W, sh, SSD_BORDER_COLOR);
    /* Bottom border */
    ssd_fill_rect(full_x, sy + sh, full_w, SSD_BORDER_W, SSD_BORDER_COLOR);
}

/* ── Blit helper ───────────────────────────────────────────────────────── */

/*
 * blit_buffer — copy pixels from a wl_buffer into the DRM back buffer
 * at screen position (dx, dy).  Only rows/columns that intersect at
 * least one of the active damage rectangles (or the entire screen when
 * full_damage is set) are written.  Returns 1 if any pixels were copied.
 */
static int blit_buffer(const WlBuffer *wb, int32_t dx, int32_t dy) {
    if (!fb[back_idx].map || !wb || !wb->shm_map) return 0;

    const uint8_t *src_base = (const uint8_t *)wb->shm_map + wb->offset;
    uint8_t       *dst_base = (uint8_t *)fb[back_idx].map;

    int32_t bw = wb->width, bh = wb->height, bs = wb->stride;
    int32_t src_col = 0, src_row = 0;
    if (dx < 0) { src_col = -dx; dx = 0; }
    if (dy < 0) { src_row = -dy; dy = 0; }
    int32_t copy_w = bw - src_col;
    int32_t copy_h = bh - src_row;
    if (dx + copy_w > (int32_t)screen_width)  copy_w = (int32_t)screen_width  - dx;
    if (dy + copy_h > (int32_t)screen_height) copy_h = (int32_t)screen_height - dy;
    if (copy_w <= 0 || copy_h <= 0) return 0;

    int copied = 0;
    for (int32_t row = 0; row < copy_h; row++) {
        int32_t screen_row = dy + row;
        /* Row culling: skip if no damage rect covers this row */
        if (!full_damage) {
            int hit = 0;
            for (int di = 0; di < n_screen_damage; di++) {
                const Rect *d = &screen_damage[di];
                if (screen_row >= d->y && screen_row < d->y + d->h &&
                    rect_intersects(d, dx, dy, copy_w, copy_h)) {
                    hit = 1; break;
                }
            }
            if (!hit) continue;
        }
        const uint8_t *src = src_base + (src_row + row) * bs + src_col * 4;
        uint8_t       *dst = dst_base
            + (uint32_t)screen_row * screen_stride
            + (uint32_t)dx * 4;
        memcpy(dst, src, (size_t)copy_w * 4);
        copied = 1;
    }
    return copied;
}

/* ── Surface lookup ────────────────────────────────────────────────────── */

static Surface *find_surface(Client *c, uint32_t id) {
    for (int i = 0; i < MAX_SURFACES; i++)
        if (c->surfaces[i].id == id) return &c->surfaces[i];
    return NULL;
}

static WlBuffer *find_buffer(Client *c, uint32_t id) {
    for (int i = 0; i < MAX_BUFFERS; i++)
        if (c->buffers[i].id == id) return &c->buffers[i];
    return NULL;
}

/* ── Compositing ───────────────────────────────────────────────────────── */

/*
 * blit_surface_tree — blit a root surface and then all desync subsurfaces
 * that are children of it (respecting above/below Z ordering).
 * Returns the number of subsurfaces that have their own damage and were
 * blitted; also merges their surface-space damage into the screen damage
 * accumulator.
 */
static void blit_surface_tree(Client *c, Surface *s, int ci) {
    WlBuffer *wb = find_buffer(c, s->attached_buffer_id);

    /* Blit children that should appear BELOW the parent */
    for (int si = 0; si < MAX_SUBSURFACES; si++) {
        Subsurface *sub = &c->subsurfaces[si];
        if (!sub->id || sub->parent_id != s->id || sub->above) continue;
        Surface *csub = find_surface(c, sub->surface_id);
        if (!csub || !csub->committed) continue;
        int32_t abs_x = s->x + sub->rel_x;
        int32_t abs_y = s->y + sub->rel_y;
        WlBuffer *cwb = find_buffer(c, csub->attached_buffer_id);
        if (cwb) {
            for (int di = 0; di < csub->n_damage; di++)
                damage_add(abs_x + (int32_t)csub->damage[di][0],
                           abs_y + (int32_t)csub->damage[di][1],
                           (int32_t)csub->damage[di][2],
                           (int32_t)csub->damage[di][3]);
            blit_buffer(cwb, abs_x, abs_y);
            csub->n_damage = 0;
        }
    }

    /* Blit parent surface */
    if (wb) blit_buffer(wb, s->x, s->y);

    /* Blit children that should appear ABOVE the parent */
    for (int si = 0; si < MAX_SUBSURFACES; si++) {
        Subsurface *sub = &c->subsurfaces[si];
        if (!sub->id || sub->parent_id != s->id || !sub->above) continue;
        Surface *csub = find_surface(c, sub->surface_id);
        if (!csub || !csub->committed) continue;
        int32_t abs_x = s->x + sub->rel_x;
        int32_t abs_y = s->y + sub->rel_y;
        WlBuffer *cwb = find_buffer(c, csub->attached_buffer_id);
        if (cwb) {
            for (int di = 0; di < csub->n_damage; di++)
                damage_add(abs_x + (int32_t)csub->damage[di][0],
                           abs_y + (int32_t)csub->damage[di][1],
                           (int32_t)csub->damage[di][2],
                           (int32_t)csub->damage[di][3]);
            blit_buffer(cwb, abs_x, abs_y);
            csub->n_damage = 0;
        }
    }

    /* Send wl_buffer.release for the parent buffer */
    if (wb)
        wl_send(c->fd, wb->id, WL_BUFFER_EVT_RELEASE, NULL, 0);

    /* Send wl_surface.enter on first commit */
    if (!s->enter_sent && c->output_id) {
        wl_send(c->fd, s->id, WL_SURFACE_EVT_ENTER, &c->output_id, 4);
        s->enter_sent = 1;
    }
    s->n_damage = 0;
    (void)ci;
}

/*
 * composite_and_flip — damage-aware repaint.
 *
 * Pipeline:
 *   1. Collect all pending surface damage into the screen damage accumulator.
 *   2. If full_damage, clear the back buffer to black first.
 *      Otherwise skip the clear — only damaged regions will be overwritten.
 *   3. Paint layer surfaces in order: BACKGROUND → BOTTOM.
 *   4. Paint regular xdg_toplevel surfaces (with SSD if applicable).
 *   5. Paint layer surfaces: TOP → OVERLAY.
 *   6. Page-flip.
 *   7. Reset damage accumulator.
 */
static void composite_and_flip(void) {
    if (!fb[back_idx].map) return;

    /* ── Step 1: collect surface damage into screen damage ── */
    for (int ci = 0; ci < n_clients; ci++) {
        Client *c = &clients[ci];
        if (!c->alive) continue;
        for (int si = 0; si < MAX_SURFACES; si++) {
            Surface *s = &c->surfaces[si];
            if (!s->id || !s->committed || s->parent_surface_id) continue;
            for (int di = 0; di < s->n_damage; di++)
                damage_add(s->x + (int32_t)s->damage[di][0],
                           s->y + (int32_t)s->damage[di][1],
                           (int32_t)s->damage[di][2],
                           (int32_t)s->damage[di][3]);
        }
        /* layer surfaces always mark their whole area dirty on commit */
        for (int li = 0; li < MAX_LAYER_SURFACES; li++) {
            LayerSurface *ls = &c->layer_surfaces[li];
            if (!ls->id || !ls->configured) continue;
            Surface *s = find_surface(c, ls->surface_id);
            if (s && s->committed && s->n_damage)
                damage_add(ls->x, ls->y, ls->w, ls->h);
        }
    }

    if (n_screen_damage == 0 && !full_damage) return; /* nothing to do */

    /* ── Step 2: clear only damaged regions (or full buffer) ── */
    if (full_damage) {
        memset(fb[back_idx].map, 0, (size_t)fb[back_idx].size);
    } else {
        uint8_t *base = (uint8_t *)fb[back_idx].map;
        for (int di = 0; di < n_screen_damage; di++) {
            const Rect *d = &screen_damage[di];
            for (int32_t row = 0; row < d->h; row++) {
                uint8_t *line = base
                    + (uint32_t)(d->y + row) * screen_stride
                    + (uint32_t)d->x * 4;
                memset(line, 0, (size_t)d->w * 4);
            }
        }
    }

    /* ── Macro: blit a layer at the given ZWL_LAYER_* enum value ── */
#define BLIT_LAYER(layer_enum) \
    for (int ci = 0; ci < n_clients; ci++) { \
        Client *c = &clients[ci]; \
        if (!c->alive) continue; \
        for (int li = 0; li < MAX_LAYER_SURFACES; li++) { \
            LayerSurface *ls = &c->layer_surfaces[li]; \
            if (!ls->id || ls->layer != (layer_enum) || !ls->configured) continue; \
            Surface *s = find_surface(c, ls->surface_id); \
            if (!s || !s->committed) continue; \
            s->x = ls->x; s->y = ls->y; \
            blit_surface_tree(c, s, ci); \
        } \
    }

    /* ── Steps 3-5: paint in Z order ── */
    BLIT_LAYER(ZWL_LAYER_BACKGROUND)
    BLIT_LAYER(ZWL_LAYER_BOTTOM)

    /* Regular xdg_toplevel surfaces */
    for (int ci = 0; ci < n_clients; ci++) {
        Client *c = &clients[ci];
        if (!c->alive) continue;
        for (int si = 0; si < MAX_SURFACES; si++) {
            Surface *s = &c->surfaces[si];
            if (!s->id || !s->committed || s->parent_surface_id) continue;
            /* Skip surfaces owned by a layer shell */
            int is_layer = 0;
            for (int li = 0; li < MAX_LAYER_SURFACES; li++)
                if (c->layer_surfaces[li].id &&
                    c->layer_surfaces[li].surface_id == s->id) { is_layer = 1; break; }
            if (is_layer) continue;

            /* Identify the xdg_toplevel for SSD */
            XdgToplevel *xt = NULL;
            for (int xi = 0; xi < MAX_XDG_SURFACES; xi++) {
                XdgSurface *xs = &c->xdg_surfaces[xi];
                if (!xs->id || xs->wl_surface_id != s->id) continue;
                for (int ti = 0; ti < MAX_XDG_TOPLEVELS; ti++) {
                    if (c->xdg_toplevels[ti].xdg_surface_id == xs->id) {
                        xt = &c->xdg_toplevels[ti]; break;
                    }
                }
            }

            WlBuffer *wb = find_buffer(c, s->attached_buffer_id);
            if (xt && !xt->has_csd) {
                /* Draw SSD — must happen before blitting client content
                 * so the titlebar doesn't overdraw the client pixels. */
                int is_focused = (focused_client == ci);
                int32_t cw = wb ? wb->width  : 0;
                int32_t ch = wb ? wb->height : 0;
                /* Mark SSD area dirty */
                damage_add(s->x - SSD_BORDER_W,
                           s->y - SSD_TITLEBAR_H - SSD_BORDER_W,
                           cw + SSD_BORDER_W * 2,
                           ch + SSD_TITLEBAR_H + SSD_BORDER_W * 2);
                ssd_draw_decorations(s->x, s->y, cw, ch, is_focused);
            }
            blit_surface_tree(c, s, ci);
        }
    }

    BLIT_LAYER(ZWL_LAYER_TOP)
    BLIT_LAYER(ZWL_LAYER_OVERLAY)
#undef BLIT_LAYER

    /* ── Step 6: flip ── */
    drm_flip();

    /* ── Step 7: reset damage ── */
    damage_clear();
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
            uint32_t new_id  = wl_read_u32(data, 4 + 4 + ipadded + 4);

            if (name == WL_GLOBAL_NAME_COMPOSITOR) {
                c->compositor_id = new_id;
            } else if (name == WL_GLOBAL_NAME_SUBCOMPOSITOR) {
                c->subcompositor_id = new_id;
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
            } else if (name == WL_GLOBAL_NAME_LAYER_SHELL) {
                c->layer_shell_id = new_id;
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

    /* ── wl_subcompositor ────────────────────────────────────────────── */
    if (obj == c->subcompositor_id) {
        if (op == WL_SUBCOMPOSITOR_REQ_GET_SUBSURFACE) {
            /*
             * get_subsurface(id: new_id, surface: wl_surface,
             *                parent: wl_surface)
             */
            uint32_t new_id    = wl_read_u32(data, 0);
            uint32_t surf_id   = wl_read_u32(data, 4);
            uint32_t parent_id = wl_read_u32(data, 8);
            for (int i = 0; i < MAX_SUBSURFACES; i++) {
                if (c->subsurfaces[i].id == 0) {
                    c->subsurfaces[i].id        = new_id;
                    c->subsurfaces[i].surface_id = surf_id;
                    c->subsurfaces[i].parent_id  = parent_id;
                    c->subsurfaces[i].rel_x      = 0;
                    c->subsurfaces[i].rel_y      = 0;
                    c->subsurfaces[i].sync        = 1; /* default: sync */
                    c->subsurfaces[i].above       = 1; /* default: above parent */
                    /* Mark the child surface as owned by a parent */
                    Surface *cs = find_surface(c, surf_id);
                    if (cs) cs->parent_surface_id = parent_id;
                    break;
                }
            }
        }
        return;
    }

    /* ── wl_subsurface ───────────────────────────────────────────────── */
    for (int si = 0; si < MAX_SUBSURFACES; si++) {
        Subsurface *sub = &c->subsurfaces[si];
        if (sub->id != obj) continue;
        switch (op) {
        case WL_SUBSURFACE_REQ_DESTROY:
            /* Unlink the child surface from its parent */
            {
                Surface *cs = find_surface(c, sub->surface_id);
                if (cs) cs->parent_surface_id = 0;
            }
            sub->id = 0;
            break;
        case WL_SUBSURFACE_REQ_SET_POSITION:
            sub->rel_x = wl_read_i32(data, 0);
            sub->rel_y = wl_read_i32(data, 4);
            /* Mark the parent surface damaged so the subsurface moves */
            {
                Surface *ps = find_surface(c, sub->parent_id);
                if (ps) full_damage = 1;
            }
            break;
        case WL_SUBSURFACE_REQ_PLACE_ABOVE:
            /*
             * place_above(sibling: wl_surface)
             * For MVP: if the sibling IS the parent, treat as above=1.
             * A full implementation would maintain an ordered Z-list.
             */
            sub->above = 1;
            break;
        case WL_SUBSURFACE_REQ_PLACE_BELOW:
            sub->above = 0;
            break;
        case WL_SUBSURFACE_REQ_SET_SYNC:
            sub->sync = 1;
            break;
        case WL_SUBSURFACE_REQ_SET_DESYNC:
            sub->sync = 0;
            break;
        }
        return;
    }

    /* ── zwlr_layer_shell_v1 ─────────────────────────────────────────── */
    if (obj == c->layer_shell_id) {
        if (op == ZWL_LAYER_SHELL_REQ_GET_LAYER_SURFACE) {
            /*
             * get_layer_surface(id: new_id, surface: wl_surface,
             *                   output: wl_output | 0,
             *                   layer: uint32, namespace: string)
             */
            uint32_t new_id  = wl_read_u32(data, 0);
            uint32_t surf_id = wl_read_u32(data, 4);
            /* output (4 bytes) — ignored: we have only one output */
            uint32_t layer   = wl_read_u32(data, 12);
            /* namespace string follows at offset 16 — not stored */
            for (int li = 0; li < MAX_LAYER_SURFACES; li++) {
                if (c->layer_surfaces[li].id == 0) {
                    LayerSurface *ls = &c->layer_surfaces[li];
                    memset(ls, 0, sizeof(*ls));
                    ls->id         = new_id;
                    ls->surface_id = surf_id;
                    ls->layer      = layer < 4u ? layer : ZWL_LAYER_TOP;
                    /* Send initial configure so the client knows the size */
                    layer_surface_configure(c, ls);
                    break;
                }
            }
        }
        return;
    }

    /* ── zwlr_layer_surface_v1 ───────────────────────────────────────── */
    for (int li = 0; li < MAX_LAYER_SURFACES; li++) {
        LayerSurface *ls = &c->layer_surfaces[li];
        if (ls->id != obj) continue;
        switch (op) {
        case ZWL_LAYER_SURFACE_REQ_SET_SIZE:
            ls->req_width  = wl_read_i32(data, 0);
            ls->req_height = wl_read_i32(data, 4);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_ANCHOR:
            ls->anchor = wl_read_u32(data, 0);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_EXCLUSIVE_ZONE:
            ls->exclusive_zone = wl_read_i32(data, 0);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_MARGIN:
            ls->margin_top    = wl_read_i32(data,  0);
            ls->margin_right  = wl_read_i32(data,  4);
            ls->margin_bottom = wl_read_i32(data,  8);
            ls->margin_left   = wl_read_i32(data, 12);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_KEYBOARD_INTERACTIVITY:
            /* Noted but keyboard routing is unchanged for now */
            break;
        case ZWL_LAYER_SURFACE_REQ_ACK_CONFIGURE:
            if (wl_read_u32(data, 0) == ls->pending_serial)
                ls->configured = 1;
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_LAYER:
            ls->layer = wl_read_u32(data, 0);
            layer_surface_configure(c, ls);
            break;
        case ZWL_LAYER_SURFACE_REQ_DESTROY:
            ls->id = 0;
            break;
        }