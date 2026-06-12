/*
 * userspace/wayland/compositor.c — rustos Wayland compositor
 *
 * Implements:
 *   1. wl_display socket at /run/wayland-0  (AF_UNIX stream)
 *   2. Wayland wire protocol dispatch with SCM_RIGHTS fd receive
 *   3. Core globals: wl_compositor, wl_shm, wl_seat, wl_output,
 *                    xdg_wm_base, wl_subcompositor, zwlr_layer_shell_v1
 *   4. wl_shm buffer sharing (SCM_RIGHTS fd → mmap pool → wl_buffer)
 *   5. xdg_shell: xdg_wm_base / xdg_surface / xdg_toplevel
 *   6. wl_keyboard.keymap and repeat_info
 *   7. Damage-region partial scanout into a DRM dumb-buffer back buffer
 *   8. wl_subsurface MVP positioning and above/below-parent Z behavior
 *   9. zwlr_layer_shell_v1 layer ordering and anchored geometry
 *  10. Server-side decorations for xdg_toplevel windows without CSD
 *
 * Missing / TODO:
 *   - seccomp allowlist filter
 *   - full wl_pointer event routing
 *   - wl_keyboard.enter / wl_keyboard.leave on focus change
 *   - xdg_wm_base ping scheduling
 *   - full subsurface sibling Z-list ordering
 *   - privilege drop after DRM/input fd acquisition
 *
 * Build:
 *   musl-gcc -static -O2 -D_GNU_SOURCE -fstack-protector-strong \
 *            -Wall -Wextra -std=c11 -o rustos-compositor compositor.c
 */

#include "compositor_types.h"

Client clients_storage[MAX_CLIENTS];
CompositorState g = {
    .epoll_fd       = -1,
    .listen_fd      = -1,
    .drm_fd         = -1,
    .input_fd       = -1,
    .screen_width   = 1024,
    .screen_height  = 768,
    .back_idx       = 1,
    .flip_pending   = 0,
    .full_damage    = 1,
    .focused_client = -1,
    .serial_counter = 1,
};

static NORETURN void compositor_fatal(const char *msg) {
    fprintf(stderr, "compositor: fatal: %s (errno=%d)\n", msg, errno);
    _exit(1);
}

static uint32_t next_serial(void) {
    uint32_t serial = g.serial_counter++;
    if (g.serial_counter == 0)
        g.serial_counter = 1;
    return serial ? serial : next_serial();
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

static int set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int write_all(int fd, const void *buf, size_t len) {
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

static int keymap_create_memfd(void) {
    int fd = (int)syscall(SYS_memfd_create, "xkb-keymap",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return -1;
    size_t len = sizeof(KEYMAP_STRING);
    if (write_all(fd, KEYMAP_STRING, len) < 0 ||
        lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return -1;
    }
    (void)fcntl(fd, F_ADD_SEALS,
                F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
    return fd;
}

/* ── Error / validation helpers ────────────────────────────────────────── */
static void post_error(Client *c, uint32_t bad_obj, uint32_t code, const char *msg) {
    if (!c || c->fd < 0) return;
    uint8_t payload[512];
    size_t sz = 0;
    memcpy(payload + sz, &bad_obj, 4); sz += 4;
    memcpy(payload + sz, &code,    4); sz += 4;
    sz += wl_encode_str(payload + sz, msg);
    wl_send(c->fd, WL_DISPLAY_ID, WL_DISPLAY_EVT_ERROR, payload, (uint16_t)sz);
    c->alive = 0;
}

static int require_len(Client *c, uint32_t obj, uint16_t op,
                       uint16_t dlen, uint16_t need) {
    if (dlen >= need) return 1;
    (void)op;
    post_error(c, obj, WL_DISPLAY_ERROR_BAD_LENGTH, "short Wayland request");
    return 0;
}

static int valid_layer(uint32_t layer) {
    return layer <= ZWL_LAYER_OVERLAY;
}

static int valid_shm_format(uint32_t format) {
    return format == WL_SHM_FORMAT_ARGB8888 ||
           format == WL_SHM_FORMAT_XRGB8888;
}

static int object_id_exists(Client *c, uint32_t id) {
    if (!id) return 1;
    if (id == WL_DISPLAY_ID) return 1;
    if (id == c->registry_id || id == c->compositor_id ||
        id == c->subcompositor_id || id == c->shm_id ||
        id == c->seat_id || id == c->pointer_id ||
        id == c->keyboard_id || id == c->output_id ||
        id == c->xdg_wm_base_id || id == c->layer_shell_id)
        return 1;
    for (int i = 0; i < MAX_SURFACES; i++)
        if (c->surfaces[i].id == id) return 1;
    for (int i = 0; i < MAX_SUBSURFACES; i++)
        if (c->subsurfaces[i].id == id) return 1;
    for (int i = 0; i < MAX_LAYER_SURFACES; i++)
        if (c->layer_surfaces[i].id == id) return 1;
    for (int i = 0; i < MAX_XDG_SURFACES; i++)
        if (c->xdg_surfaces[i].id == id) return 1;
    for (int i = 0; i < MAX_XDG_TOPLEVELS; i++)
        if (c->xdg_toplevels[i].id == id) return 1;
    for (int i = 0; i < MAX_BUFFERS; i++)
        if (c->buffers[i].id == id) return 1;
    for (int i = 0; i < MAX_POOLS; i++)
        if (c->pools[i].id == id) return 1;
    return 0;
}

static int require_new_id(Client *c, uint32_t obj, uint32_t new_id) {
    if (!object_id_exists(c, new_id)) return 1;
    post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "new object id already exists");
    return 0;
}

static void send_delete_id(Client *c, uint32_t id) {
    if (c && c->fd >= 0 && id)
        wl_send(c->fd, WL_DISPLAY_ID, WL_DISPLAY_EVT_DELETE_ID, &id, 4);
}

/* ── Lookup helpers ────────────────────────────────────────────────────── */
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

static XdgSurface *find_xdg_surface_for_wl_surface(Client *c, uint32_t wl_surface_id) {
    for (int i = 0; i < MAX_XDG_SURFACES; i++)
        if (c->xdg_surfaces[i].id && c->xdg_surfaces[i].wl_surface_id == wl_surface_id)
            return &c->xdg_surfaces[i];
    return NULL;
}

static XdgToplevel *find_xdg_toplevel_for_surface(Client *c, Surface *s) {
    XdgSurface *xs = find_xdg_surface_for_wl_surface(c, s ? s->id : 0);
    if (!xs) return NULL;
    for (int i = 0; i < MAX_XDG_TOPLEVELS; i++)
        if (c->xdg_toplevels[i].id && c->xdg_toplevels[i].xdg_surface_id == xs->id)
            return &c->xdg_toplevels[i];
    return NULL;
}

#include "drm.c"
#include "surface.c"
#include "layer_shell.c"
#include "xdg_shell.c"

/* ── Protocol event helpers ────────────────────────────────────────────── */
static void registry_global_send(Client *c, uint32_t name,
                                  const char *intf, uint32_t version) {
    uint8_t ev[256];
    size_t  sz = 0;
    memcpy(ev + sz, &name, 4); sz += 4;
    sz += wl_encode_str(ev + sz, intf);
    memcpy(ev + sz, &version, 4); sz += 4;
    wl_send(c->fd, c->registry_id, WL_REGISTRY_EVT_GLOBAL, ev, (uint16_t)sz);
}

static void send_registry_globals(Client *c) {
    registry_global_send(c, WL_GLOBAL_NAME_COMPOSITOR,    "wl_compositor",       WL_COMPOSITOR_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SHM,           "wl_shm",              WL_SHM_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SEAT,          "wl_seat",             WL_SEAT_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_OUTPUT,        "wl_output",           WL_OUTPUT_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_XDG_WM_BASE,   "xdg_wm_base",         XDG_WM_BASE_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_SUBCOMPOSITOR, "wl_subcompositor",    WL_SUBCOMPOSITOR_VERSION);
    registry_global_send(c, WL_GLOBAL_NAME_LAYER_SHELL,   "zwlr_layer_shell_v1", ZWL_LAYER_SHELL_VERSION);
}

static void send_output_info(Client *c) {
    uint32_t oid = c->output_id;
    if (!oid) return;

    uint8_t geom[256]; size_t gsz = 0;
    int32_t zeroi = 0;
    int32_t pw = OUTPUT_PHYS_W_MM, ph = OUTPUT_PHYS_H_MM;
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
    memcpy(mode + msz, &flags,           4); msz += 4;
    memcpy(mode + msz, &g.screen_width,  4); msz += 4;
    memcpy(mode + msz, &g.screen_height, 4); msz += 4;
    memcpy(mode + msz, &refresh,         4); msz += 4;
    wl_send(c->fd, oid, WL_OUTPUT_EVT_MODE, mode, (uint16_t)msz);
    wl_send(c->fd, oid, WL_OUTPUT_EVT_DONE, NULL, 0);
}

static void send_keymap(Client *c) {
    if (!c->keyboard_id) return;
    int kfd = keymap_create_memfd();
    if (kfd < 0) return;

    uint8_t payload[8];
    uint32_t fmt  = WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1;
    uint32_t size = (uint32_t)sizeof(KEYMAP_STRING);
    memcpy(payload,   &fmt,  4);
    memcpy(payload+4, &size, 4);
    wl_send_with_fd(c->fd, c->keyboard_id, WL_KEYBOARD_EVT_KEYMAP, payload, 8, kfd);
    close(kfd);

    uint8_t ri[8];
    int32_t rate  = 25;
    int32_t delay = 600;
    memcpy(ri,   &rate,  4);
    memcpy(ri+4, &delay, 4);
    wl_send(c->fd, c->keyboard_id, WL_KEYBOARD_EVT_REPEAT_INFO, ri, 8);
}

/* ── Dispatcher ────────────────────────────────────────────────────────── */
static void dispatch_message(Client *c, uint32_t obj, uint16_t op,
                             const uint8_t *data, uint16_t dlen) {
    if (obj == WL_DISPLAY_ID) {
        if (op == WL_DISPLAY_REQ_SYNC) {
            if (!require_len(c, obj, op, dlen, 4)) return;
            uint32_t cb_id = wl_read_u32(data, 0);
            if (!require_new_id(c, obj, cb_id)) return;
            uint32_t serial = next_serial();
            wl_send(c->fd, cb_id, WL_CALLBACK_EVT_DONE, &serial, 4);
            wl_send(c->fd, WL_DISPLAY_ID, WL_DISPLAY_EVT_DELETE_ID, &cb_id, 4);
        } else if (op == WL_DISPLAY_REQ_GET_REGISTRY) {
            if (!require_len(c, obj, op, dlen, 4)) return;
            uint32_t new_id = wl_read_u32(data, 0);
            if (!require_new_id(c, obj, new_id)) return;
            c->registry_id = new_id;
            send_registry_globals(c);
        }
        return;
    }

    if (obj == c->registry_id) {
        if (op == WL_REGISTRY_REQ_BIND) {
            if (!require_len(c, obj, op, dlen, 16)) return;
            uint32_t name = wl_read_u32(data, 0);
            uint32_t ilen = wl_read_u32(data, 4);
            if (ilen > dlen - 12u) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_LENGTH, "registry bind string overruns request");
                return;
            }
            uint32_t ipadded = (ilen + 3u) & ~3u;
            if (ipadded > dlen - 16u) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_LENGTH, "registry bind padding overruns request");
                return;
            }
            uint32_t new_id = wl_read_u32(data, 4 + 4 + ipadded + 4);
            if (!require_new_id(c, obj, new_id)) return;

            if (name == WL_GLOBAL_NAME_COMPOSITOR) {
                c->compositor_id = new_id;
            } else if (name == WL_GLOBAL_NAME_SUBCOMPOSITOR) {
                c->subcompositor_id = new_id;
            } else if (name == WL_GLOBAL_NAME_SHM) {
                c->shm_id = new_id;
                uint32_t fmt = WL_SHM_FORMAT_ARGB8888;
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

    if (obj == c->compositor_id) {
        if (op == WL_COMPOSITOR_REQ_CREATE_SURFACE) {
            if (!require_len(c, obj, op, dlen, 4)) return;
            uint32_t new_id = wl_read_u32(data, 0);
            if (!alloc_surface(c, new_id))
                post_error(c, obj, WL_DISPLAY_ERROR_NO_MEMORY, "surface table full or duplicate id");
        }
        return;
    }

    if (obj == c->subcompositor_id) {
        if (op == WL_SUBCOMPOSITOR_REQ_GET_SUBSURFACE) {
            if (!require_len(c, obj, op, dlen, 12)) return;
            uint32_t new_id    = wl_read_u32(data, 0);
            uint32_t surf_id   = wl_read_u32(data, 4);
            uint32_t parent_id = wl_read_u32(data, 8);
            if (!require_new_id(c, obj, new_id)) return;
            Surface *cs = find_surface(c, surf_id);
            Surface *ps = find_surface(c, parent_id);
            if (!cs || !ps) {
                post_error(c, obj, WL_DISPLAY_ERROR_INVALID_OBJECT, "bad subsurface surface id");
                return;
            }
            if (cs->role != SURFACE_ROLE_NONE) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_surface already has a role");
                return;
            }
            Subsurface *slot = NULL;
            for (int i = 0; i < MAX_SUBSURFACES; i++)
                if (!c->subsurfaces[i].id) { slot = &c->subsurfaces[i]; break; }
            if (!slot) {
                post_error(c, obj, WL_DISPLAY_ERROR_NO_MEMORY, "subsurface table full");
                return;
            }
            memset(slot, 0, sizeof(*slot));
            slot->id = new_id;
            slot->surface_id = surf_id;
            slot->parent_id = parent_id;
            slot->sync = 1;
            slot->above = 1;
            cs->parent_surface_id = parent_id;
            cs->role = SURFACE_ROLE_SUBSURFACE;
        }
        return;
    }

    for (int si = 0; si < MAX_SUBSURFACES; si++) {
        Subsurface *sub = &c->subsurfaces[si];
        if (sub->id != obj) continue;
        switch (op) {
        case WL_SUBSURFACE_REQ_DESTROY: {
            Surface *cs = find_surface(c, sub->surface_id);
            if (cs && cs->role == SURFACE_ROLE_SUBSURFACE) {
                cs->parent_surface_id = 0;
                cs->role = SURFACE_ROLE_NONE;
            }
            uint32_t id = sub->id;
            memset(sub, 0, sizeof(*sub));
            send_delete_id(c, id);
            break;
        }
        case WL_SUBSURFACE_REQ_SET_POSITION: {
            if (!require_len(c, obj, op, dlen, 8)) return;
            int32_t old_x = sub->rel_x, old_y = sub->rel_y;
            sub->rel_x = wl_read_i32(data, 0);
            sub->rel_y = wl_read_i32(data, 4);
            Surface *ps = find_surface(c, sub->parent_id);
            Surface *cs = find_surface(c, sub->surface_id);
            if (ps && cs) {
                WlBuffer *wb = find_buffer(c, cs->attached_buffer_id);
                int32_t w = wb ? wb->width : cs->blit_w;
                int32_t h = wb ? wb->height : cs->blit_h;
                damage_add(ps->x + old_x, ps->y + old_y, w, h);
                damage_add(ps->x + sub->rel_x, ps->y + sub->rel_y, w, h);
            }
            break;
        }
        case WL_SUBSURFACE_REQ_PLACE_ABOVE:
            if (!require_len(c, obj, op, dlen, 4)) return;
            /* TODO: maintain a full sibling Z-list; MVP only tracks above/below parent. */
            sub->above = 1;
            g.full_damage = 1;
            break;
        case WL_SUBSURFACE_REQ_PLACE_BELOW:
            if (!require_len(c, obj, op, dlen, 4)) return;
            /* TODO: maintain a full sibling Z-list; MVP only tracks above/below parent. */
            sub->above = 0;
            g.full_damage = 1;
            break;
        case WL_SUBSURFACE_REQ_SET_SYNC:
            sub->sync = 1;
            break;
        case WL_SUBSURFACE_REQ_SET_DESYNC:
            sub->sync = 0;
            break;
        default:
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported wl_subsurface request");
            break;
        }
        return;
    }

    if (dispatch_layer_shell_message(c, obj, op, data, dlen)) return;

    if (obj == c->shm_id) {
        if (op == WL_SHM_REQ_CREATE_POOL) {
            if (!require_len(c, obj, op, dlen, 8)) return;
            if (c->n_pending_fds <= 0) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_shm.create_pool missing fd");
                return;
            }
            uint32_t new_id = wl_read_u32(data, 0);
            int32_t size = wl_read_i32(data, 4);
            if (!require_new_id(c, obj, new_id)) return;
            if (size <= 0) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_shm pool has invalid size");
                return;
            }
            int fd = c->pending_fds[0];
            memmove(c->pending_fds, c->pending_fds + 1,
                    (size_t)(c->n_pending_fds - 1) * sizeof(c->pending_fds[0]));
            c->n_pending_fds--;
            (void)set_cloexec(fd);
            void *map = mmap(NULL, (size_t)size, PROT_READ, MAP_SHARED, fd, 0);
            if (map == MAP_FAILED) {
                close(fd);
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_shm pool mmap failed");
                return;
            }
            WlPool *slot = NULL;
            for (int i = 0; i < MAX_POOLS; i++)
                if (!c->pools[i].id) { slot = &c->pools[i]; break; }
            if (!slot) {
                munmap(map, (size_t)size);
                close(fd);
                post_error(c, obj, WL_DISPLAY_ERROR_NO_MEMORY, "wl_shm pool table full");
                return;
            }
            memset(slot, 0, sizeof(*slot));
            slot->id = new_id;
            slot->shm_fd = fd;
            slot->map = map;
            slot->size = size;
        }
        return;
    }

    for (int pi = 0; pi < MAX_POOLS; pi++) {
        WlPool *pool = &c->pools[pi];
        if (pool->id != obj) continue;
        switch (op) {
        case WL_SHM_POOL_REQ_CREATE_BUFFER: {
            if (!require_len(c, obj, op, dlen, 24)) return;
            uint32_t new_id = wl_read_u32(data, 0);
            int32_t offset = wl_read_i32(data, 4);
            int32_t width  = wl_read_i32(data, 8);
            int32_t height = wl_read_i32(data, 12);
            int32_t stride = wl_read_i32(data, 16);
            uint32_t format = wl_read_u32(data, 20);
            if (!require_new_id(c, obj, new_id)) return;
            if (offset < 0 || width <= 0 || height <= 0 || stride <= 0 ||
                width > INT32_MAX / BPP || !valid_shm_format(format)) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "invalid wl_shm buffer geometry");
                return;
            }
            int64_t min_stride = (int64_t)width * BPP;
            if ((int64_t)stride < min_stride) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "invalid wl_shm buffer stride");
                return;
            }
            if (height > 1 && (int64_t)(height - 1) > (INT64_MAX - min_stride) / stride) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_shm buffer size overflow");
                return;
            }
            int64_t image_bytes = (int64_t)(height - 1) * stride + min_stride;
            if (image_bytes <= 0 || (int64_t)offset > (int64_t)pool->size - image_bytes) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_shm buffer exceeds pool");
                return;
            }
            WlBuffer *slot = NULL;
            for (int i = 0; i < MAX_BUFFERS; i++)
                if (!c->buffers[i].id) { slot = &c->buffers[i]; break; }
            if (!slot) {
                post_error(c, obj, WL_DISPLAY_ERROR_NO_MEMORY, "wl_buffer table full");
                return;
            }
            memset(slot, 0, sizeof(*slot));
            slot->id = new_id;
            slot->shm_fd = pool->shm_fd;
            slot->shm_map = pool->map;
            slot->offset = offset;
            slot->width = width;
            slot->height = height;
            slot->stride = stride;
            slot->format = format;
            break;
        }
        case WL_SHM_POOL_REQ_DESTROY:
            for (int bi = 0; bi < MAX_BUFFERS; bi++)
                if (c->buffers[bi].id && c->buffers[bi].shm_fd == pool->shm_fd)
                    destroy_buffer(c, &c->buffers[bi]);
            destroy_pool(pool);
            break;
        case WL_SHM_POOL_REQ_RESIZE: {
            if (!require_len(c, obj, op, dlen, 4)) return;
            int32_t new_size = wl_read_i32(data, 0);
            if (new_size <= pool->size) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE,
                           "wl_shm_pool.resize must grow the pool");
                return;
            }
            void *new_map = mmap(NULL, (size_t)new_size, PROT_READ, MAP_SHARED, pool->shm_fd, 0);
            if (new_map == MAP_FAILED) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_shm pool resize mmap failed");
                return;
            }
            if (pool->map) munmap(pool->map, (size_t)pool->size);
            pool->map = new_map;
            pool->size = new_size;
            /* Single-threaded invariant: no concurrent repaint can observe stale shm_map. */
            for (int bi = 0; bi < MAX_BUFFERS; bi++)
                if (c->buffers[bi].id && c->buffers[bi].shm_fd == pool->shm_fd)
                    c->buffers[bi].shm_map = new_map;
            break;
        }
        default:
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported wl_shm_pool request");
            break;
        }
        return;
    }

    for (int bi = 0; bi < MAX_BUFFERS; bi++) {
        WlBuffer *b = &c->buffers[bi];
        if (b->id != obj) continue;
        if (op == WL_BUFFER_REQ_DESTROY)
            destroy_buffer(c, b);
        else
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported wl_buffer request");
        return;
    }

    for (int si = 0; si < MAX_SURFACES; si++) {
        Surface *s = &c->surfaces[si];
        if (s->id != obj) continue;
        switch (op) {
        case WL_SURFACE_REQ_DESTROY:
            destroy_surface(c, s);
            break;
        case WL_SURFACE_REQ_ATTACH: {
            if (!require_len(c, obj, op, dlen, 12)) return;
            uint32_t buffer_id = wl_read_u32(data, 0);
            WlBuffer *old = find_buffer(c, s->attached_buffer_id);
            WlBuffer *newb = buffer_id ? find_buffer(c, buffer_id) : NULL;
            if (buffer_id && !newb) {
                post_error(c, obj, WL_DISPLAY_ERROR_INVALID_OBJECT, "attach references unknown buffer");
                return;
            }
            if (old) damage_add(s->x, s->y, old->width, old->height);
            s->attached_buffer_id = buffer_id;
            if (newb) {
                s->blit_w = newb->width;
                s->blit_h = newb->height;
                damage_add(s->x, s->y, newb->width, newb->height);
            }
            break;
        }
        case WL_SURFACE_REQ_DAMAGE:
        case WL_SURFACE_REQ_DAMAGE_BUFFER:
            if (!require_len(c, obj, op, dlen, 16)) return;
            mark_surface_damage(s, wl_read_i32(data, 0), wl_read_i32(data, 4),
                                wl_read_i32(data, 8), wl_read_i32(data, 12));
            break;
        case WL_SURFACE_REQ_FRAME:
            if (!require_len(c, obj, op, dlen, 4)) return;
            {
                uint32_t cb_id = wl_read_u32(data, 0);
                if (!require_new_id(c, obj, cb_id)) return;
                s->frame_cb_id = cb_id;
            }
            break;
        case WL_SURFACE_REQ_COMMIT: {
            WlBuffer *wb = find_buffer(c, s->attached_buffer_id);
            if (s->has_prev)
                damage_add(s->prev_x, s->prev_y, s->prev_w, s->prev_h);
            if (wb) {
                s->blit_w = wb->width;
                s->blit_h = wb->height;
                damage_add(s->x, s->y, wb->width, wb->height);
            }
            s->prev_x = s->x; s->prev_y = s->y;
            s->prev_w = s->blit_w; s->prev_h = s->blit_h;
            s->has_prev = 1;
            s->committed = 1;
            if (s->frame_cb_id) {
                uint32_t serial = next_serial();
                wl_send(c->fd, s->frame_cb_id, WL_CALLBACK_EVT_DONE, &serial, 4);
                wl_send(c->fd, WL_DISPLAY_ID, WL_DISPLAY_EVT_DELETE_ID, &s->frame_cb_id, 4);
                s->frame_cb_id = 0;
            }
            composite_and_flip();
            break;
        }
        case WL_SURFACE_REQ_SET_OPAQUE:
        case WL_SURFACE_REQ_SET_INPUT:
        case WL_SURFACE_REQ_SET_BUFFER_TRANSFORM:
        case WL_SURFACE_REQ_SET_BUFFER_SCALE:
            break;
        default:
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported wl_surface request");
            break;
        }
        return;
    }

    if (obj == c->seat_id) {
        if (op == WL_SEAT_REQ_GET_POINTER) {
            if (!require_len(c, obj, op, dlen, 4)) return;
            uint32_t new_id = wl_read_u32(data, 0);
            if (!require_new_id(c, obj, new_id)) return;
            c->pointer_id = new_id;
        } else if (op == WL_SEAT_REQ_GET_KEYBOARD) {
            if (!require_len(c, obj, op, dlen, 4)) return;
            uint32_t new_id = wl_read_u32(data, 0);
            if (!require_new_id(c, obj, new_id)) return;
            c->keyboard_id = new_id;
            send_keymap(c);
        } else if (op != WL_SEAT_REQ_RELEASE) {
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported wl_seat request");
        }
        return;
    }

    if (dispatch_xdg_shell_message(c, obj, op, data, dlen)) return;

    post_error(c, obj, WL_DISPLAY_ERROR_INVALID_OBJECT, "unknown Wayland object");
}

/* ── Runtime event loop ────────────────────────────────────────────────── */
static Client *find_client_by_fd(int fd) {
    for (int i = 0; i < g.n_clients; i++)
        if (g.clients[i].alive && g.clients[i].fd == fd)
            return &g.clients[i];
    return NULL;
}

static int epoll_add_fd(int fd) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.fd = fd;
    return epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static int setup_wayland_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    (void)unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    (void)chmod(path, 0666);
    if (listen(fd, 64) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void parse_client_messages(Client *c) {
    while (c->rx_len >= 8 && c->alive) {
        uint32_t obj = wl_read_u32(c->rx, 0);
        uint16_t op, total;
        memcpy(&op,    c->rx + 4, 2);
        memcpy(&total, c->rx + 6, 2);
        if (total < 8 || total > RX_BUF_SIZE) {
            post_error(c, obj, WL_DISPLAY_ERROR_BAD_LENGTH, "invalid Wayland message length");
            return;
        }
        if (c->rx_len < total) break;
        dispatch_message(c, obj, op, c->rx + 8, (uint16_t)(total - 8));
        if (c->rx_len > total)
            memmove(c->rx, c->rx + total, c->rx_len - total);
        c->rx_len -= total;
    }
}

static void handle_client_fd(int fd) {
    Client *c = find_client_by_fd(fd);
    if (!c) return;
    for (;;) {
        if (c->rx_len == sizeof(c->rx)) {
            post_error(c, WL_DISPLAY_ID, WL_DISPLAY_ERROR_BAD_LENGTH, "client receive buffer full");
            return;
        }
        int fds[8];
        int nfds = 0;
        ssize_t n = recv_with_fd(fd, c->rx + c->rx_len,
                                 sizeof(c->rx) - c->rx_len,
                                 fds, 8, &nfds);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            c->alive = 0;
            break;
        }
        if (n == 0) {
            c->alive = 0;
            break;
        }
        for (int i = 0; i < nfds; i++) {
            if (c->n_pending_fds < (int)(sizeof(c->pending_fds) / sizeof(c->pending_fds[0]))) {
                c->pending_fds[c->n_pending_fds++] = fds[i];
            } else {
                close(fds[i]);
                post_error(c, WL_DISPLAY_ID, WL_DISPLAY_ERROR_NO_MEMORY, "too many pending fds");
                return;
            }
        }
        c->rx_len += (size_t)n;
        parse_client_messages(c);
    }
}

static void accept_clients(void) {
    for (;;) {
        int fd = accept4(g.listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!g.clients[i].alive && g.clients[i].fd <= 0) { slot = i; break; }
        }
        if (slot < 0) {
            close(fd);
            continue;
        }
        memset(&g.clients[slot], 0, sizeof(g.clients[slot]));
        g.clients[slot].fd = fd;
        g.clients[slot].alive = 1;
        if (slot + 1 > g.n_clients)
            g.n_clients = slot + 1;
        if (epoll_add_fd(fd) < 0) {
            close(fd);
            memset(&g.clients[slot], 0, sizeof(g.clients[slot]));
        }
    }
}

static void destroy_client_resources(Client *c) {
    if (!c) return;
    for (int i = 0; i < c->n_pending_fds; i++)
        if (c->pending_fds[i] >= 0) close(c->pending_fds[i]);
    c->n_pending_fds = 0;
    for (int i = 0; i < MAX_BUFFERS; i++) destroy_buffer(c, &c->buffers[i]);
    for (int i = 0; i < MAX_POOLS; i++) destroy_pool(&c->pools[i]);
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->alive = 0;
}

static void reap_dead_clients(void) {
    for (int i = 0; i < g.n_clients; i++) {
        Client *c = &g.clients[i];
        if (!c->alive && c->fd >= 0)
            destroy_client_resources(c);
    }
    while (g.n_clients > 0 && !g.clients[g.n_clients - 1].alive && g.clients[g.n_clients - 1].fd <= 0)
        g.n_clients--;
}

#ifndef COMPOSITOR_SELFTEST
int main(void) {
    g.clients = clients_storage;

    g.drm_fd = open(DRM_DEVICE_PATH, O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (g.drm_fd < 0) compositor_fatal("open DRM device");
    if (drm_setup() < 0) compositor_fatal("DRM setup");

    g.listen_fd = setup_wayland_socket(WAYLAND_SOCKET_PATH);
    if (g.listen_fd < 0) compositor_fatal("Wayland socket setup");

    g.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g.epoll_fd < 0) compositor_fatal("epoll_create1");
    if (epoll_add_fd(g.listen_fd) < 0) compositor_fatal("epoll add listen fd");
    if (epoll_add_fd(g.drm_fd) < 0) compositor_fatal("epoll add DRM fd");

    for (;;) {
        struct epoll_event evs[64];
        int n = epoll_wait(g.epoll_fd, evs, 64, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            compositor_fatal("epoll_wait");
        }
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == g.listen_fd) {
                accept_clients();
            } else if (fd == g.drm_fd) {
                handle_drm_events();
                composite_and_flip();
            } else {
                handle_client_fd(fd);
            }
        }
        reap_dead_clients();
    }
}
#else
static int selftest_ok = 1;
#define SELFTEST_ASSERT(expr) \
    do { if (!(expr)) { fprintf(stderr, "FAIL: %s\n", #expr); selftest_ok = 0; } } while (0)

static void compositor_selftest_damage(void) {
    g.full_damage = 0;
    g.n_screen_damage = 0;
    g.screen_width = 100;
    g.screen_height = 80;
    damage_add(-10, -5, 25, 20);
    SELFTEST_ASSERT(g.n_screen_damage == 1);
    SELFTEST_ASSERT(g.screen_damage[0].x == 0);
    SELFTEST_ASSERT(g.screen_damage[0].y == 0);
    SELFTEST_ASSERT(g.screen_damage[0].w == 15);
    SELFTEST_ASSERT(g.screen_damage[0].h == 15);
}

static void compositor_selftest_formats(void) {
    SELFTEST_ASSERT(valid_shm_format(WL_SHM_FORMAT_ARGB8888));
    SELFTEST_ASSERT(valid_shm_format(WL_SHM_FORMAT_XRGB8888));
    SELFTEST_ASSERT(!valid_shm_format(0xDEADBEEFu));
}

static void compositor_selftest_layer_layout(void) {
    LayerSurface ls;
    memset(&ls, 0, sizeof(ls));
    g.full_damage = 0;
    g.screen_width = 1920;
    g.screen_height = 1080;
    ls.anchor = ZWL_ANCHOR_TOP | ZWL_ANCHOR_LEFT | ZWL_ANCHOR_RIGHT;
    ls.req_height = 32;
    ls.margin_left = 4;
    ls.margin_right = 6;
    layer_surface_layout(&ls);
    SELFTEST_ASSERT(ls.x == 4);
    SELFTEST_ASSERT(ls.y == 0);
    SELFTEST_ASSERT(ls.w == 1910);
    SELFTEST_ASSERT(ls.h == 32);
}

static void compositor_selftest_damage_rect(void) {
    Surface s;
    memset(&s, 0, sizeof(s));
    g.screen_width  = 800;
    g.screen_height = 600;
    s.n_damage = MAX_DAMAGE_RECTS;
    mark_surface_damage(&s, 0, 0, 1, 1);
    SELFTEST_ASSERT(s.n_damage == 1);
    SELFTEST_ASSERT(s.damage[0].w == (int32_t)g.screen_width);
    SELFTEST_ASSERT(s.damage[0].h == (int32_t)g.screen_height);
}

static void compositor_selftest_serial_wrap(void) {
    g.serial_counter = UINT32_MAX;
    uint32_t s1 = next_serial();
    uint32_t s2 = next_serial();
    SELFTEST_ASSERT(s1 == UINT32_MAX);
    SELFTEST_ASSERT(s2 == 1);
}

static void compositor_selftest_object_ids(void) {
    Client c;
    memset(&c, 0, sizeof(c));
    c.fd = -1;
    c.compositor_id = 7;
    SELFTEST_ASSERT(object_id_exists(&c, WL_DISPLAY_ID));
    SELFTEST_ASSERT(object_id_exists(&c, 7));
    SELFTEST_ASSERT(!object_id_exists(&c, 99));
}

int main(void) {
    g.clients = clients_storage;
    compositor_selftest_damage();
    compositor_selftest_formats();
    compositor_selftest_layer_layout();
    compositor_selftest_damage_rect();
    compositor_selftest_serial_wrap();
    compositor_selftest_object_ids();
    if (selftest_ok)
        fprintf(stderr, "compositor selftest: all passed\n");
    return selftest_ok ? 0 : 1;
}
#endif /* COMPOSITOR_SELFTEST */
