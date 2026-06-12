#include "compositor_types.h"

/* ── XDG shell helpers ─────────────────────────────────────────────────── */
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

static int dispatch_xdg_shell_message(Client *c, uint32_t obj, uint16_t op,
                                      const uint8_t *data, uint16_t dlen) {
    if (obj == c->xdg_wm_base_id) {
        if (op == XDG_WM_BASE_REQ_GET_XDG_SURFACE) {
            if (!require_len(c, obj, op, dlen, 8)) return 1;
            uint32_t new_id = wl_read_u32(data, 0);
            uint32_t surf_id = wl_read_u32(data, 4);
            if (!require_new_id(c, obj, new_id)) return 1;
            Surface *s = find_surface(c, surf_id);
            if (!s) {
                post_error(c, obj, WL_DISPLAY_ERROR_INVALID_OBJECT, "bad xdg surface id");
                return 1;
            }
            if (s->role != SURFACE_ROLE_NONE) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_surface already has a role");
                return 1;
            }
            XdgSurface *slot = NULL;
            for (int i = 0; i < MAX_XDG_SURFACES; i++)
                if (!c->xdg_surfaces[i].id) { slot = &c->xdg_surfaces[i]; break; }
            if (!slot) {
                post_error(c, obj, WL_DISPLAY_ERROR_NO_MEMORY, "xdg_surface table full");
                return 1;
            }
            memset(slot, 0, sizeof(*slot));
            slot->id = new_id;
            slot->wl_surface_id = surf_id;
            s->role = SURFACE_ROLE_XDG;
        } else if (op == XDG_WM_BASE_REQ_PONG) {
            if (!require_len(c, obj, op, dlen, 4)) return 1;
        } else if (op == XDG_WM_BASE_REQ_CREATE_POSITIONER) {
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            /* Positioner objects are accepted but not modeled until popups are implemented. */
        } else if (op == XDG_WM_BASE_REQ_DESTROY) {
            c->xdg_wm_base_id = 0;
        } else {
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported xdg_wm_base request");
        }
        return 1;
    }

    for (int xi = 0; xi < MAX_XDG_SURFACES; xi++) {
        XdgSurface *xs = &c->xdg_surfaces[xi];
        if (xs->id != obj) continue;
        switch (op) {
        case XDG_SURFACE_REQ_DESTROY: {
            Surface *s = find_surface(c, xs->wl_surface_id);
            if (s && s->role == SURFACE_ROLE_XDG)
                s->role = SURFACE_ROLE_NONE;
            uint32_t id = xs->id;
            uint32_t xsid = xs->id;
            memset(xs, 0, sizeof(*xs));
            for (int ti = 0; ti < MAX_XDG_TOPLEVELS; ti++)
                if (c->xdg_toplevels[ti].xdg_surface_id == xsid)
                    memset(&c->xdg_toplevels[ti], 0, sizeof(c->xdg_toplevels[ti]));
            send_delete_id(c, id);
            break;
        }
        case XDG_SURFACE_REQ_GET_TOPLEVEL: {
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            uint32_t new_id = wl_read_u32(data, 0);
            if (!require_new_id(c, obj, new_id)) return 1;
            XdgToplevel *slot = NULL;
            for (int i = 0; i < MAX_XDG_TOPLEVELS; i++)
                if (!c->xdg_toplevels[i].id) { slot = &c->xdg_toplevels[i]; break; }
            if (!slot) {
                post_error(c, obj, WL_DISPLAY_ERROR_NO_MEMORY, "xdg_toplevel table full");
                return 1;
            }
            memset(slot, 0, sizeof(*slot));
            slot->id = new_id;
            slot->xdg_surface_id = xs->id;
            send_xdg_configure(c, xs, slot);
            break;
        }
        case XDG_SURFACE_REQ_ACK_CONFIGURE:
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            if (wl_read_u32(data, 0) == xs->pending_configure_serial)
                xs->configured = 1;
            break;
        case XDG_SURFACE_REQ_SET_WINDOW_GEOMETRY:
            if (!require_len(c, obj, op, dlen, 16)) return 1;
            break;
        default:
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported xdg_surface request");
            break;
        }
        return 1;
    }

    for (int ti = 0; ti < MAX_XDG_TOPLEVELS; ti++) {
        XdgToplevel *xt = &c->xdg_toplevels[ti];
        if (xt->id != obj) continue;
        switch (op) {
        case XDG_TOPLEVEL_REQ_DESTROY: {
            uint32_t id = xt->id;
            memset(xt, 0, sizeof(*xt));
            send_delete_id(c, id);
            break;
        }
        case XDG_TOPLEVEL_REQ_SET_TITLE:
        case XDG_TOPLEVEL_REQ_SET_APP_ID: {
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            uint32_t len = wl_read_u32(data, 0);
            uint32_t padded = (len + 3u) & ~3u;
            if (len > dlen - 4u || padded > dlen - 4u) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_LENGTH, "xdg_toplevel string overruns request");
                return 1;
            }
            char *dst = (op == XDG_TOPLEVEL_REQ_SET_TITLE) ? xt->title : xt->app_id;
            size_t cap = (op == XDG_TOPLEVEL_REQ_SET_TITLE) ? sizeof(xt->title) : sizeof(xt->app_id);
            size_t copy = len < cap - 1 ? len : cap - 1;
            memcpy(dst, data + 4, copy);
            dst[copy] = '\0';
            break;
        }
        case XDG_TOPLEVEL_REQ_SET_MIN_SIZE:
            if (!require_len(c, obj, op, dlen, 8)) return 1;
            xt->min_w = wl_read_i32(data, 0);
            xt->min_h = wl_read_i32(data, 4);
            break;
        case XDG_TOPLEVEL_REQ_SET_MAX_SIZE:
            if (!require_len(c, obj, op, dlen, 8)) return 1;
            xt->max_w = wl_read_i32(data, 0);
            xt->max_h = wl_read_i32(data, 4);
            break;
        case XDG_TOPLEVEL_REQ_SET_PARENT:
        case XDG_TOPLEVEL_REQ_SHOW_WINDOW_MENU:
        case XDG_TOPLEVEL_REQ_MOVE:
        case XDG_TOPLEVEL_REQ_RESIZE:
        case XDG_TOPLEVEL_REQ_SET_MAXIMIZED:
        case XDG_TOPLEVEL_REQ_UNSET_MAXIMIZED:
        case XDG_TOPLEVEL_REQ_SET_FULLSCREEN:
        case XDG_TOPLEVEL_REQ_UNSET_FULLSCREEN:
        case XDG_TOPLEVEL_REQ_SET_MINIMIZED:
            /* Accepted as no-op MVP behavior; TODO: implement interactive move/resize/state. */
            break;
        default:
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported xdg_toplevel request");
            break;
        }
        return 1;
    }

    return 0;
}
