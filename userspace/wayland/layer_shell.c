#include "compositor_types.h"

/* ── Layer shell helpers ───────────────────────────────────────────────── */
static void layer_surface_layout(LayerSurface *ls) {
    int32_t sw = (int32_t)g.screen_width;
    int32_t sh = (int32_t)g.screen_height;
    int32_t x = ls->margin_left;
    int32_t y = ls->margin_top;
    int32_t usable_w = sw - ls->margin_left - ls->margin_right;
    int32_t usable_h = sh - ls->margin_top  - ls->margin_bottom;
    if (usable_w < 0) usable_w = 0;
    if (usable_h < 0) usable_h = 0;
    int32_t w = ls->req_width  > 0 ? ls->req_width  : usable_w;
    int32_t h = ls->req_height > 0 ? ls->req_height : usable_h;

    uint32_t a = ls->anchor;
    if ((a & ZWL_ANCHOR_LEFT) && (a & ZWL_ANCHOR_RIGHT)) w = usable_w;
    if ((a & ZWL_ANCHOR_TOP)  && (a & ZWL_ANCHOR_BOTTOM)) h = usable_h;
    if (w < 0) w = 0;
    if (h < 0) h = 0;

    if ((a & ZWL_ANCHOR_RIGHT) && !(a & ZWL_ANCHOR_LEFT))
        x = sw - w - ls->margin_right;
    if ((a & ZWL_ANCHOR_BOTTOM) && !(a & ZWL_ANCHOR_TOP))
        y = sh - h - ls->margin_bottom;

    if (ls->has_prev)
        damage_add(ls->prev_x, ls->prev_y, ls->prev_w, ls->prev_h);
    ls->x = x; ls->y = y; ls->w = w; ls->h = h;
    ls->prev_x = x; ls->prev_y = y;
    ls->prev_w = w; ls->prev_h = h;
    ls->has_prev = 1;
    if (ls->exclusive_zone != 0)
        g.full_damage = 1;
}

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

static int dispatch_layer_shell_message(Client *c, uint32_t obj, uint16_t op,
                                        const uint8_t *data, uint16_t dlen) {
    if (obj == c->layer_shell_id) {
        if (op == ZWL_LAYER_SHELL_REQ_GET_LAYER_SURFACE) {
            if (!require_len(c, obj, op, dlen, 16)) return 1;
            uint32_t new_id  = wl_read_u32(data, 0);
            uint32_t surf_id = wl_read_u32(data, 4);
            uint32_t layer   = wl_read_u32(data, 12);
            if (!require_new_id(c, obj, new_id)) return 1;
            Surface *s = find_surface(c, surf_id);
            if (!s) {
                post_error(c, obj, WL_DISPLAY_ERROR_INVALID_OBJECT, "bad layer surface id");
                return 1;
            }
            if (s->role != SURFACE_ROLE_NONE) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "wl_surface already has a role");
                return 1;
            }
            LayerSurface *slot = NULL;
            for (int li = 0; li < MAX_LAYER_SURFACES; li++)
                if (!c->layer_surfaces[li].id) { slot = &c->layer_surfaces[li]; break; }
            if (!slot) {
                post_error(c, obj, WL_DISPLAY_ERROR_NO_MEMORY, "layer-surface table full");
                return 1;
            }
            memset(slot, 0, sizeof(*slot));
            slot->id = new_id;
            slot->surface_id = surf_id;
            slot->layer = valid_layer(layer) ? layer : ZWL_LAYER_TOP;
            s->role = SURFACE_ROLE_LAYER;
            layer_surface_configure(c, slot);
        }
        return 1;
    }

    for (int li = 0; li < MAX_LAYER_SURFACES; li++) {
        LayerSurface *ls = &c->layer_surfaces[li];
        if (ls->id != obj) continue;
        switch (op) {
        case ZWL_LAYER_SURFACE_REQ_SET_SIZE:
            if (!require_len(c, obj, op, dlen, 8)) return 1;
            ls->req_width  = wl_read_i32(data, 0);
            ls->req_height = wl_read_i32(data, 4);
            layer_surface_configure(c, ls);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_ANCHOR:
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            ls->anchor = wl_read_u32(data, 0);
            layer_surface_configure(c, ls);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_EXCLUSIVE_ZONE:
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            ls->exclusive_zone = wl_read_i32(data, 0);
            layer_surface_configure(c, ls);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_MARGIN:
            if (!require_len(c, obj, op, dlen, 16)) return 1;
            ls->margin_top    = wl_read_i32(data,  0);
            ls->margin_right  = wl_read_i32(data,  4);
            ls->margin_bottom = wl_read_i32(data,  8);
            ls->margin_left   = wl_read_i32(data, 12);
            layer_surface_configure(c, ls);
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_KEYBOARD_INTERACTIVITY:
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            break;
        case ZWL_LAYER_SURFACE_REQ_ACK_CONFIGURE:
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            if (wl_read_u32(data, 0) == ls->pending_serial)
                ls->configured = 1;
            break;
        case ZWL_LAYER_SURFACE_REQ_SET_LAYER: {
            if (!require_len(c, obj, op, dlen, 4)) return 1;
            uint32_t new_layer = wl_read_u32(data, 0);
            if (!valid_layer(new_layer)) {
                post_error(c, obj, WL_DISPLAY_ERROR_BAD_VALUE, "bad layer enum");
                return 1;
            }
            ls->layer = new_layer;
            layer_surface_configure(c, ls);
            break;
        }
        case ZWL_LAYER_SURFACE_REQ_DESTROY: {
            Surface *s = find_surface(c, ls->surface_id);
            if (s && s->role == SURFACE_ROLE_LAYER)
                s->role = SURFACE_ROLE_NONE;
            uint32_t id = ls->id;
            memset(ls, 0, sizeof(*ls));
            send_delete_id(c, id);
            break;
        }
        default:
            post_error(c, obj, WL_DISPLAY_ERROR_INVALID_METHOD, "unsupported layer-surface request");
            break;
        }
        return 1;
    }

    return 0;
}
