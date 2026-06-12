#include "compositor_types.h"

/* ── Damage helpers ────────────────────────────────────────────────────── */
static inline void damage_add(int32_t x, int32_t y, int32_t w, int32_t h) {
    if (g.full_damage) return;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int32_t)g.screen_width)  w = (int32_t)g.screen_width  - x;
    if (y + h > (int32_t)g.screen_height) h = (int32_t)g.screen_height - y;
    if (w <= 0 || h <= 0) return;
    if (g.n_screen_damage >= MAX_SCREEN_DAMAGE) { g.full_damage = 1; return; }
    g.screen_damage[g.n_screen_damage++] = (Rect){x, y, w, h};
}

static inline void damage_clear(void) {
    g.n_screen_damage = 0;
    g.full_damage     = 0;
}

static inline int rect_intersects(const Rect *d,
                                   int32_t bx, int32_t by,
                                   int32_t bw, int32_t bh) {
    return !(bx >= d->x + d->w || bx + bw <= d->x ||
             by >= d->y + d->h || by + bh <= d->y);
}

static void mark_surface_damage(Surface *s, int32_t x, int32_t y, int32_t w, int32_t h) {
    if (!s || w <= 0 || h <= 0) return;
    if (s->n_damage >= MAX_DAMAGE_RECTS) {
        s->n_damage = 1;
        s->damage[0] = (Rect){
            .x = 0,
            .y = 0,
            .w = s->blit_w > 0 ? s->blit_w : (int32_t)g.screen_width,
            .h = s->blit_h > 0 ? s->blit_h : (int32_t)g.screen_height,
        };
        return;
    }
    s->damage[s->n_damage++] = (Rect){x, y, w, h};
}

/* ── Rendering ─────────────────────────────────────────────────────────── */
static void ssd_fill_rect(int32_t rx, int32_t ry, int32_t rw, int32_t rh,
                           uint32_t color) {
    if (!g.fb[g.back_idx].map) return;
    if (rx < 0) { rw += rx; rx = 0; }
    if (ry < 0) { rh += ry; ry = 0; }
    if (rx + rw > (int32_t)g.screen_width)  rw = (int32_t)g.screen_width  - rx;
    if (ry + rh > (int32_t)g.screen_height) rh = (int32_t)g.screen_height - ry;
    if (rw <= 0 || rh <= 0) return;

    uint32_t *dst = (uint32_t *)g.fb[g.back_idx].map;
    for (int32_t row = 0; row < rh; row++) {
        uint32_t *line = dst + (uint32_t)(ry + row) * (g.screen_stride / BPP) + (uint32_t)rx;
        for (int32_t col = 0; col < rw; col++)
            line[col] = color;
    }
}

static void ssd_draw_decorations(int32_t sx, int32_t sy, int32_t sw, int32_t sh,
                                  int focused) {
    uint32_t tbar_col = focused ? SSD_FOCUSED_COLOR : SSD_TITLEBAR_COLOR;
    int32_t full_x = sx - SSD_BORDER_W;
    int32_t full_y = sy - SSD_TITLEBAR_H - SSD_BORDER_W;
    int32_t full_w = sw + SSD_BORDER_W * 2;
    ssd_fill_rect(full_x, full_y, full_w, SSD_BORDER_W, SSD_BORDER_COLOR);
    ssd_fill_rect(full_x, full_y + SSD_BORDER_W, full_w, SSD_TITLEBAR_H, tbar_col);
    ssd_fill_rect(full_x, sy, SSD_BORDER_W, sh, SSD_BORDER_COLOR);
    ssd_fill_rect(sx + sw, sy, SSD_BORDER_W, sh, SSD_BORDER_COLOR);
    ssd_fill_rect(full_x, sy + sh, full_w, SSD_BORDER_W, SSD_BORDER_COLOR);
}

static int blit_buffer(const WlBuffer *wb, int32_t dx, int32_t dy) {
    if (!g.fb[g.back_idx].map || !wb || !wb->shm_map) return 0;

    const uint8_t *src_base = (const uint8_t *)wb->shm_map + wb->offset;
    uint8_t       *dst_base = (uint8_t *)g.fb[g.back_idx].map;

    int32_t bw = wb->width, bh = wb->height, bs = wb->stride;
    int32_t src_col = 0, src_row = 0;
    if (dx < 0) { src_col = -dx; dx = 0; }
    if (dy < 0) { src_row = -dy; dy = 0; }
    int32_t copy_w = bw - src_col;
    int32_t copy_h = bh - src_row;
    if (dx + copy_w > (int32_t)g.screen_width)  copy_w = (int32_t)g.screen_width  - dx;
    if (dy + copy_h > (int32_t)g.screen_height) copy_h = (int32_t)g.screen_height - dy;
    if (copy_w <= 0 || copy_h <= 0) return 0;

    int copied = 0;
    for (int32_t row = 0; row < copy_h; row++) {
        int32_t screen_row = dy + row;
        if (!g.full_damage) {
            int hit = 0;
            for (int di = 0; di < g.n_screen_damage; di++) {
                const Rect *d = &g.screen_damage[di];
                if (screen_row >= d->y && screen_row < d->y + d->h &&
                    rect_intersects(d, dx, dy, copy_w, copy_h)) {
                    hit = 1; break;
                }
            }
            if (!hit) continue;
        }
        const uint32_t *src = (const uint32_t *)(const void *)
            (src_base + (src_row + row) * bs + src_col * BPP);
        uint32_t *dst = (uint32_t *)(void *)
            (dst_base + (uint32_t)screen_row * g.screen_stride + (uint32_t)dx * BPP);
        if (wb->format == WL_SHM_FORMAT_XRGB8888) {
            memcpy(dst, src, (size_t)copy_w * BPP);
        } else {
            for (int32_t col = 0; col < copy_w; col++) {
                uint32_t sp = src[col];
                uint32_t a = sp >> 24;
                if (a == 255u) {
                    dst[col] = sp;
                } else if (a != 0u) {
                    uint32_t dp = dst[col];
                    uint32_t inv = 255u - a;
                    uint32_t rb = (((sp & 0x00FF00FFu) * a) +
                                   ((dp & 0x00FF00FFu) * inv)) >> 8;
                    uint32_t g_ch = (((sp & 0x0000FF00u) * a) +
                                     ((dp & 0x0000FF00u) * inv)) >> 8;
                    dst[col] = 0xFF000000u | (rb & 0x00FF00FFu) | (g_ch & 0x0000FF00u);
                }
            }
        }
        copied = 1;
    }
    return copied;
}

static void destroy_buffer(Client *c, WlBuffer *b) {
    if (!b || !b->id) return;
    uint32_t id = b->id;
    memset(b, 0, sizeof(*b));
    send_delete_id(c, id);
}

static void destroy_pool(WlPool *p) {
    if (!p || !p->id) return;
    if (p->map && p->size > 0) munmap(p->map, (size_t)p->size);
    if (p->shm_fd >= 0) close(p->shm_fd);
    memset(p, 0, sizeof(*p));
    p->shm_fd = -1;
}

static void destroy_surface(Client *c, Surface *s) {
    if (!c || !s || !s->id) return;
    uint32_t sid = s->id;
    for (int i = 0; i < MAX_SUBSURFACES; i++) {
        if (c->subsurfaces[i].id &&
            (c->subsurfaces[i].surface_id == sid || c->subsurfaces[i].parent_id == sid))
            memset(&c->subsurfaces[i], 0, sizeof(c->subsurfaces[i]));
    }
    for (int i = 0; i < MAX_LAYER_SURFACES; i++)
        if (c->layer_surfaces[i].surface_id == sid)
            memset(&c->layer_surfaces[i], 0, sizeof(c->layer_surfaces[i]));
    for (int i = 0; i < MAX_XDG_SURFACES; i++)
        if (c->xdg_surfaces[i].wl_surface_id == sid) {
            uint32_t xsid = c->xdg_surfaces[i].id;
            memset(&c->xdg_surfaces[i], 0, sizeof(c->xdg_surfaces[i]));
            for (int ti = 0; ti < MAX_XDG_TOPLEVELS; ti++)
                if (c->xdg_toplevels[ti].xdg_surface_id == xsid)
                    memset(&c->xdg_toplevels[ti], 0, sizeof(c->xdg_toplevels[ti]));
        }
    damage_add(s->x, s->y, s->blit_w, s->blit_h);
    uint32_t id = s->id;
    memset(s, 0, sizeof(*s));
    send_delete_id(c, id);
}

static Surface *alloc_surface(Client *c, uint32_t id) {
    if (object_id_exists(c, id)) return NULL;
    for (int i = 0; i < MAX_SURFACES; i++) {
        if (c->surfaces[i].id == 0) {
            memset(&c->surfaces[i], 0, sizeof(c->surfaces[i]));
            c->surfaces[i].id = id;
            c->surfaces[i].role = SURFACE_ROLE_NONE;
            return &c->surfaces[i];
        }
    }
    return NULL;
}

static void blit_surface_tree(Client *c, Surface *s) {
    WlBuffer *wb = find_buffer(c, s->attached_buffer_id);

    for (int pass = 0; pass < 2; pass++) {
        int want_above = pass;
        if (pass == 1 && wb)
            blit_buffer(wb, s->x, s->y);
        for (int si = 0; si < MAX_SUBSURFACES; si++) {
            Subsurface *sub = &c->subsurfaces[si];
            if (!sub->id || sub->parent_id != s->id || sub->above != want_above) continue;
            Surface *csub = find_surface(c, sub->surface_id);
            if (!csub || !csub->committed) continue;
            int32_t abs_x = s->x + sub->rel_x;
            int32_t abs_y = s->y + sub->rel_y;
            WlBuffer *cwb = find_buffer(c, csub->attached_buffer_id);
            if (!cwb) continue;
            for (int di = 0; di < csub->n_damage; di++)
                damage_add(abs_x + csub->damage[di].x,
                           abs_y + csub->damage[di].y,
                           csub->damage[di].w,
                           csub->damage[di].h);
            blit_buffer(cwb, abs_x, abs_y);
            csub->n_damage = 0;
        }
    }

    if (wb)
        wl_send(c->fd, wb->id, WL_BUFFER_EVT_RELEASE, NULL, 0);

    if (!s->enter_sent && c->output_id) {
        wl_send(c->fd, s->id, WL_SURFACE_EVT_ENTER, &c->output_id, 4);
        s->enter_sent = 1;
    }
    s->n_damage = 0;
}

static void collect_surface_damage(void) {
    for (int ci = 0; ci < g.n_clients; ci++) {
        Client *c = &g.clients[ci];
        if (!c->alive) continue;
        for (int si = 0; si < MAX_SURFACES; si++) {
            Surface *s = &c->surfaces[si];
            if (!s->id || !s->committed || s->parent_surface_id) continue;
            for (int di = 0; di < s->n_damage; di++)
                damage_add(s->x + s->damage[di].x,
                           s->y + s->damage[di].y,
                           s->damage[di].w,
                           s->damage[di].h);
            if (s->role == SURFACE_ROLE_XDG) {
                XdgToplevel *xt = find_xdg_toplevel_for_surface(c, s);
                WlBuffer *wb = find_buffer(c, s->attached_buffer_id);
                if (xt && !xt->has_csd && wb)
                    damage_add(s->x - SSD_BORDER_W,
                               s->y - SSD_TITLEBAR_H - SSD_BORDER_W,
                               wb->width + SSD_BORDER_W * 2,
                               wb->height + SSD_TITLEBAR_H + SSD_BORDER_W * 2);
            }
        }
        for (int li = 0; li < MAX_LAYER_SURFACES; li++) {
            LayerSurface *ls = &c->layer_surfaces[li];
            if (!ls->id || !ls->configured) continue;
            Surface *s = find_surface(c, ls->surface_id);
            if (s && s->committed && s->n_damage)
                damage_add(ls->x, ls->y, ls->w, ls->h);
        }
    }
}

static void clear_damage_regions(void) {
    if (g.full_damage) {
        memset(g.fb[g.back_idx].map, 0, (size_t)g.fb[g.back_idx].size);
        return;
    }
    uint8_t *base = (uint8_t *)g.fb[g.back_idx].map;
    for (int di = 0; di < g.n_screen_damage; di++) {
        const Rect *d = &g.screen_damage[di];
        for (int32_t row = 0; row < d->h; row++) {
            uint8_t *line = base
                + (uint32_t)(d->y + row) * g.screen_stride
                + (uint32_t)d->x * BPP;
            memset(line, 0, (size_t)d->w * BPP);
        }
    }
}

static void blit_layer(uint32_t layer_enum) {
    for (int ci = 0; ci < g.n_clients; ci++) {
        Client *c = &g.clients[ci];
        if (!c->alive) continue;
        for (int li = 0; li < MAX_LAYER_SURFACES; li++) {
            LayerSurface *ls = &c->layer_surfaces[li];
            if (!ls->id || ls->layer != layer_enum || !ls->configured) continue;
            Surface *s = find_surface(c, ls->surface_id);
            if (!s || !s->committed) continue;
            s->x = ls->x; s->y = ls->y;
            blit_surface_tree(c, s);
        }
    }
}

static void blit_regular_surfaces(void) {
    for (int ci = 0; ci < g.n_clients; ci++) {
        Client *c = &g.clients[ci];
        if (!c->alive) continue;
        for (int si = 0; si < MAX_SURFACES; si++) {
            Surface *s = &c->surfaces[si];
            if (!s->id || !s->committed || s->parent_surface_id) continue;
            if (s->role == SURFACE_ROLE_LAYER || s->role == SURFACE_ROLE_SUBSURFACE) continue;

            XdgToplevel *xt = find_xdg_toplevel_for_surface(c, s);
            WlBuffer *wb = find_buffer(c, s->attached_buffer_id);
            if (xt && !xt->has_csd && wb)
                ssd_draw_decorations(s->x, s->y, wb->width, wb->height,
                                     g.focused_client == ci);
            blit_surface_tree(c, s);
        }
    }
}

static void composite_and_flip(void) {
    if (!g.fb[g.back_idx].map || g.flip_pending) return;
    collect_surface_damage();
    if (g.n_screen_damage == 0 && !g.full_damage) return;
    clear_damage_regions();
    blit_layer(ZWL_LAYER_BACKGROUND);
    blit_layer(ZWL_LAYER_BOTTOM);
    blit_regular_surfaces();
    blit_layer(ZWL_LAYER_TOP);
    blit_layer(ZWL_LAYER_OVERLAY);
    drm_flip();
    damage_clear();
}
