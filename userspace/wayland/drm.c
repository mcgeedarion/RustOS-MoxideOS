#include "compositor_types.h"

/* ── DRM helpers ───────────────────────────────────────────────────────── */
static void drm_destroy_buf(DrmBuf *b) {
    if (!b) return;
    if (b->fb_id) {
        uint32_t fb_id = b->fb_id;
        (void)ioctl(g.drm_fd, DRM_IOCTL_MODE_RMFB, &fb_id);
    }
    if (b->map) munmap(b->map, (size_t)b->size);
    if (b->handle) {
        struct drm_mode_destroy_dumb dd = { .handle = b->handle };
        (void)ioctl(g.drm_fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dd);
    }
    memset(b, 0, sizeof(*b));
}

static int drm_alloc_buf(DrmBuf *b, uint32_t w, uint32_t h, uint32_t expected_stride) {
    memset(b, 0, sizeof(*b));
    struct drm_mode_create_dumb cd = { .height = h, .width = w, .bpp = 32 };
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0) return -1;
    b->handle = cd.handle;
    b->size   = cd.size;
    if (expected_stride && cd.pitch != expected_stride) {
        errno = EINVAL;
        drm_destroy_buf(b);
        return -1;
    }
    g.screen_stride = cd.pitch;

    struct drm_mode_map_dumb md = { .handle = b->handle };
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) {
        drm_destroy_buf(b);
        return -1;
    }
    b->map = mmap(NULL, (size_t)b->size, PROT_READ|PROT_WRITE,
                  MAP_SHARED, g.drm_fd, (off_t)md.offset);
    if (b->map == MAP_FAILED) {
        b->map = NULL;
        drm_destroy_buf(b);
        return -1;
    }
    memset(b->map, 0, (size_t)b->size);

    struct drm_mode_fb_cmd fc = {
        .width = w, .height = h,
        .pitch = cd.pitch, .bpp = 32, .depth = 24,
        .handle = b->handle,
    };
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_ADDFB, &fc) < 0) {
        drm_destroy_buf(b);
        return -1;
    }
    b->fb_id = fc.fb_id;
    return 0;
}

static int drm_setup(void) {
    struct drm_mode_card_res res = {0};
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) return -1;

    uint32_t conn_ids[8] = {0}, crtc_ids[8] = {0};
    res.connector_id_ptr = (uintptr_t)conn_ids;
    res.crtc_id_ptr      = (uintptr_t)crtc_ids;
    res.count_connectors = res.count_connectors < 8 ? res.count_connectors : 8;
    res.count_crtcs      = res.count_crtcs      < 8 ? res.count_crtcs      : 8;
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) return -1;
    if (res.count_connectors == 0 || res.count_crtcs == 0) return -1;

    struct drm_mode_get_connector conn = {0};
    uint32_t connector_id = 0;
    for (uint32_t i = 0; i < res.count_connectors; i++) {
        memset(&conn, 0, sizeof(conn));
        conn.connector_id = conn_ids[i];
        if (ioctl(g.drm_fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) continue;
        if (conn.connection == DRM_MODE_CONNECTED && conn.count_modes > 0) {
            connector_id = conn_ids[i];
            break;
        }
    }
    if (!connector_id) return -1;

    struct drm_mode_modeinfo modes[4] = {0};
    memset(&conn, 0, sizeof(conn));
    conn.connector_id = connector_id;
    conn.modes_ptr   = (uintptr_t)modes;
    conn.count_modes = 4;
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) return -1;
    if (conn.count_modes == 0) return -1;

    g.screen_width    = modes[0].hdisplay;
    g.screen_height   = modes[0].vdisplay;
    g.primary_crtc_id = crtc_ids[0];

    if (drm_alloc_buf(&g.fb[0], g.screen_width, g.screen_height, 0) < 0) return -1;
    if (drm_alloc_buf(&g.fb[1], g.screen_width, g.screen_height, g.screen_stride) < 0) {
        drm_destroy_buf(&g.fb[0]);
        return -1;
    }

    struct drm_mode_crtc crtc = {
        .crtc_id            = g.primary_crtc_id,
        .fb_id              = g.fb[0].fb_id,
        .set_connectors_ptr = (uintptr_t)&connector_id,
        .count_connectors   = 1,
        .mode               = modes[0],
        .mode_valid         = 1,
    };
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_SETCRTC, &crtc) < 0) {
        drm_destroy_buf(&g.fb[1]);
        drm_destroy_buf(&g.fb[0]);
        return -1;
    }
    return 0;
}

static void drm_flip(void) {
    if (g.flip_pending || !g.fb[g.back_idx].fb_id) return;
    struct drm_mode_crtc_page_flip pf = {
        .crtc_id   = g.primary_crtc_id,
        .fb_id     = g.fb[g.back_idx].fb_id,
        .flags     = DRM_MODE_PAGE_FLIP_EVENT,
        .user_data = 0,
    };
    if (ioctl(g.drm_fd, DRM_IOCTL_MODE_PAGE_FLIP, &pf) == 0)
        g.flip_pending = 1;
}

static void drm_flip_complete(void) {
    if (g.flip_pending) {
        g.back_idx ^= 1;
        g.flip_pending = 0;
    }
}

typedef struct { uint32_t type, length; } DrmEventHeader;

static void handle_drm_events(void) {
    uint8_t buf[1024];
    for (;;) {
        ssize_t n = read(g.drm_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        if (n == 0) return;
        size_t off = 0;
        while (off + sizeof(DrmEventHeader) <= (size_t)n) {
            DrmEventHeader ev;
            memcpy(&ev, buf + off, sizeof(ev));
            if (ev.length < sizeof(DrmEventHeader) || off + ev.length > (size_t)n)
                break;
            if (ev.type == DRM_EVENT_FLIP_COMPLETE)
                drm_flip_complete();
            off += ev.length;
        }
    }
}
