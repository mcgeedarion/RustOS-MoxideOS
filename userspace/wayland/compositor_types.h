#pragma once

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#if defined(__has_include)
#  if __has_include(<linux/drm.h>)
#    include <linux/drm.h>
#  elif __has_include(<drm/drm.h>)
#    include <drm/drm.h>
#  else
#    error "DRM headers are required"
#  endif
#else
#  include <linux/drm.h>
#endif

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
#define MAX_SCREEN_DAMAGE   64
#define RX_BUF_SIZE         (64 * 1024)
#define WAYLAND_SOCKET_PATH "/run/wayland-0"
#define DRM_DEVICE_PATH     "/dev/dri/card0"
#define BPP                 4

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001u
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002u
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL   0x0001u
#define F_SEAL_SHRINK 0x0002u
#define F_SEAL_GROW   0x0004u
#define F_SEAL_WRITE  0x0008u
#endif
#ifndef DRM_MODE_CONNECTED
#define DRM_MODE_CONNECTED 1u
#endif
#ifndef DRM_EVENT_FLIP_COMPLETE
#define DRM_EVENT_FLIP_COMPLETE 0x02u
#endif

#define WL_DISPLAY_ERROR_INVALID_OBJECT 0u
#define WL_DISPLAY_ERROR_INVALID_METHOD 1u
#define WL_DISPLAY_ERROR_NO_MEMORY      2u
#define WL_DISPLAY_ERROR_BAD_LENGTH     3u
#define WL_DISPLAY_ERROR_BAD_VALUE      4u

#if defined(__GNUC__)
#define MAYBE_UNUSED __attribute__((unused))
#define NORETURN     __attribute__((noreturn))
#else
#define MAYBE_UNUSED
#define NORETURN
#endif

/* SSD geometry */
#define SSD_TITLEBAR_H      24
#define SSD_BORDER_W        2
#define SSD_TITLEBAR_COLOR  0xFF404040u
#define SSD_BORDER_COLOR    0xFF606060u
#define SSD_FOCUSED_COLOR   0xFF2255AAu

/* Physical display size in mm for wl_output.geometry. */
#define OUTPUT_PHYS_W_MM    270
#define OUTPUT_PHYS_H_MM    202

#ifndef WL_KEYBOARD_EVT_REPEAT_INFO
#define WL_KEYBOARD_EVT_REPEAT_INFO 6u
#endif

/* ── Common types ──────────────────────────────────────────────────────── */
typedef struct { int32_t x, y, w, h; } Rect;

typedef struct {
    uint32_t handle;
    uint32_t fb_id;
    uint64_t size;
    void    *map;
} DrmBuf;

typedef enum {
    SURFACE_ROLE_NONE = 0,
    SURFACE_ROLE_XDG,
    SURFACE_ROLE_LAYER,
    SURFACE_ROLE_SUBSURFACE,
} SurfaceRole;

typedef struct Client_s Client;

typedef struct {
    int          epoll_fd;
    int          listen_fd;
    int          drm_fd;
    int          input_fd;

    uint32_t     screen_width;
    uint32_t     screen_height;
    uint32_t     screen_stride;
    uint32_t     primary_crtc_id;

    DrmBuf       fb[2];
    int          back_idx;
    int          flip_pending;

    Rect         screen_damage[MAX_SCREEN_DAMAGE];
    int          n_screen_damage;
    int          full_damage;

    Client      *clients;
    int          n_clients;
    int          focused_client;

    uint32_t     serial_counter;
} CompositorState;

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
    uint32_t    id;
    uint32_t    attached_buffer_id;
    int32_t     x, y;
    int32_t     blit_w, blit_h;
    Rect        damage[MAX_DAMAGE_RECTS];
    int         n_damage;
    uint32_t    frame_cb_id;
    int         committed;
    int         enter_sent;
    int         has_prev;
    int32_t     prev_x, prev_y, prev_w, prev_h;
    uint32_t    parent_surface_id;
    SurfaceRole role;
} Surface;

typedef struct {
    uint32_t id;
    uint32_t surface_id;
    uint32_t parent_id;
    int32_t  rel_x, rel_y;
    int      sync;
    int      above;
} Subsurface;

typedef struct {
    uint32_t id;
    uint32_t surface_id;
    uint32_t layer;
    uint32_t anchor;
    int32_t  exclusive_zone;
    int32_t  margin_top, margin_right, margin_bottom, margin_left;
    int32_t  req_width, req_height;
    int32_t  x, y, w, h;
    int32_t  prev_x, prev_y, prev_w, prev_h;
    int      has_prev;
    uint32_t pending_serial;
    int      configured;
} LayerSurface;

typedef struct {
    uint32_t id;
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
    int      has_csd;
} XdgToplevel;

struct Client_s {
    int       fd;
    int       alive;

    uint8_t   rx[RX_BUF_SIZE];
    size_t    rx_len;

    int       pending_fds[8];
    int       n_pending_fds;

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
};

extern Client clients_storage[MAX_CLIENTS];
extern CompositorState g;
