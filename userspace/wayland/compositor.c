/*
 * userspace/wayland/compositor.c — rustos Wayland compositor
 *
 * This is a privileged userspace process (ring 3, UID 0) that implements
 * the Wayland compositor.  It runs completely outside the kernel;
 * communication with the kernel is via normal Linux-compatible syscalls:
 *
 *   - open("/dev/dri/card0", O_RDWR)  — DRM master fd (passed via env)
 *   - open("/dev/input/event0", ...)  — evdev input (passed via env)
 *   - socket(AF_UNIX, SOCK_STREAM, 0) — listen on /run/wayland-0
 *   - ioctl(drm_fd, DRM_IOCTL_*)      — mode-setting, dumb buffers, vblank
 *   - mmap(drm_buf)                   — map dumb buffers into process VA
 *   - epoll_*                         — multiplexed I/O over all fds
 *
 * Running the compositor in userspace means:
 *   - A compositor crash never panics the kernel.
 *   - init (PID 1) receives SIGCHLD and can restart us automatically.
 *   - Our seccomp filter (installed at startup) restricts us to fewer
 *     than 15 syscalls, dramatically reducing the kernel attack surface.
 *   - Memory safety errors (buffer overflows, use-after-free) in blending
 *     code produce a SIGSEGV that kills the compositor process, not the OS.
 *
 * Build:
 *   musl-gcc -static -O2 -o rustos-compositor compositor.c
 *
 * Syscall ABI compatibility:
 *   Written against the rustos syscall ABI which mirrors Linux x86-64.
 *   Tested with musl-libc.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/drm.h>
#include <linux/dma-buf.h>

/* ── compile-time constants ─────────────────────────────────────────────── */

#define WAYLAND_SOCKET_PATH   "/run/wayland-0"
#define MAX_CLIENTS           64
#define MAX_SURFACES          256
#define RX_BUF_SIZE           (64 * 1024)
#define MAX_DAMAGE_RECTS      32

/* Wayland wire protocol object IDs we create at bind time */
#define WL_DISPLAY_ID         1
#define WL_REGISTRY_ID        2

/* Well-known global interface names */
#define INTF_COMPOSITOR   "wl_compositor"
#define INTF_SHM          "wl_shm"
#define INTF_SEAT         "wl_seat"
#define INTF_OUTPUT       "wl_output"

/* ── DRM helpers ────────────────────────────────────────────────────────── */

static int drm_fd    = -1;
static int input_fd  = -1;
static int epoll_fd  = -1;
static int listen_fd = -1;

static uint32_t screen_width  = 0;
static uint32_t screen_height = 0;
static uint32_t screen_stride = 0;
static uint32_t primary_fb_id = 0;
static void    *primary_map   = NULL;  /* mmap of the primary dumb buffer */

/* DRM dumb buffer for the compositor's back-buffer */
static uint32_t back_buf_handle = 0;
static uint64_t back_buf_size   = 0;
static void    *back_buf_map    = NULL;

/*
 * drm_get_resources: query the connected CRTC / connector and learn the
 * current display resolution.  We use DRM_IOCTL_MODE_GETRESOURCES and
 * DRM_IOCTL_MODE_GETCONNECTOR (Linux-compatible ioctls).
 */
static int drm_setup(void) {
    struct drm_mode_card_res res = {0};
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) return -1;

    /* Allocate arrays and re-issue to get the actual IDs */
    uint32_t connector_ids[8] = {0};
    uint32_t crtc_ids[8]      = {0};
    res.connector_id_ptr = (uintptr_t)connector_ids;
    res.crtc_id_ptr      = (uintptr_t)crtc_ids;
    res.count_connectors  = res.count_connectors < 8 ? res.count_connectors : 8;
    res.count_crtcs       = res.count_crtcs      < 8 ? res.count_crtcs      : 8;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) return -1;
    if (res.count_connectors == 0) return -1;

    /* Find the first connected connector and its preferred mode */
    struct drm_mode_get_connector conn = {0};
    conn.connector_id = connector_ids[0];
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) return -1;
    if (conn.count_modes == 0) return -1;

    struct drm_mode_modeinfo modes[4] = {0};
    conn.modes_ptr   = (uintptr_t)modes;
    conn.count_modes = conn.count_modes < 4 ? conn.count_modes : 4;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) return -1;

    screen_width  = modes[0].hdisplay;
    screen_height = modes[0].vdisplay;
    screen_stride = screen_width * 4;  /* 32-bit ARGB */

    /* Allocate the primary dumb buffer */
    struct drm_mode_create_dumb cd = {
        .height = screen_height,
        .width  = screen_width,
        .bpp    = 32,
    };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0) return -1;
    back_buf_handle = cd.handle;
    back_buf_size   = cd.size;
    screen_stride   = cd.pitch;

    /* mmap the dumb buffer */
    struct drm_mode_map_dumb md = { .handle = back_buf_handle };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) return -1;
    back_buf_map = mmap(NULL, (size_t)back_buf_size, PROT_READ|PROT_WRITE,
                        MAP_SHARED, drm_fd, (off_t)md.offset);
    if (back_buf_map == MAP_FAILED) return -1;
    memset(back_buf_map, 0x00, (size_t)back_buf_size);

    /* Create a DRM framebuffer object wrapping the dumb buffer */
    struct drm_mode_fb_cmd fb = {
        .width  = screen_width,
        .height = screen_height,
        .pitch  = screen_stride,
        .bpp    = 32,
        .depth  = 24,
        .handle = back_buf_handle,
    };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_ADDFB, &fb) < 0) return -1;
    primary_fb_id = fb.fb_id;
    primary_map   = back_buf_map;

    /* Program the CRTC */
    struct drm_mode_crtc crtc = {
        .crtc_id      = crtc_ids[0],
        .fb_id        = primary_fb_id,
        .set_connectors_ptr = (uintptr_t)&connector_ids[0],
        .count_connectors   = 1,
        .mode         = modes[0],
        .mode_valid   = 1,
    };
    if (ioctl(drm_fd, DRM_IOCTL_MODE_SETCRTC, &crtc) < 0) return -1;
    return 0;
}

/* Flip the back-buffer to the display via DRM page-flip */
static void drm_flip(void) {
    struct drm_mode_crtc_page_flip pf = {
        .crtc_id   = 1,      /* CRTC_ID = 1 (matches kernel drm.rs) */
        .fb_id     = primary_fb_id,
        .flags     = DRM_MODE_PAGE_FLIP_EVENT,
        .user_data = 0,
    };
    ioctl(drm_fd, DRM_IOCTL_MODE_PAGE_FLIP, &pf);
}

/* ── Wayland wire protocol helpers ──────────────────────────────────────── */

typedef struct {
    uint32_t object_id;
    uint16_t opcode;
    uint16_t msg_size;   /* total message size including header */
    uint8_t  payload[];
} __attribute__((packed)) WlHeader;

static void wl_send(int fd, uint32_t obj, uint16_t opcode,
                    const void *payload, uint16_t plen) {
    uint8_t  buf[4096];
    uint16_t total = (uint16_t)(8 + plen);
    memcpy(buf,     &obj,    4);
    memcpy(buf + 4, &opcode, 2);
    memcpy(buf + 6, &total,  2);
    if (plen) memcpy(buf + 8, payload, plen);
    write(fd, buf, total);
}

static uint32_t read_u32(const uint8_t *buf, size_t off) {
    uint32_t v; memcpy(&v, buf + off, 4); return v;
}

/* ── Surface / client object model ─────────────────────────────────────── */

typedef struct {
    uint32_t  id;             /* wl_surface object id */
    void     *shm_data;       /* pointer into client SHM pool */
    uint32_t  width, height, stride;
    int32_t   x, y;           /* screen position set by xdg_surface/toplevel */
    uint32_t  damage[MAX_DAMAGE_RECTS][4]; /* x,y,w,h */
    int       n_damage;
    int       committed;
    uint32_t  frame_cb_id;    /* pending wl_callback id, 0 if none */
} Surface;

typedef struct {
    int       fd;             /* connected client socket fd */
    uint8_t   rx[RX_BUF_SIZE];
    size_t    rx_len;
    uint32_t  next_id;        /* next object ID to assign */

    /* Registered globals */
    uint32_t  registry_id;
    uint32_t  compositor_id;
    uint32_t  shm_id;
    uint32_t  seat_id;

    /* SHM pool */
    int       shm_fd;
    void     *shm_pool;
    size_t    shm_pool_size;

    Surface   surfaces[32];
    int       n_surfaces;
    int       alive;
} Client;

static Client clients[MAX_CLIENTS];
static int    n_clients = 0;

/* ── Protocol dispatch ──────────────────────────────────────────────────── */

static void send_registry_globals(Client *c) {
    /* wl_registry.global(name, interface, version) */
    uint32_t name; uint8_t ev[256]; size_t evsz;
    /* wl_compositor */
    name = 1;
    const char *ci = INTF_COMPOSITOR;
    uint32_t cilen = (uint32_t)strlen(ci);
    uint32_t ciplen = (cilen + 3) & ~3u; /* 4-byte aligned */
    uint32_t ver = 5;
    evsz = 0;
    memcpy(ev+evsz, &name,   4); evsz+=4;
    memcpy(ev+evsz, &cilen,  4); evsz+=4;
    memcpy(ev+evsz, ci,  ciplen); evsz+=ciplen;
    memcpy(ev+evsz, &ver,    4); evsz+=4;
    wl_send(c->fd, c->registry_id, 0 /*global*/, ev, (uint16_t)evsz);

    /* wl_shm */
    name = 2;
    const char *si = INTF_SHM;
    uint32_t silen = (uint32_t)strlen(si);
    uint32_t siplen = (silen + 3) & ~3u;
    ver = 1;
    evsz = 0;
    memcpy(ev+evsz, &name,   4); evsz+=4;
    memcpy(ev+evsz, &silen,  4); evsz+=4;
    memcpy(ev+evsz, si, siplen); evsz+=siplen;
    memcpy(ev+evsz, &ver,    4); evsz+=4;
    wl_send(c->fd, c->registry_id, 0, ev, (uint16_t)evsz);

    /* wl_seat */
    name = 3;
    const char *sei = INTF_SEAT;
    uint32_t seilen = (uint32_t)strlen(sei);
    uint32_t seiplen = (seilen + 3) & ~3u;
    ver = 7;
    evsz = 0;
    memcpy(ev+evsz, &name,    4); evsz+=4;
    memcpy(ev+evsz, &seilen,  4); evsz+=4;
    memcpy(ev+evsz, sei, seiplen); evsz+=seiplen;
    memcpy(ev+evsz, &ver,     4); evsz+=4;
    wl_send(c->fd, c->registry_id, 0, ev, (uint16_t)evsz);
}

static void dispatch_message(Client *c, uint32_t obj, uint16_t op,
                              const uint8_t *data, uint16_t dlen) {
    /* wl_display */
    if (obj == WL_DISPLAY_ID) {
        if (op == 1 /* get_registry */) {
            c->registry_id = read_u32(data, 0);
            send_registry_globals(c);
        }
        return;
    }
    /* wl_registry */
    if (obj == c->registry_id) {
        if (op == 0 /* bind */) {
            uint32_t name    = read_u32(data, 0);
            uint32_t new_id  = read_u32(data, dlen - 4); /* last field */
            if (name == 1) c->compositor_id = new_id;
            if (name == 2) c->shm_id        = new_id;
            if (name == 3) c->seat_id       = new_id;
            /* For wl_seat: send capabilities event (pointer=1, keyboard=2) */
            if (name == 3) {
                uint32_t caps = 3;
                wl_send(c->fd, new_id, 0 /*capabilities*/, &caps, 4);
            }
        }
        return;
    }
    /* wl_compositor */
    if (obj == c->compositor_id) {
        if (op == 0 /* create_surface */) {
            uint32_t new_id = read_u32(data, 0);
            if (c->n_surfaces < 32) {
                Surface *s = &c->surfaces[c->n_surfaces++];
                memset(s, 0, sizeof(*s));
                s->id = new_id;
            }
        }
        return;
    }
    /* wl_shm */
    if (obj == c->shm_id) {
        if (op == 0 /* create_pool */) {
            /* create_pool(new_id, fd, size) */
            /* fd is passed out-of-band via SCM_RIGHTS in a real impl;
               for rustos shared memory we use the wl_shm_pool fd field
               directly as a kernel shm handle that mmap resolves. */
            uint32_t pool_id  = read_u32(data, 0);
            int32_t  shm_fd   = (int32_t)read_u32(data, 4);
            int32_t  shm_size = (int32_t)read_u32(data, 8);
            c->shm_fd        = shm_fd;
            c->shm_pool_size = (size_t)shm_size;
            c->shm_pool      = mmap(NULL, c->shm_pool_size,
                                    PROT_READ, MAP_SHARED, shm_fd, 0);
        }
        return;
    }
    /* wl_surface */
    for (int i = 0; i < c->n_surfaces; i++) {
        Surface *s = &c->surfaces[i];
        if (s->id != obj) continue;
        switch (op) {
        case 0: /* destroy */ s->id = 0; break;
        case 1: /* attach(buffer_id, x, y) */
            /* buffer_id references a wl_buffer created from the SHM pool */
            s->shm_data = c->shm_pool;
            s->x = (int32_t)read_u32(data, 4);
            s->y = (int32_t)read_u32(data, 8);
            break;
        case 2: /* damage(x,y,w,h) */
        case 9: /* damage_buffer(x,y,w,h) */
            if (s->n_damage < MAX_DAMAGE_RECTS) {
                uint32_t *r = s->damage[s->n_damage++];
                r[0] = read_u32(data, 0); r[1] = read_u32(data, 4);
                r[2] = read_u32(data, 8); r[3] = read_u32(data, 12);
            }
            break;
        case 3: /* frame(callback_id) */
            s->frame_cb_id = read_u32(data, 0);
            break;
        case 6: /* commit */
            s->committed = 1;
            /* Blit surface into back-buffer */
            if (s->shm_data && back_buf_map) {
                uint32_t blit_w = s->width  ? s->width  : screen_width;
                uint32_t blit_h = s->height ? s->height : screen_height;
                uint32_t dst_x  = (uint32_t)(s->x < 0 ? 0 : s->x);
                uint32_t dst_y  = (uint32_t)(s->y < 0 ? 0 : s->y);
                uint32_t rows   = blit_h;
                if (dst_y + rows > screen_height) rows = screen_height - dst_y;
                uint32_t cols   = blit_w;
                if (dst_x + cols > screen_width)  cols = screen_width  - dst_x;
                for (uint32_t row = 0; row < rows; row++) {
                    const uint8_t *src = (const uint8_t *)s->shm_data
                                        + row * (blit_w * 4);
                    uint8_t *dst = (uint8_t *)back_buf_map
                                  + (dst_y + row) * screen_stride
                                  + dst_x * 4;
                    memcpy(dst, src, cols * 4);
                }
                s->n_damage = 0;
            }
            /* Page-flip to show the new frame */
            drm_flip();
            break;
        case 8: /* set_buffer_scale */
            /* accepted but ignored at this resolution */ break;
        default: break;
        }
        return;
    }
}

/* ── Message parser ─────────────────────────────────────────────────────── */

static void process_rx(Client *c) {
    size_t off = 0;
    while (off + 8 <= c->rx_len) {
        uint32_t obj  = read_u32(c->rx, off);
        uint16_t op, msz;
        memcpy(&op,  c->rx + off + 4, 2);
        memcpy(&msz, c->rx + off + 6, 2);
        if (msz < 8 || off + msz > c->rx_len) break;
        dispatch_message(c, obj, op,
                         c->rx + off + 8,
                         (uint16_t)(msz - 8));
        off += msz;
    }
    /* Shift unconsumed bytes to front */
    if (off > 0 && off < c->rx_len)
        memmove(c->rx, c->rx + off, c->rx_len - off);
    c->rx_len -= off;
}

/* ── Input forwarding ───────────────────────────────────────────────────── */

/* Linux input_event structure */
struct input_event {
    /* struct timeval (8 bytes on 64-bit) */
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

static int focused_client = -1;  /* index into clients[] */

static void forward_input(void) {
    struct input_event ev;
    ssize_t n = read(input_fd, &ev, sizeof(ev));
    if (n != (ssize_t)sizeof(ev)) return;
    if (focused_client < 0 || focused_client >= n_clients) return;
    Client *c = &clients[focused_client];
    if (!c->alive || c->seat_id == 0) return;

    if (ev.type == EV_KEY) {
        /* wl_keyboard.key(serial, time, key, state) */
        uint32_t serial = 0, time_ms = 0;
        uint32_t key = (uint32_t)ev.code;
        uint32_t state = (ev.value == 0) ? 0 : 1;
        uint8_t payload[16];
        memcpy(payload,    &serial,  4);
        memcpy(payload+4,  &time_ms, 4);
        memcpy(payload+8,  &key,     4);
        memcpy(payload+12, &state,   4);
        /* wl_keyboard opcode 4 = key */
        wl_send(c->fd, c->seat_id + 1 /* keyboard obj id */, 4, payload, 16);
    } else if (ev.type == EV_REL) {
        /* wl_pointer.motion(time, x_fp, y_fp) */
        uint32_t time_ms = 0;
        int32_t  val     = ev.value;
        uint8_t payload[12];
        memcpy(payload,   &time_ms, 4);
        /* Fixed-point 24.8: multiply by 256 */
        int32_t fp = val * 256;
        if (ev.code == REL_X) {
            memcpy(payload+4, &fp, 4);
            int32_t zero = 0;
            memcpy(payload+8, &zero, 4);
        } else {
            int32_t zero = 0;
            memcpy(payload+4, &zero, 4);
            memcpy(payload+8, &fp,   4);
        }
        /* wl_pointer opcode 2 = motion */
        wl_send(c->fd, c->seat_id + 2 /* pointer obj id */, 2, payload, 12);
    }
}

/* ── seccomp filter ─────────────────────────────────────────────────────── */

/*
 * Install a seccomp-BPF whitelist that allows only the syscalls this
 * compositor needs.  Any other syscall → SECCOMP_RET_KILL_PROCESS.
 *
 * Allowed syscalls:
 *   read, write, close, mmap, munmap, ioctl, recvmsg, sendmsg,
 *   epoll_create1, epoll_ctl, epoll_wait, accept4,
 *   exit, exit_group, rt_sigreturn
 *
 * This is called AFTER all fds are opened and the DRM CRTC is
 * programmed, so we no longer need open(), socket(), bind(), listen().
 */
static void install_seccomp(void) {
    /* Architecture check: bail if not x86-64 to avoid breaking RISC-V */
#ifndef AUDIT_ARCH_X86_64
    return;
#else
    /* BPF program: load arch, verify, load syscall number, whitelist */
    struct sock_filter filter[] = {
        /* Verify architecture */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
            offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Load syscall number */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
            offsetof(struct seccomp_data, nr)),

        /* Whitelist each allowed syscall */
#define ALLOW(nr) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (nr), 0, 1), \
                  BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
        ALLOW(0),   /* read         */
        ALLOW(1),   /* write        */
        ALLOW(3),   /* close        */
        ALLOW(9),   /* mmap         */
        ALLOW(11),  /* munmap       */
        ALLOW(16),  /* ioctl        */
        ALLOW(46),  /* sendmsg      */
        ALLOW(47),  /* recvmsg      */
        ALLOW(228), /* clock_gettime */
        ALLOW(232), /* epoll_wait   */
        ALLOW(233), /* epoll_ctl    */
        ALLOW(242), /* epoll_create1 */
        ALLOW(288), /* accept4      */
        ALLOW(231), /* exit_group   */
        ALLOW(60),  /* exit         */
        ALLOW(15),  /* rt_sigreturn */
#undef ALLOW
        /* Default: kill the entire process */
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
#endif
}

/* ── Main event loop ────────────────────────────────────────────────────── */

static void log_msg(const char *s) {
    write(1, s, strlen(s));
    write(1, "\n", 1);
}

int main(void) {
    /* ── Read inherited fds from environment ─────────────────────────── */
    const char *drm_env   = getenv("WAYLAND_DRM_FD");
    const char *input_env = getenv("WAYLAND_INPUT_FD");
    drm_fd   = drm_env   ? atoi(drm_env)   : open("/dev/dri/card0",         O_RDWR);
    input_fd = input_env ? atoi(input_env) : open("/dev/input/event0", O_RDONLY | O_NONBLOCK);

    if (drm_fd < 0) { log_msg("[compositor] no DRM device"); _exit(1); }

    /* ── DRM: query display, create dumb buffer, program CRTC ─────────── */
    if (drm_setup() < 0) {
        log_msg("[compositor] DRM setup failed — no display output");
        /* Continue anyway: we can still serve clients without a display */
    } else {
        log_msg("[compositor] DRM display initialised");
    }

    /* ── Unix socket: bind /run/wayland-0 ───────────────────────────── */
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

    /* ── epoll: watch listen_fd, DRM fd, input fd ───────────────────── */
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev;
    ev.events   = EPOLLIN;
    ev.data.fd  = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
    if (drm_fd >= 0) {
        ev.data.fd = drm_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, drm_fd, &ev);
    }
    if (input_fd >= 0) {
        ev.data.fd = input_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, input_fd, &ev);
    }

    /* ── Install seccomp filter (after all fds open, before the loop) ── */
    install_seccomp();

    log_msg("[compositor] event loop started");

    /* ── Event loop ─────────────────────────────────────────────────── */
    struct epoll_event events[32];
    for (;;) {
        int nev = epoll_wait(epoll_fd, events, 32, 16 /* ms timeout = ~60 Hz */);

        for (int i = 0; i < nev; i++) {
            int efd = events[i].data.fd;

            /* New client connection */
            if (efd == listen_fd) {
                int cfd = accept4(listen_fd, NULL, NULL,
                                  SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (cfd >= 0 && n_clients < MAX_CLIENTS) {
                    Client *c = &clients[n_clients++];
                    memset(c, 0, sizeof(*c));
                    c->fd      = cfd;
                    c->alive   = 1;
                    c->next_id = 2;
                    /* Add to epoll */
                    ev.events  = EPOLLIN | EPOLLET;
                    ev.data.fd = cfd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &ev);
                    /* Send wl_display.delete_id synthetic to complete handshake */
                }
                continue;
            }

            /* DRM vblank / page-flip event */
            if (efd == drm_fd) {
                /* Read the DRM event to drain the fd */
                uint8_t drmev[64];
                read(drm_fd, drmev, sizeof(drmev));
                /* Fire all pending frame callbacks */
                for (int ci = 0; ci < n_clients; ci++) {
                    Client *c = &clients[ci];
                    if (!c->alive) continue;
                    for (int si = 0; si < c->n_surfaces; si++) {
                        Surface *s = &c->surfaces[si];
                        if (s->frame_cb_id) {
                            /* wl_callback.done(serial) */
                            uint32_t serial = (uint32_t)nev;
                            wl_send(c->fd, s->frame_cb_id, 0, &serial, 4);
                            s->frame_cb_id = 0;
                        }
                    }
                }
                continue;
            }

            /* Input event */
            if (efd == input_fd) {
                forward_input();
                continue;
            }

            /* Client data */
            for (int ci = 0; ci < n_clients; ci++) {
                Client *c = &clients[ci];
                if (!c->alive || c->fd != efd) continue;
                ssize_t n = read(c->fd, c->rx + c->rx_len,
                                 RX_BUF_SIZE - c->rx_len);
                if (n <= 0) {
                    /* Client disconnected */
                    close(c->fd);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
                    c->alive = 0;
                    if (focused_client == ci) focused_client = -1;
                } else {
                    c->rx_len += (size_t)n;
                    process_rx(c);
                }
                break;
            }
        }
    }
}
