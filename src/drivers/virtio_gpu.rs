//! virtio-gpu PCI driver.
//!
//! ## Device
//!   PCI vendor 0x1AF4, device 0x1050 (virtio-gpu-pci).
//!
//! ## Virtqueues
//!   Queue 0 = controlq  — host → guest commands and responses.
//!   Queue 1 = cursorq   — cursor update / move commands (fire-and-forget).
//!
//! ## Resource model (virtio-gpu v1 spec §5.7)
//!   1. CREATE_2D_RESOURCE  — allocates a host-side pixel buffer.
//!   2. RESOURCE_ATTACH_BACKING — maps guest physical pages into that resource.
//!   3. SET_SCANOUT          — binds resource to a display output.
//!   4. TRANSFER_TO_HOST_2D  — copies the guest backing pages into the resource.
//!   5. RESOURCE_FLUSH       — presents resource rect to the physical display.
//!
//! ## Public surface (called by gpu.rs / framebuffer.rs)
//!   is_present()              — true after successful init
//!   num_scanouts()            — number of display outputs
//!   scanout_info(idx)         — (width, height, fb_phys) for output idx
//!   dimensions()              — (width, height) of scanout 0
//!   fb_phys()                 — physical FB address of scanout 0
//!   flush(x,y,w,h)            — TRANSFER + FLUSH on scanout 0
//!   flush_all()               — full-surface flush on all scanouts
//!   flush_scanout(idx)        — full-surface flush on scanout idx
//!   cursor_update_scanout(idx, pixels, x, y)
//!   cursor_move_scanout(idx, x, y, visible)

extern crate alloc;

use core::sync::atomic::{fence, AtomicBool, Ordering};
use spin::Mutex;
use crate::drivers::pcie::{enumerate, cam_read32, cam_write32};
use crate::mm::pmm;

// ── PCI ids ───────────────────────────────────────────────────────────────────

const VIRTIO_VENDOR:   u16 = 0x1AF4;
const VIRTIO_DEV_GPU:  u16 = 0x1050;

// ── Virtio MMIO register offsets (legacy BAR0 I/O for transitional device) ────
// For virtio-gpu QEMU exposes a modern PCIe device with capability structures,
// but the simplest path is to use the legacy I/O BAR which QEMU still provides.

const REG_DEVICE_FEATURES:  u16 = 0x00;
const REG_GUEST_FEATURES:   u16 = 0x04;
const REG_QUEUE_ADDR:       u16 = 0x08;
const REG_QUEUE_SIZE:       u16 = 0x0C;
const REG_QUEUE_SELECT:     u16 = 0x0E;
const REG_QUEUE_NOTIFY:     u16 = 0x10;
const REG_DEVICE_STATUS:    u16 = 0x12;
const REG_ISR_STATUS:       u16 = 0x13;

// ── Device status bits ────────────────────────────────────────────────────────

const S_ACK:         u8 = 0x01;
const S_DRIVER:      u8 = 0x02;
const S_DRIVER_OK:   u8 = 0x04;
const S_FEATURES_OK: u8 = 0x08;
const S_FAILED:      u8 = 0x80;

// ── virtio-gpu feature bits ───────────────────────────────────────────────────

const VIRTIO_GPU_F_VIRGL:    u32 = 1 << 0; // 3D (we don't enable this)
const VIRTIO_GPU_F_EDID:     u32 = 1 << 1; // EDID support (optional)

// ── virtio-gpu command types ──────────────────────────────────────────────────

const CMD_GET_DISPLAY_INFO:       u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D:     u32 = 0x0101;
const CMD_RESOURCE_UNREF:         u32 = 0x0102;
const CMD_SET_SCANOUT:            u32 = 0x0103;
const CMD_RESOURCE_FLUSH:         u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D:    u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING:u32 = 0x0106;
const CMD_RESOURCE_DETACH_BACKING:u32 = 0x0107;
const CMD_UPDATE_CURSOR:          u32 = 0x0300;
const CMD_MOVE_CURSOR:            u32 = 0x0301;

const RESP_OK_NODATA:             u32 = 0x1100;
const RESP_OK_DISPLAY_INFO:       u32 = 0x1101;

// ── virtio-gpu pixel format ───────────────────────────────────────────────────

const VIRTIO_GPU_FORMAT_B8G8R8X8: u32 = 2; // BGRX, matches our Framebuffer pixel format

// ── Virtqueue geometry ────────────────────────────────────────────────────────

const CTRL_QUEUE_SIZE:   usize = 16;
const CURSOR_QUEUE_SIZE: usize = 16;

const VRING_DESC_F_NEXT:  u16 = 0x1;
const VRING_DESC_F_WRITE: u16 = 0x2;

// ── Maximum scanouts (virtio-gpu spec: up to 16) ──────────────────────────────

const MAX_SCANOUTS: usize = 4; // we support up to 4 displays

// ── Wire structures (little-endian, packed where required) ────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuCtrlHdr {
    typ:      u32,
    flags:    u32,
    fence_id: u64,
    ctx_id:   u32,
    padding:  u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuRect {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

// VIRTIO_GPU_CMD_GET_DISPLAY_INFO response
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuDisplayInfo {
    hdr:    VirtioGpuCtrlHdr,
    pmodes: [VirtioGpuDisplayOne; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuDisplayOne {
    r:       VirtioGpuRect,
    enabled: u32,
    flags:   u32,
}

// VIRTIO_GPU_CMD_RESOURCE_CREATE_2D
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuResourceCreate2d {
    hdr:         VirtioGpuCtrlHdr,
    resource_id: u32,
    format:      u32,
    width:        u32,
    height:       u32,
}

// VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuResourceAttachBacking {
    hdr:         VirtioGpuCtrlHdr,
    resource_id: u32,
    nr_entries:  u32,
    // Followed by `nr_entries` VirtioGpuMemEntry; we inline one.
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuMemEntry {
    addr:    u64,
    length:  u32,
    padding: u32,
}

// VIRTIO_GPU_CMD_SET_SCANOUT
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuSetScanout {
    hdr:         VirtioGpuCtrlHdr,
    r:           VirtioGpuRect,
    scanout_id:  u32,
    resource_id: u32,
}

// VIRTIO_GPU_CMD_RESOURCE_FLUSH
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuResourceFlush {
    hdr:         VirtioGpuCtrlHdr,
    r:           VirtioGpuRect,
    resource_id: u32,
    padding:     u32,
}

// VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuTransferToHost2d {
    hdr:         VirtioGpuCtrlHdr,
    r:           VirtioGpuRect,
    offset:      u64,
    resource_id: u32,
    padding:     u32,
}

// Cursor commands (UPDATE_CURSOR and MOVE_CURSOR share the same struct)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuUpdateCursor {
    hdr:         VirtioGpuCtrlHdr,
    pos:         VirtioGpuCursorPos,
    resource_id: u32,
    hot_x:       u32,
    hot_y:       u32,
    padding:     u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioGpuCursorPos {
    scanout_id: u32,
    x:          u32,
    y:          u32,
    padding:    u32,
}

// ── Split-ring virtqueue ──────────────────────────────────────────────────────

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C, align(2))]
struct VirtqAvail {
    flags:      u16,
    idx:        u16,
    ring:       [u16; CTRL_QUEUE_SIZE],
    used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem { id: u32, len: u32 }

#[repr(C, align(4))]
struct VirtqUsed {
    flags:       u16,
    idx:         u16,
    ring:        [UsedElem; CTRL_QUEUE_SIZE],
    avail_event: u16,
}

// ── Static command/response scratch buffers ────────────────────────────────────

// We issue one command at a time (serialised by CTRL_LOCK) so a single
// set of scratch buffers is enough.

const CMD_BUF_SIZE: usize = 256; // largest command struct < 256 bytes
const RSP_BUF_SIZE: usize = 256;

#[repr(C, align(4096))]
struct CtrlQueue {
    desc:  [VirtqDesc; CTRL_QUEUE_SIZE],
    avail: VirtqAvail,
    _pad:  [u8; 4096 - core::mem::size_of::<VirtqAvail>() % 4096],
    used:  VirtqUsed,
    cmd:   [u8; CMD_BUF_SIZE],
    rsp:   [u8; RSP_BUF_SIZE],
}

#[repr(C, align(4096))]
struct CursorQueue {
    desc:  [VirtqDesc; CURSOR_QUEUE_SIZE],
    avail: VirtqAvail,
    _pad:  [u8; 4096 - core::mem::size_of::<VirtqAvail>() % 4096],
    used:  VirtqUsed,
    cmd:   [u8; CMD_BUF_SIZE],
}

static mut CTRLQ:   CtrlQueue   = unsafe { core::mem::zeroed() };
static mut CURSORQ: CursorQueue = unsafe { core::mem::zeroed() };

// ── Cursor bitmap resource ────────────────────────────────────────────────────

const CURSOR_W: u32 = 64;
const CURSOR_H: u32 = 64;
const CURSOR_RES_ID: u32 = 0xCCC; // arbitrary static resource id

#[repr(C, align(4096))]
struct CursorBuf([u32; (CURSOR_W * CURSOR_H) as usize]);
static mut CURSOR_FB: CursorBuf = CursorBuf([0; (CURSOR_W * CURSOR_H) as usize]);

// ── Per-scanout state ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct ScanoutState {
    width:       u32,
    height:      u32,
    resource_id: u32,  // virtio resource handle (1-based per scanout)
    fb_phys:     u64,  // physical address of the backing pixel buffer
    enabled:     bool,
}

// ── Driver state ──────────────────────────────────────────────────────────────

struct GpuState {
    io_base:   u16,
    scanouts:  [ScanoutState; MAX_SCANOUTS],
    n_scanouts: usize,
    ctrl_avail_idx: u16,
    ctrl_last_used: u16,
    cursor_avail_idx: u16,
}

static CTRL_LOCK: Mutex<Option<GpuState>> = Mutex::new(None);
static PRESENT:   AtomicBool = AtomicBool::new(false);

// ── I/O port helpers ──────────────────────────────────────────────────────────

#[inline(always)] unsafe fn inb(p: u16) -> u8  {
    let v: u8;  core::arch::asm!("in al, dx",  out("al")  v, in("dx") p, options(nomem,nostack)); v
}
#[inline(always)] unsafe fn inw(p: u16) -> u16 {
    let v: u16; core::arch::asm!("in ax, dx",  out("ax")  v, in("dx") p, options(nomem,nostack)); v
}
#[inline(always)] unsafe fn inl(p: u16) -> u32 {
    let v: u32; core::arch::asm!("in eax, dx", out("eax") v, in("dx") p, options(nomem,nostack)); v
}
#[inline(always)] unsafe fn outb(p: u16, v: u8)  {
    core::arch::asm!("out dx, al",  in("dx") p, in("al")  v, options(nomem,nostack));
}
#[inline(always)] unsafe fn outw(p: u16, v: u16) {
    core::arch::asm!("out dx, ax",  in("dx") p, in("ax")  v, options(nomem,nostack));
}
#[inline(always)] unsafe fn outl(p: u16, v: u32) {
    core::arch::asm!("out dx, eax", in("dx") p, in("eax") v, options(nomem,nostack));
}

// ── Virtqueue setup ───────────────────────────────────────────────────────────

unsafe fn setup_queue(io: u16, queue_idx: u16, desc_pa: u64) {
    outw(io + REG_QUEUE_SELECT, queue_idx);
    outl(io + REG_QUEUE_ADDR,   (desc_pa >> 12) as u32);
}

// ── Command submission ────────────────────────────────────────────────────────

/// Send one command (from CTRLQ.cmd, len `cmd_len`) and collect a response
/// (into CTRLQ.rsp, up to `rsp_len` bytes).  Spins until used ring advances.
unsafe fn send_ctrl_cmd(st: &mut GpuState, cmd_len: usize, rsp_len: usize) {
    let q = &mut CTRLQ;

    let cmd_desc = 0usize;
    let rsp_desc = 1usize;

    // Desc 0: command (device-readable)
    q.desc[cmd_desc] = VirtqDesc {
        addr:  q.cmd.as_ptr() as u64,
        len:   cmd_len as u32,
        flags: VRING_DESC_F_NEXT,
        next:  rsp_desc as u16,
    };
    // Desc 1: response (device-writable)
    q.desc[rsp_desc] = VirtqDesc {
        addr:  q.rsp.as_ptr() as u64,
        len:   rsp_len as u32,
        flags: VRING_DESC_F_WRITE,
        next:  0,
    };

    let avail_slot = st.ctrl_avail_idx as usize % CTRL_QUEUE_SIZE;
    q.avail.ring[avail_slot] = cmd_desc as u16;
    fence(Ordering::SeqCst);
    q.avail.idx = q.avail.idx.wrapping_add(1);
    st.ctrl_avail_idx = st.ctrl_avail_idx.wrapping_add(1);
    fence(Ordering::SeqCst);

    // Kick controlq (queue 0).
    outw(st.io_base + REG_QUEUE_NOTIFY, 0);

    // Spin-poll until the used ring advances.
    let target = q.avail.idx;
    while q.used.idx != st.ctrl_last_used.wrapping_add(
        target.wrapping_sub(st.ctrl_avail_idx.wrapping_sub(1))
    ) {
        core::hint::spin_loop();
    }
    // Simpler: just wait for used.idx to equal avail.idx (single in-flight cmd)
    let expected = st.ctrl_last_used.wrapping_add(1);
    loop {
        fence(Ordering::SeqCst);
        if q.used.idx == expected { break; }
        core::hint::spin_loop();
    }
    st.ctrl_last_used = expected;

    // Ack ISR.
    let _ = inb(st.io_base + REG_ISR_STATUS);
}

/// Write a command struct T into the scratch buffer.
unsafe fn write_cmd<T: Copy>(cmd: &T) {
    let src  = cmd  as *const T as *const u8;
    let dst  = CTRLQ.cmd.as_mut_ptr();
    let len  = core::mem::size_of::<T>();
    core::ptr::copy_nonoverlapping(src, dst, len);
}

/// Read response type T from the scratch response buffer.
unsafe fn read_rsp<T: Copy>() -> T {
    let src = CTRLQ.rsp.as_ptr() as *const T;
    src.read_unaligned()
}

// ── Cursor queue helpers ──────────────────────────────────────────────────────

unsafe fn send_cursor_cmd(st: &mut GpuState, cmd_len: usize) {
    let q = &mut CURSORQ;

    q.desc[0] = VirtqDesc {
        addr:  q.cmd.as_ptr() as u64,
        len:   cmd_len as u32,
        flags: 0,
        next:  0,
    };

    let avail_slot = st.cursor_avail_idx as usize % CURSOR_QUEUE_SIZE;
    q.avail.ring[avail_slot] = 0u16;
    fence(Ordering::SeqCst);
    q.avail.idx = q.avail.idx.wrapping_add(1);
    st.cursor_avail_idx = st.cursor_avail_idx.wrapping_add(1);
    fence(Ordering::SeqCst);

    // Kick cursorq (queue 1).
    outw(st.io_base + REG_QUEUE_NOTIFY, 1);
    // Cursor commands are fire-and-forget; no spin-poll needed.
}

unsafe fn write_cursor_cmd<T: Copy>(cmd: &T) {
    let src = cmd as *const T as *const u8;
    let dst = CURSORQ.cmd.as_mut_ptr();
    core::ptr::copy_nonoverlapping(src, dst, core::mem::size_of::<T>());
}

// ── High-level GPU operations ─────────────────────────────────────────────────

/// Issue GET_DISPLAY_INFO and populate scanout state for all enabled outputs.
unsafe fn query_display_info(st: &mut GpuState) {
    write_cmd(&VirtioGpuCtrlHdr {
        typ: CMD_GET_DISPLAY_INFO,
        ..Default::default()
    });
    send_ctrl_cmd(st, core::mem::size_of::<VirtioGpuCtrlHdr>(),
                      core::mem::size_of::<VirtioGpuDisplayInfo>());

    let info: VirtioGpuDisplayInfo = read_rsp();
    if info.hdr.typ != RESP_OK_DISPLAY_INFO { return; }

    st.n_scanouts = 0;
    for i in 0..MAX_SCANOUTS.min(16) {
        let pm = &info.pmodes[i];
        if pm.enabled != 0 && pm.r.w > 0 && pm.r.h > 0 {
            st.scanouts[st.n_scanouts].width   = pm.r.w;
            st.scanouts[st.n_scanouts].height  = pm.r.h;
            st.scanouts[st.n_scanouts].enabled = true;
            st.n_scanouts += 1;
            if st.n_scanouts >= MAX_SCANOUTS { break; }
        }
    }

    // Fall back to 1024×768 if device reported nothing (shouldn't happen with QEMU).
    if st.n_scanouts == 0 {
        st.scanouts[0] = ScanoutState { width: 1024, height: 768, enabled: true,
                                        resource_id: 0, fb_phys: 0 };
        st.n_scanouts = 1;
    }
}

/// Allocate a PMM-backed pixel buffer and register it as a virtio 2D resource
/// for `scanout_idx`.  Resource IDs are 1-based: scanout 0 → resource 1, etc.
unsafe fn create_scanout_resource(st: &mut GpuState, scanout_idx: usize) {
    let s = &mut st.scanouts[scanout_idx];
    let res_id = (scanout_idx + 1) as u32;
    let w = s.width;
    let h = s.height;

    // Allocate backing pages from PMM.
    let bytes  = w as usize * h as usize * 4;
    let pages  = (bytes + 0xFFF) / 0x1000;
    let phys   = match pmm::alloc_pages(pages) {
        Some(p) => p.as_ptr() as u64,
        None    => { crate::println!("virtio_gpu: OOM for scanout {}", scanout_idx); return; }
    };
    s.resource_id = res_id;
    s.fb_phys     = phys;

    // 1. CREATE_2D_RESOURCE
    write_cmd(&VirtioGpuResourceCreate2d {
        hdr:         VirtioGpuCtrlHdr { typ: CMD_RESOURCE_CREATE_2D, ..Default::default() },
        resource_id: res_id,
        format:      VIRTIO_GPU_FORMAT_B8G8R8X8,
        width:       w,
        height:      h,
    });
    send_ctrl_cmd(st, core::mem::size_of::<VirtioGpuResourceCreate2d>(),
                      core::mem::size_of::<VirtioGpuCtrlHdr>());

    // 2. RESOURCE_ATTACH_BACKING  (header + 1 mem entry, sent as single descriptor)
    //    We lay them out contiguously in the command buffer.
    #[repr(C)]
    struct AttachCmd {
        hdr:   VirtioGpuResourceAttachBacking,
        entry: VirtioGpuMemEntry,
    }
    write_cmd(&AttachCmd {
        hdr: VirtioGpuResourceAttachBacking {
            hdr:         VirtioGpuCtrlHdr { typ: CMD_RESOURCE_ATTACH_BACKING, ..Default::default() },
            resource_id: res_id,
            nr_entries:  1,
        },
        entry: VirtioGpuMemEntry {
            addr:    phys,
            length:  (w * h * 4),
            padding: 0,
        },
    });
    send_ctrl_cmd(st, core::mem::size_of::<AttachCmd>(),
                      core::mem::size_of::<VirtioGpuCtrlHdr>());

    // 3. SET_SCANOUT  — bind the resource to the display output.
    write_cmd(&VirtioGpuSetScanout {
        hdr:         VirtioGpuCtrlHdr { typ: CMD_SET_SCANOUT, ..Default::default() },
        r:           VirtioGpuRect { x: 0, y: 0, w, h },
        scanout_id:  scanout_idx as u32,
        resource_id: res_id,
    });
    send_ctrl_cmd(st, core::mem::size_of::<VirtioGpuSetScanout>(),
                      core::mem::size_of::<VirtioGpuCtrlHdr>());

    crate::println!(
        "virtio_gpu: scanout {} {}×{} resource_id={} fb_phys={:#x}",
        scanout_idx, w, h, res_id, phys
    );
}

/// Issue TRANSFER_TO_HOST_2D + RESOURCE_FLUSH for a scanout.
unsafe fn do_flush(st: &mut GpuState, scanout_idx: usize, x: u32, y: u32, w: u32, h: u32) {
    let s = st.scanouts[scanout_idx];
    if s.resource_id == 0 { return; }

    // Clamp rect to scanout bounds.
    let x = x.min(s.width);
    let y = y.min(s.height);
    let w = w.min(s.width  - x);
    let h = h.min(s.height - y);
    if w == 0 || h == 0 { return; }

    // TRANSFER_TO_HOST_2D
    write_cmd(&VirtioGpuTransferToHost2d {
        hdr:         VirtioGpuCtrlHdr { typ: CMD_TRANSFER_TO_HOST_2D, ..Default::default() },
        r:           VirtioGpuRect { x, y, w, h },
        offset:      (y * s.width + x) as u64 * 4,
        resource_id: s.resource_id,
        padding:     0,
    });
    send_ctrl_cmd(st, core::mem::size_of::<VirtioGpuTransferToHost2d>(),
                      core::mem::size_of::<VirtioGpuCtrlHdr>());

    // RESOURCE_FLUSH
    write_cmd(&VirtioGpuResourceFlush {
        hdr:         VirtioGpuCtrlHdr { typ: CMD_RESOURCE_FLUSH, ..Default::default() },
        r:           VirtioGpuRect { x, y, w, h },
        resource_id: s.resource_id,
        padding:     0,
    });
    send_ctrl_cmd(st, core::mem::size_of::<VirtioGpuResourceFlush>(),
                      core::mem::size_of::<VirtioGpuCtrlHdr>());
}

// ── Probe / init ──────────────────────────────────────────────────────────────

/// Called from kernel init after PCI enumeration.
pub fn init() {
    let dev = match enumerate().into_iter()
        .find(|d| d.vendor == VIRTIO_VENDOR && d.device == VIRTIO_DEV_GPU)
    {
        Some(d) => d,
        None    => { crate::println!("virtio_gpu: no device"); return; }
    };

    // BAR0 for legacy virtio-gpu is an I/O BAR.
    let bar0 = dev.bars[0];
    if (bar0 & 1) == 0 {
        crate::println!("virtio_gpu: BAR0 not I/O — modern transport not yet supported");
        return;
    }
    let io = (bar0 & 0xFFFC) as u16;

    dev.enable_bus_master();
    let cmd = cam_read32(dev.bus, dev.dev, dev.func, 0x04);
    cam_write32(dev.bus, dev.dev, dev.func, 0x04, cmd | 0x05);

    unsafe {
        // Reset
        outb(io + REG_DEVICE_STATUS, 0);
        outb(io + REG_DEVICE_STATUS, S_ACK | S_DRIVER);

        // Feature negotiation: accept EDID if available, skip VIRGL.
        let dev_feat = inl(io + REG_DEVICE_FEATURES);
        outl(io + REG_GUEST_FEATURES, dev_feat & VIRTIO_GPU_F_EDID);

        outb(io + REG_DEVICE_STATUS, S_ACK | S_DRIVER | S_FEATURES_OK);
        if inb(io + REG_DEVICE_STATUS) & S_FEATURES_OK == 0 {
            outb(io + REG_DEVICE_STATUS, S_FAILED);
            crate::println!("virtio_gpu: FEATURES_OK not set");
            return;
        }

        // Initialise queue descriptors.
        CTRLQ.avail.idx   = 0;
        CTRLQ.used.idx    = 0;
        CURSORQ.avail.idx = 0;
        CURSORQ.used.idx  = 0;

        setup_queue(io, 0, CTRLQ.desc.as_ptr() as u64);
        setup_queue(io, 1, CURSORQ.desc.as_ptr() as u64);

        outb(io + REG_DEVICE_STATUS, S_ACK | S_DRIVER | S_FEATURES_OK | S_DRIVER_OK);

        let mut st = GpuState {
            io_base:          io,
            scanouts:         [ScanoutState::default(); MAX_SCANOUTS],
            n_scanouts:       0,
            ctrl_avail_idx:   0,
            ctrl_last_used:   0,
            cursor_avail_idx: 0,
        };

        // Discover display geometry.
        query_display_info(&mut st);

        // Create a resource + backing buffer for each enabled scanout.
        for i in 0..st.n_scanouts {
            create_scanout_resource(&mut st, i);
        }

        // Create cursor resource (64×64 BGRX).
        {
            write_cmd(&VirtioGpuResourceCreate2d {
                hdr:         VirtioGpuCtrlHdr { typ: CMD_RESOURCE_CREATE_2D, ..Default::default() },
                resource_id: CURSOR_RES_ID,
                format:      VIRTIO_GPU_FORMAT_B8G8R8X8,
                width:       CURSOR_W,
                height:      CURSOR_H,
            });
            send_ctrl_cmd(&mut st,
                core::mem::size_of::<VirtioGpuResourceCreate2d>(),
                core::mem::size_of::<VirtioGpuCtrlHdr>());

            #[repr(C)]
            struct AttachCmd {
                hdr:   VirtioGpuResourceAttachBacking,
                entry: VirtioGpuMemEntry,
            }
            write_cmd(&AttachCmd {
                hdr: VirtioGpuResourceAttachBacking {
                    hdr:         VirtioGpuCtrlHdr { typ: CMD_RESOURCE_ATTACH_BACKING, ..Default::default() },
                    resource_id: CURSOR_RES_ID,
                    nr_entries:  1,
                },
                entry: VirtioGpuMemEntry {
                    addr:    CURSOR_FB.0.as_ptr() as u64,
                    length:  CURSOR_W * CURSOR_H * 4,
                    padding: 0,
                },
            });
            send_ctrl_cmd(&mut st,
                core::mem::size_of::<AttachCmd>(),
                core::mem::size_of::<VirtioGpuCtrlHdr>());
        }

        *CTRL_LOCK.lock() = Some(st);
        PRESENT.store(true, Ordering::Release);

        crate::println!(
            "virtio_gpu: ready — {} scanout(s), primary {}×{}",
            CTRL_LOCK.lock().as_ref().unwrap().n_scanouts,
            CTRL_LOCK.lock().as_ref().unwrap().scanouts[0].width,
            CTRL_LOCK.lock().as_ref().unwrap().scanouts[0].height,
        );
    }
}

// ── Public surface called by framebuffer.rs / gpu.rs ─────────────────────────

/// `true` after successful `init()`.
pub fn is_present() -> bool {
    PRESENT.load(Ordering::Acquire)
}

/// Number of active display scanouts.
pub fn num_scanouts() -> usize {
    CTRL_LOCK.lock().as_ref().map(|s| s.n_scanouts).unwrap_or(0)
}

/// `(width, height, fb_phys)` for scanout `idx`, or `None`.
pub fn scanout_info(idx: usize) -> Option<(u32, u32, u64)> {
    let guard = CTRL_LOCK.lock();
    let st = guard.as_ref()?;
    if idx >= st.n_scanouts { return None; }
    let s = &st.scanouts[idx];
    Some((s.width, s.height, s.fb_phys))
}

/// `(width, height)` of scanout 0 (primary display).
pub fn dimensions() -> Option<(u32, u32)> {
    scanout_info(0).map(|(w, h, _)| (w, h))
}

/// Physical address of the pixel buffer for scanout 0.
pub fn fb_phys() -> Option<u64> {
    scanout_info(0).map(|(_, _, p)| p)
}

/// Flush a dirty rect on scanout 0 (called by `framebuffer::Framebuffer::flush`).
pub fn flush(x: u32, y: u32, w: u32, h: u32) {
    if let Some(st) = CTRL_LOCK.lock().as_mut() {
        unsafe { do_flush(st, 0, x, y, w, h); }
    }
}

/// Flush the full surface of all scanouts.
pub fn flush_all() {
    if let Some(st) = CTRL_LOCK.lock().as_mut() {
        let n = st.n_scanouts;
        for i in 0..n {
            let (w, h) = (st.scanouts[i].width, st.scanouts[i].height);
            unsafe { do_flush(st, i, 0, 0, w, h); }
        }
    }
}

/// Flush the full surface of one scanout (called by `gpu::VirtioGpuBackend::flush`).
pub fn flush_scanout(idx: usize) {
    if let Some(st) = CTRL_LOCK.lock().as_mut() {
        if idx < st.n_scanouts {
            let (w, h) = (st.scanouts[idx].width, st.scanouts[idx].height);
            unsafe { do_flush(st, idx, 0, 0, w, h); }
        }
    }
}

/// Upload a 64×64 ARGB cursor bitmap to scanout `idx` at hot-spot `(x, y)`.
pub fn cursor_update_scanout(idx: usize, pixels: &[u32], x: i32, y: i32) {
    if pixels.len() < (CURSOR_W * CURSOR_H) as usize { return; }

    // Copy pixels into the static cursor backing buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(
            pixels.as_ptr(),
            CURSOR_FB.0.as_mut_ptr(),
            (CURSOR_W * CURSOR_H) as usize,
        );
    }

    if let Some(st) = CTRL_LOCK.lock().as_mut() {
        unsafe {
            // TRANSFER cursor resource to host.
            write_cmd(&VirtioGpuTransferToHost2d {
                hdr:         VirtioGpuCtrlHdr { typ: CMD_TRANSFER_TO_HOST_2D, ..Default::default() },
                r:           VirtioGpuRect { x: 0, y: 0, w: CURSOR_W, h: CURSOR_H },
                offset:      0,
                resource_id: CURSOR_RES_ID,
                padding:     0,
            });
            send_ctrl_cmd(st, core::mem::size_of::<VirtioGpuTransferToHost2d>(),
                              core::mem::size_of::<VirtioGpuCtrlHdr>());

            // UPDATE_CURSOR command via cursorq.
            write_cursor_cmd(&VirtioGpuUpdateCursor {
                hdr: VirtioGpuCtrlHdr { typ: CMD_UPDATE_CURSOR, ..Default::default() },
                pos: VirtioGpuCursorPos {
                    scanout_id: idx as u32,
                    x:          x.max(0) as u32,
                    y:          y.max(0) as u32,
                    padding:    0,
                },
                resource_id: CURSOR_RES_ID,
                hot_x:       0,
                hot_y:       0,
                padding:     0,
            });
            send_cursor_cmd(st, core::mem::size_of::<VirtioGpuUpdateCursor>());
        }
    }
}

/// Move the cursor on scanout `idx` without re-uploading the bitmap.
pub fn cursor_move_scanout(idx: usize, x: i32, y: i32, visible: bool) {
    if let Some(st) = CTRL_LOCK.lock().as_mut() {
        unsafe {
            write_cursor_cmd(&VirtioGpuUpdateCursor {
                hdr: VirtioGpuCtrlHdr {
                    // MOVE_CURSOR = 0x0301; use 0 resource to hide cursor.
                    typ: CMD_MOVE_CURSOR,
                    ..Default::default()
                },
                pos: VirtioGpuCursorPos {
                    scanout_id: idx as u32,
                    x:          x.max(0) as u32,
                    y:          y.max(0) as u32,
                    padding:    0,
                },
                resource_id: if visible { CURSOR_RES_ID } else { 0 },
                hot_x: 0, hot_y: 0, padding: 0,
            });
            send_cursor_cmd(st, core::mem::size_of::<VirtioGpuUpdateCursor>());
        }
    }
}
