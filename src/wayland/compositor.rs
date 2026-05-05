#![cfg(feature = "wayland")]
//! wl_compositor and wl_surface objects.
//!
//! wl_compositor (v5) requests:
//!   0: create_surface(new_id: object<wl_surface>)
//!   1: create_region(new_id: object<wl_region>)
//!
//! wl_surface requests:
//!   0: destroy
//!   1: attach(buffer: object<wl_buffer>, x: int, y: int)
//!   2: damage(x, y, w, h: int)
//!   3: frame(callback: new_id)  — deferred to next vblank
//!   4: set_opaque_region(region: object)
//!   5: set_input_region(region: object)
//!   6: commit
//!   7: set_buffer_transform(transform: int)
//!   8: set_buffer_scale(scale: int)
//!   9: damage_buffer(x, y, w, h: int)
//!  10: offset(x, y: int)
//!
//! Frame callbacks are accumulated in PENDING_FRAME_CBS and fired by
//! `fire_frame_callbacks()` which is called from the server loop after
//! each vblank ISR fires (detected via vblank_count() delta).

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;
use super::{Client, ObjType, read_u32, encode_u32};

#[derive(Debug, Default, Clone)]
pub struct Surface {
    pub attached_buffer: Option<u32>,
    pub damage: Vec<(i32,i32,i32,i32)>,
    pub committed: bool,
    pub x: i32,
    pub y: i32,
    pub scale: i32,
}

// ── Frame callback queue ───────────────────────────────────────────────────

pub struct PendingCallback {
    pub client_sock: usize,
    pub cb_id: u32,
}

static PENDING_FRAME_CBS: Mutex<Vec<PendingCallback>> = Mutex::new(Vec::new());

/// Called from the Wayland server loop after each vblank.
pub fn fire_frame_callbacks(clients: &mut Vec<Client>) {
    let serial = (crate::drivers::amdgpu_irq::vblank_count() & 0xFFFF_FFFF) as u32;
    let cbs: Vec<PendingCallback> = {
        let mut q = PENDING_FRAME_CBS.lock();
        core::mem::replace(&mut *q, Vec::new())
    };
    for cb in cbs {
        if let Some(client) = clients.iter_mut().find(|c| c.sock_idx == cb.client_sock) {
            client.send(cb.cb_id, 0, &encode_u32(serial));
            client.objects.remove(&cb.cb_id);
            client.flush();
        }
    }
}

pub fn handle_compositor(client: &mut Client, id: u32, msg: &super::WlMsg) {
    match msg.opcode {
        0 => { let new_id = read_u32(&msg.payload, 0); client.objects.insert(new_id, ObjType::Surface(Surface::default())); }
        1 => { let new_id = read_u32(&msg.payload, 0); client.objects.insert(new_id, ObjType::Region); }
        _ => {}
    }
}

pub fn handle_surface(client: &mut Client, id: u32, msg: &super::WlMsg) {
    let surf = match client.objects.get_mut(&id) {
        Some(ObjType::Surface(s)) => s,
        _ => return,
    };
    match msg.opcode {
        0 => { /* destroy */ }
        1 => {
            let buf_id = read_u32(&msg.payload, 0);
            surf.attached_buffer = if buf_id == 0 { None } else { Some(buf_id) };
            surf.x = read_u32(&msg.payload, 4) as i32;
            surf.y = read_u32(&msg.payload, 8) as i32;
        }
        2 | 9 => {
            surf.damage.push((
                read_u32(&msg.payload,  0) as i32,
                read_u32(&msg.payload,  4) as i32,
                read_u32(&msg.payload,  8) as i32,
                read_u32(&msg.payload, 12) as i32,
            ));
        }
        3 => {
            let cb_id = read_u32(&msg.payload, 0);
            client.objects.insert(cb_id, ObjType::Callback(0));
            PENDING_FRAME_CBS.lock().push(PendingCallback { client_sock: client.sock_idx, cb_id });
        }
        6 => { commit_surface(client, id); }
        8 => { surf.scale = (read_u32(&msg.payload, 0) as i32).max(1); }
        _ => {}
    }
}

fn commit_surface(client: &mut Client, surf_id: u32) {
    let (buf_id, damage, x, y) = match client.objects.get(&surf_id) {
        Some(ObjType::Surface(s)) => (s.attached_buffer, s.damage.clone(), s.x, s.y),
        _ => return,
    };
    let buf_id = match buf_id { Some(b) => b, None => return };
    let (pa, width, height, stride) = match client.objects.get(&buf_id) {
        Some(ObjType::Buffer(b)) => (b.pa, b.width, b.height, b.stride),
        _ => return,
    };
    let gop = crate::drivers::gop::get_info();
    if gop.base == 0 { return; }

    let full = alloc::vec![(0i32, 0i32, width as i32, height as i32)];
    let regions: &[(i32,i32,i32,i32)] = if damage.is_empty() { &full } else { &damage };

    for (dx, dy, dw, dh) in regions {
        let src_x  = (*dx).max(0) as u32;
        let src_y  = (*dy).max(0) as u32;
        let copy_w = (*dw as u32).min(width.saturating_sub(src_x)).min(gop.width);
        let copy_h = (*dh as u32).min(height.saturating_sub(src_y)).min(gop.height);
        let dst_x  = (x + *dx).max(0) as u32;
        let dst_y  = (y + *dy).max(0) as u32;
        for row in 0..copy_h {
            let src_off   = ((src_y + row) * stride + src_x * 4) as u64;
            let dst_off   = ((dst_y + row) * gop.stride + dst_x * 4) as u64;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (pa + src_off) as *const u8,
                    (gop.base + dst_off) as *mut u8,
                    (copy_w * 4) as usize,
                );
            }
        }
    }
    client.send(buf_id, 0, &[]);
    if let Some(ObjType::Surface(s)) = client.objects.get_mut(&surf_id) {
        s.damage.clear();
        s.committed = true;
    }
}
