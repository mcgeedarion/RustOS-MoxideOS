//! GDB stub session loop — drives the RSP framing state machine over the
//! serial transport and dispatches to `rsp::handle_packet`.
//!
//! ## Transport
//!
//! ```
//!   ACK:       '+'
//!   NAK:       '-'
//!   Packet:    '$' <body> '#' <xx>     where xx = 2-digit hex checksum
//!   Interrupt: 0x03
//! ```
//!
//! After receiving a complete, valid packet the stub sends `+` (ACK) and
//! then the response. On checksum mismatch it sends `-` (NAK) so GDB retries.
//!
//! ## vCont
//!
//! `vCont` packets are intercepted **before** `rsp::handle_packet` and
//! routed to `rsp_vcont::handle_vcont`. The session owns an `RspState` that
//! tracks the `halted` flag and optional `range_step` bounds.
//!
//! `vCont?` capability queries return `vCont;c;s;t;r`.
//!
//! Range-step (`vCont;r<s>,<e>`) arms hardware single-step and loops until
//! `rsp_vcont::range_step_done` returns `true`, at which point a `T05` stop
//! reply is sent.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::rsp::{handle_packet, rsp_packet, Session};
use super::rsp_vcont::{handle_vcont, range_step_done, RspState};
use super::serial::SerialPort;
use super::target::GdbTarget;
use crate::debug::gdbstub::arch::GdbArch;

/// Read one complete `$body#xx` packet from the serial port.
/// Returns the packet body on success, or `None` if a 0x03 interrupt byte
/// is received (GDB Ctrl-C).
fn recv_packet(serial: &mut SerialPort) -> Option<String> {
    loop {
        let b = unsafe { serial.read_byte() };
        match b {
            0x03     => return None,
            b'+' | b'-' => continue,
            b'$'     => {},
            _        => continue,
        }

        let mut body = Vec::with_capacity(64);
        loop {
            let c = unsafe { serial.read_byte() };
            if c == b'#' { break; }
            body.push(c);
        }

        let hi = unsafe { serial.read_byte() };
        let lo = unsafe { serial.read_byte() };
        let expected: u8 = body.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        let got_hi = (hi as char).to_digit(16).unwrap_or(0) as u8;
        let got_lo = (lo as char).to_digit(16).unwrap_or(0) as u8;
        let got = (got_hi << 4) | got_lo;

        if got != expected {
            unsafe { serial.write_byte(b'-') };
            continue;
        }
        unsafe { serial.write_byte(b'+') };
        return Some(String::from_utf8_lossy(&body).into_owned());
    }
}

fn send_response(serial: &mut SerialPort, resp: &str) {
    for b in resp.bytes() {
        unsafe { serial.write_byte(b) };
    }
}

/// Block until the target stops, then send the stop reply.
/// For range-step, re-arms single-step until PC leaves the range.
fn wait_and_notify(
    serial: &mut SerialPort,
    target: &mut GdbTarget,
    vcont_state: &mut RspState,
) {
    loop {
        let status = loop {
            let s = target.poll_status();
            if s != "running" && !s.is_empty() && s != "none" {
                break s;
            }
            crate::proc::scheduler::yield_now();
        };

        // Determine current PC via the arch-appropriate trait.
        #[cfg(target_arch = "x86_64")]
        let pc = crate::debug::gdbstub::arch::X86_64::pc(target.trap_frame());
        #[cfg(target_arch = "riscv64")]
        let pc = crate::debug::gdbstub::arch::RiscV64::pc(target.trap_frame());
        #[cfg(target_arch = "aarch64")]
        let pc = crate::debug::gdbstub::arch::AArch64::pc(target.trap_frame());
        #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64", target_arch = "aarch64")))]
        let pc: u64 = 0;

        if vcont_state.range_step.is_some() && !range_step_done(vcont_state, pc) {
            // Still inside the range — re-arm single-step and continue.
            target.ctl("step");
            continue;
        }

        // Out of range or not a range-step: send stop reply.
        vcont_state.halted = true;
        vcont_state.range_step = None;

        let reply = if status.starts_with('T') || status.starts_with('W') {
            rsp_packet(&status)
        } else {
            rsp_packet("T05")
        };
        send_response(serial, &reply);
        return;
    }
}

/// Register `/dev/gdbstub` in devfs.
pub fn register_dev() {
    crate::fs::devfs::register_char_dev("gdbstub", 4, 66);
}

/// Attach to `pid` and drive the RSP loop until the debugger detaches or
/// kills the target.
pub fn run(serial: &mut SerialPort, pid: usize) {
    crate::proc::signal::send_signal(pid, 19); // SIGSTOP

    let mut target = match GdbTarget::attach(pid) {
        Some(t) => t,
        None => {
            send_response(serial, &rsp_packet("E01"));
            return;
        },
    };

    let mut session     = Session::new();
    let mut vcont_state = RspState::new();

    // Initial stop reply.
    send_response(serial, &rsp_packet("T05"));

    loop {
        match recv_packet(serial) {
            None => {
                // Ctrl-C: stop a running target.
                target.ctl("stop");
                vcont_state.halted    = true;
                vcont_state.range_step = None;
                send_response(serial, &rsp_packet("T02")); // SIGINT
            },

            Some(body) => {
                // --- vCont interception (before the generic handler) ---
                if body.starts_with("vCont") {
                    let reply = handle_vcont(&body, target.trap_frame_mut(), &mut vcont_state);
                    if !reply.is_empty() {
                        // Non-empty reply means immediate stop (vCont;t or vCont?).
                        send_response(serial, &rsp_packet(&reply));
                    } else if !vcont_state.halted {
                        // Target is now running — wait for the next stop.
                        wait_and_notify(serial, &mut target, &mut vcont_state);
                    }
                    continue;
                }

                // --- Generic RSP dispatch ---
                let resp = handle_packet(&body, &mut target, &mut session);

                if resp.is_empty() {
                    // 'c' or 's' — wait for stop.
                    if body.as_bytes().first().map_or(false, |&b| b == b'c' || b == b's') {
                        wait_and_notify(serial, &mut target, &mut vcont_state);
                    }
                } else {
                    send_response(serial, &resp);
                    if body.as_bytes().first() == Some(&b'D') {
                        session.detach(&mut target);
                        break;
                    }
                }
            },
        }
    }
}

/// Initialise the stub's serial port and register `/dev/gdbstub`.
///
/// # Safety
/// Must be called exactly once; no concurrent users of COM1.
pub unsafe fn init(serial: &mut SerialPort) {
    serial.init();
    register_dev();
    log::info!("gdbstub: /dev/gdbstub ready on COM1 (115200 8N1)");
}
