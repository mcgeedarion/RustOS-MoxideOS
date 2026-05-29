//! GDB stub session loop — drives the RSP framing state machine over the
//! serial transport and dispatches to `rsp::handle_packet`.
//!
//! ## Transport
//!
//! The GDB remote protocol framing is:
//!
//! ```
//!   ACK:       '+'
//!   NAK:       '-'
//!   Packet:    '$' <body> '#' <xx>     where xx = 2-digit hex checksum
//!   Interrupt: 0x03
//! ```
//!
//! After receiving a complete, valid packet the stub sends `+` (ACK) and
//! then the response.  On checksum mismatch it sends `-` (NAK) so GDB retries.
//!
//! ## /dev/gdbstub char device
//!
//! `session_start` registers a char device at `/dev/gdbstub` backed by
//! COM1 via `devfs::register_char_dev`.  Userspace can then attach a GDB
//! instance with:
//!
//! ```sh
//! (gdb) target remote /dev/gdbstub
//! ```
//!
//! Kernel-side, `gdbstub_listen` spins in a kernel thread waiting for the
//! first `+` or `$` byte from GDB before entering the packet loop.
//!
//! ## Attaching to a process
//!
//! The stub attaches to a PID by calling `GdbTarget::attach(pid)`.  The
//! target must already be in `PtraceState::Stopped` (the caller sends
//! SIGSTOP first, or the process hit a breakpoint / SIGTRAP).
//!
//! ## Stop-reply injection
//!
//! After `c` or `s` the session loop blocks on `target.wait_stop()`.  When
//! the target stops again (SIGTRAP, SIGSEGV, …) the loop sends the
//! `T<signal>` stop reply unprompted so GDB knows to re-query registers.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::rsp::{handle_packet, rsp_packet, Session};
use super::serial::SerialPort;
use super::target::GdbTarget;

// ── RSP framing state machine ─────────────────────────────────────────────────

/// Read one complete `$body#xx` packet from the serial port.
/// Returns the packet body on success, or `None` if a 0x03 interrupt byte
/// is received (GDB Ctrl-C).
///
/// Sends `+` ACK or `-` NAK to the host before returning.
fn recv_packet(serial: &mut SerialPort) -> Option<String> {
    loop {
        // Skip until '$'
        let b = unsafe { serial.read_byte() };
        match b {
            0x03 => return None, // Ctrl-C interrupt
            b'+' | b'-' => continue, // stray ACK/NAK from previous exchange
            b'$' => {}
            _ => continue,
        }

        // Read body until '#'
        let mut body = Vec::with_capacity(64);
        loop {
            let c = unsafe { serial.read_byte() };
            if c == b'#' { break; }
            body.push(c);
        }

        // Read two checksum hex digits
        let hi = unsafe { serial.read_byte() };
        let lo = unsafe { serial.read_byte() };
        let expected: u8 = body.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        let got_hi = (hi as char).to_digit(16).unwrap_or(0) as u8;
        let got_lo = (lo as char).to_digit(16).unwrap_or(0) as u8;
        let got = (got_hi << 4) | got_lo;

        if got != expected {
            // NAK — ask GDB to retransmit
            unsafe { serial.write_byte(b'-') };
            continue;
        }

        // ACK
        unsafe { serial.write_byte(b'+') };

        return Some(String::from_utf8_lossy(&body).into_owned());
    }
}

/// Send an RSP response string verbatim (it is already framed by `rsp_packet`).
fn send_response(serial: &mut SerialPort, resp: &str) {
    for b in resp.bytes() {
        unsafe { serial.write_byte(b) };
    }
}

// ── Stop-reply helper ─────────────────────────────────────────────────────────

/// Block until the target transitions out of the running state, then send
/// the stop reply to GDB.  Called after `c` or `s` packets.
fn wait_and_notify(serial: &mut SerialPort, target: &mut GdbTarget) {
    // Spin-poll the ctl fd.  In a real kernel this would yield / sleep,
    // but for the stub task this busy-wait is acceptable.
    let stop_reply = loop {
        let status = target.poll_status();
        if status != "running" && !status.is_empty() && status != "none" {
            break status;
        }
        // Yield to the scheduler so other tasks can run while we wait.
        crate::proc::scheduler::yield_now();
    };

    // Format as RSP stop reply if not already.
    let reply = if stop_reply.starts_with('T') || stop_reply.starts_with('W') {
        rsp_packet(&stop_reply)
    } else {
        rsp_packet("T05") // generic SIGTRAP
    };
    send_response(serial, &reply);
}

// ── /dev/gdbstub char device registration ────────────────────────────────────

/// Register `/dev/gdbstub` in devfs so GDB can open it as a serial device.
///
/// Must be called after devfs is mounted (i.e. after `init_mounts`).
pub fn register_dev() {
    // devfs::register_char_dev creates a char-device node with the given name,
    // major, and minor.  We reuse the ttyS0 major (4) and pick minor 66 to
    // avoid conflicting with existing ttyS* nodes (minor 64 = ttyS0, 65 = ttyS1).
    crate::fs::devfs::register_char_dev("gdbstub", 4, 66);
}

// ── Main session loop ─────────────────────────────────────────────────────────

/// Attach to `pid` and drive the RSP loop until the debugger detaches or
/// kills the target.  Returns when the session is done.
///
/// `serial` must already be initialised (call `serial.init()` once at boot).
pub fn run(serial: &mut SerialPort, pid: usize) {
    // Stop the target so we can inspect it.
    crate::proc::signal::send_signal(pid, 19); // SIGSTOP

    let mut target = match GdbTarget::attach(pid) {
        Some(t) => t,
        None => {
            let err = rsp_packet("E01");
            send_response(serial, &err);
            return;
        }
    };

    let mut session = Session::new();

    // Send an initial stop reply so GDB sees the target as halted.
    let initial = rsp_packet("T05");
    send_response(serial, &initial);

    loop {
        match recv_packet(serial) {
            None => {
                // 0x03 Ctrl-C: stop a running target
                target.ctl("stop");
                let stop = rsp_packet("T02"); // SIGINT
                send_response(serial, &stop);
            }
            Some(body) => {
                let resp = handle_packet(&body, &mut target, &mut session);

                // 'c' and 's' return an empty string — we must block until
                // the target stops before sending the next stop reply.
                if resp.is_empty() {
                    // Check if this was a continue/step (not kill)
                    if !body.is_empty() && (body.as_bytes()[0] == b'c' ||
                                            body.as_bytes()[0] == b's') {
                        wait_and_notify(serial, &mut target);
                    }
                    // 'k' sends "OK" then we're done — handled by the Ok branch
                } else {
                    send_response(serial, &resp);

                    // Detach on 'D' packet (explicit detach from GDB)
                    if body.as_bytes().first() == Some(&b'D') {
                        session.detach(&mut target);
                        break;
                    }
                }
            }
        }
    }
}

// ── Boot-time GDB stub init ───────────────────────────────────────────────────

/// Initialise the stub's serial port and register `/dev/gdbstub`.
///
/// Call once from the kernel init path, after devfs is mounted.
/// After this, GDB can connect over the serial UART.
///
/// # Safety
/// Must be called exactly once; no concurrent users of COM1.
pub unsafe fn init(serial: &mut SerialPort) {
    serial.init();
    register_dev();
    log::info!("gdbstub: /dev/gdbstub ready on COM1 (115200 8N1)");
}
