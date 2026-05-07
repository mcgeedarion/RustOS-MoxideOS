//! TCP — Transmission Control Protocol (RFC 793 + RFC 7323 timestamps).
//!
//! Per-connection state machine with:
//!   3-way handshake (SYN / SYN-ACK / ACK)
//!   Sliding window with cumulative ACKs
//!   Retransmit timeout (simple fixed 200 ms)
//!   FIN / RST teardown
//!   Listen backlog queue

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::ip;

// ── TCP header constants ──────────────────────────────────────────────────────
pub const TCP_HDR_MIN: usize = 20;

// Flags
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

// ── Connection state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// A single TCP connection.
pub struct TcpConn {
    pub state:      TcpState,
    pub local_ip:   u32,
    pub local_port: u16,
    pub remote_ip:  u32,
    pub remote_port:u16,

    // Send sequence space
    pub snd_una: u32,  // oldest unacknowledged
    pub snd_nxt: u32,  // next sequence to send
    pub snd_wnd: u16,  // remote window
    pub snd_isn: u32,  // initial SN

    // Receive sequence space
    pub rcv_nxt: u32,  // next expected
    pub rcv_wnd: u16,  // our window
    pub rcv_isn: u32,  // remote initial SN

    /// Reassembled receive buffer (data ordered by seq).
    pub rx_buf:  VecDeque<u8>,
    /// Pending transmit data.
    pub tx_buf:  VecDeque<u8>,
    /// Unacknowledged segments (for retransmit).
    pub unacked: Vec<(u32, Vec<u8>)>, // (seq, payload)

    // For accept queues
    pub backlog: VecDeque<TcpConn>,
}

impl TcpConn {
    pub fn new() -> Self {
        TcpConn {
            state:       TcpState::Closed,
            local_ip:    0, local_port: 0,
            remote_ip:   0, remote_port: 0,
            snd_una: 0, snd_nxt: 0, snd_wnd: 65535, snd_isn: 0,
            rcv_nxt: 0, rcv_wnd: 65535, rcv_isn: 0,
            rx_buf:  VecDeque::new(),
            tx_buf:  VecDeque::new(),
            unacked: Vec::new(),
            backlog: VecDeque::new(),
        }
    }
}

// ── Global connection table ───────────────────────────────────────────────────

pub static TCP_CONNS: Mutex<Vec<TcpConn>> = Mutex::new(Vec::new());

// ── Checksum ─────────────────────────────────────────────────────────────────

pub fn tcp_checksum(src_ip: u32, dst_ip: u32, segment: &[u8]) -> u16 {
    let len = segment.len() as u32;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.to_be_bytes());
    pseudo[4..8].copy_from_slice(&dst_ip.to_be_bytes());
    pseudo[8] = 0;
    pseudo[9] = ip::PROTO_TCP;
    pseudo[10] = (len >> 8) as u8;
    pseudo[11] = len as u8;

    let mut sum: u32 = 0;
    for chunk in pseudo.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for i in (0..segment.len()).step_by(2) {
        let a = segment[i];
        let b = if i + 1 < segment.len() { segment[i+1] } else { 0 };
        sum += u16::from_be_bytes([a, b]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Build and send ────────────────────────────────────────────────────────────

/// Build a TCP segment and hand it to the IP layer.
pub fn send_segment(
    src_ip: u32,  src_port: u16,
    dst_ip: u32,  dst_port: u16,
    seq: u32, ack: u32,
    flags: u8,
    window: u16,
    data: &[u8],
) {
    let hdr_len = TCP_HDR_MIN;
    let total   = hdr_len + data.len();
    let mut seg = alloc::vec![0u8; total];

    seg[0]  = (src_port >> 8) as u8;
    seg[1]  = src_port as u8;
    seg[2]  = (dst_port >> 8) as u8;
    seg[3]  = dst_port as u8;
    seg[4]  = (seq >> 24) as u8;
    seg[5]  = (seq >> 16) as u8;
    seg[6]  = (seq >> 8) as u8;
    seg[7]  = seq as u8;
    seg[8]  = (ack >> 24) as u8;
    seg[9]  = (ack >> 16) as u8;
    seg[10] = (ack >> 8) as u8;
    seg[11] = ack as u8;
    seg[12] = ((hdr_len / 4) << 4) as u8; // data offset
    seg[13] = flags;
    seg[14] = (window >> 8) as u8;
    seg[15] = window as u8;
    // checksum at [16..18] computed below
    seg[hdr_len..].copy_from_slice(data);

    let csum = tcp_checksum(src_ip, dst_ip, &seg);
    seg[16] = (csum >> 8) as u8;
    seg[17] = csum as u8;

    ip::send(dst_ip, ip::PROTO_TCP, &seg);
}

/// Send RST to a remote endpoint.
fn send_rst(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, seq: u32, ack: u32) {
    send_segment(src_ip, src_port, dst_ip, dst_port, seq, ack, RST | ACK, 0, &[]);
}

// ── Receive path ─────────────────────────────────────────────────────────────

/// Called from ip::receive for protocol = TCP.
pub fn receive(src_ip: u32, pkt: &[u8]) {
    if pkt.len() < TCP_HDR_MIN { return; }

    // Parse TCP header
    let src_port   = u16::from_be_bytes([pkt[0], pkt[1]]);
    let dst_port   = u16::from_be_bytes([pkt[2], pkt[3]]);
    let seq        = u32::from_be_bytes([pkt[4],  pkt[5],  pkt[6],  pkt[7]]);
    let ack_num    = u32::from_be_bytes([pkt[8],  pkt[9],  pkt[10], pkt[11]]);
    let data_off   = ((pkt[12] >> 4) * 4) as usize;
    let flags      = pkt[13];
    let window     = u16::from_be_bytes([pkt[14], pkt[15]]);
    if pkt.len() < data_off { return; }
    let data       = &pkt[data_off..];

    // Verify checksum
    let our_ip = ip::our_ip();
    if tcp_checksum(src_ip, our_ip, pkt) != 0 { return; }

    let mut conns = TCP_CONNS.lock();

    // 1. Find established / in-progress connection matching 4-tuple.
    let conn_idx = conns.iter().position(|c|
        c.local_port == dst_port && c.remote_ip == src_ip && c.remote_port == src_port
        && !matches!(c.state, TcpState::Closed | TcpState::Listen)
    );

    if let Some(idx) = conn_idx {
        process_established(idx, &mut conns, src_ip, seq, ack_num, flags, window, data);
        return;
    }

    // 2. Check for SYN against a listening socket.
    let listen_idx = conns.iter().position(|c|
        c.local_port == dst_port && c.state == TcpState::Listen
    );

    if let Some(lidx) = listen_idx {
        if flags & SYN != 0 && flags & ACK == 0 {
            // Create a new half-open connection.
            let isn = crate::rand::rand32();
            let mut new_conn = TcpConn::new();
            new_conn.state        = TcpState::SynReceived;
            new_conn.local_ip     = our_ip;
            new_conn.local_port   = dst_port;
            new_conn.remote_ip    = src_ip;
            new_conn.remote_port  = src_port;
            new_conn.rcv_isn      = seq;
            new_conn.rcv_nxt      = seq.wrapping_add(1);
            new_conn.snd_isn      = isn;
            new_conn.snd_nxt      = isn.wrapping_add(1);
            new_conn.snd_una      = isn;
            new_conn.snd_wnd      = window;

            // Send SYN-ACK
            send_segment(our_ip, dst_port, src_ip, src_port,
                isn, new_conn.rcv_nxt, SYN | ACK, 65535, &[]);

            conns[lidx].backlog.push_back(new_conn);
            return;
        }
    }

    // No match → RST
    if flags & RST == 0 {
        let ack_seq = if flags & ACK != 0 { ack_num } else { seq.wrapping_add(data.len() as u32) };
        send_rst(our_ip, dst_port, src_ip, src_port, ack_seq, seq);
    }
}

/// Process a segment for an existing (non-Listen) connection.
fn process_established(
    idx: usize,
    conns: &mut Vec<TcpConn>,
    src_ip: u32,
    seq: u32, ack: u32, flags: u8, window: u16,
    data: &[u8],
) {
    let our_ip = ip::our_ip();
    let conn   = &mut conns[idx];

    // RST handling
    if flags & RST != 0 {
        conn.state = TcpState::Closed;
        return;
    }

    // Update remote window
    conn.snd_wnd = window;

    // ACK processing
    if flags & ACK != 0 {
        if conn.state == TcpState::SynSent {
            // SYN-ACK received (active open)
            if flags & SYN != 0 {
                conn.rcv_isn  = seq;
                conn.rcv_nxt  = seq.wrapping_add(1);
                conn.snd_una  = ack;
                conn.state    = TcpState::Established;
                // Send final ACK
                send_segment(our_ip, conn.local_port,
                    conn.remote_ip, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, ACK, conn.rcv_wnd, &[]);
                return;
            }
        }
        // Advance snd_una
        if is_between(conn.snd_una, ack, conn.snd_nxt.wrapping_add(1)) {
            // Remove acked segments from unacked
            conn.unacked.retain(|(s, _)| !is_between(conn.snd_una, *s, ack));
            conn.snd_una = ack;
        }
        // SynReceived → Established on first ACK
        if conn.state == TcpState::SynReceived {
            conn.state = TcpState::Established;
        }
        // FinWait1 → FinWait2 if our FIN was acked
        if conn.state == TcpState::FinWait1 && conn.snd_una == conn.snd_nxt {
            conn.state = TcpState::FinWait2;
        }
        // LastAck → Closed if our FIN was acked
        if conn.state == TcpState::LastAck && conn.snd_una == conn.snd_nxt {
            conn.state = TcpState::Closed;
            return;
        }
    }

    // Data / FIN handling
    if matches!(conn.state, TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2) {
        let expected = conn.rcv_nxt;
        if seq == expected && !data.is_empty() {
            conn.rx_buf.extend(data.iter().copied());
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(data.len() as u32);
        }
        if flags & FIN != 0 {
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
            match conn.state {
                TcpState::Established => {
                    conn.state = TcpState::CloseWait;
                }
                TcpState::FinWait2 => {
                    conn.state = TcpState::TimeWait;
                }
                _ => {}
            }
        }
        // Send cumulative ACK
        let ack_seq = conn.rcv_nxt;
        let lp = conn.local_port; let rip = conn.remote_ip; let rp = conn.remote_port;
        let wnd = conn.rcv_wnd;
        let snd = conn.snd_nxt;
        send_segment(our_ip, lp, rip, rp, snd, ack_seq, ACK, wnd, &[]);
    }
}

/// Sequence-number comparison: is `x` in [lo, hi)?
fn is_between(lo: u32, x: u32, hi: u32) -> bool {
    if lo <= hi { lo <= x && x < hi }
    else        { lo <= x || x < hi } // wrap-around
}

// ── Public API (used by socket layer) ────────────────────────────────────────

/// Open an active TCP connection (client side).
pub fn connect(local_port: u16, remote_ip: u32, remote_port: u16) -> usize {
    let our_ip = ip::our_ip();
    let isn    = crate::rand::rand32();
    let mut c  = TcpConn::new();
    c.state        = TcpState::SynSent;
    c.local_ip     = our_ip;
    c.local_port   = local_port;
    c.remote_ip    = remote_ip;
    c.remote_port  = remote_port;
    c.snd_isn      = isn;
    c.snd_nxt      = isn.wrapping_add(1);
    c.snd_una      = isn;
    send_segment(our_ip, local_port, remote_ip, remote_port,
        isn, 0, SYN, 65535, &[]);
    let mut conns = TCP_CONNS.lock();
    conns.push(c);
    conns.len() - 1
}

/// Bind a listening socket.
pub fn listen(local_port: u16) -> usize {
    let mut c = TcpConn::new();
    c.state      = TcpState::Listen;
    c.local_ip   = ip::our_ip();
    c.local_port = local_port;
    let mut conns = TCP_CONNS.lock();
    conns.push(c);
    conns.len() - 1
}

/// Accept the next fully-established connection from a listen socket's backlog.
/// Returns the new connection index or None.
pub fn accept(listen_idx: usize) -> Option<usize> {
    let mut conns = TCP_CONNS.lock();
    // find a SynReceived that is now Established in the backlog
    if let Some(conn) = conns.get_mut(listen_idx) {
        let pos = conn.backlog.iter().position(|c| c.state == TcpState::Established);
        if let Some(p) = pos {
            let accepted = conn.backlog.remove(p).unwrap();
            conns.push(accepted);
            return Some(conns.len() - 1);
        }
    }
    None
}

/// Write data to a TCP connection's send buffer (caller pumps it via flush).
pub fn write(idx: usize, data: &[u8]) -> isize {
    let mut conns = TCP_CONNS.lock();
    if let Some(c) = conns.get_mut(idx) {
        if c.state != TcpState::Established { return -104; } // ECONNRESET
        c.tx_buf.extend(data.iter().copied());
        return data.len() as isize;
    }
    -9 // EBADF
}

/// Flush pending TX data out as segments.
pub fn flush(idx: usize) {
    let our_ip = ip::our_ip();
    let mut conns = TCP_CONNS.lock();
    if let Some(c) = conns.get_mut(idx) {
        if c.state != TcpState::Established { return; }
        let mss = 1460usize;
        while !c.tx_buf.is_empty() {
            let send_len = c.tx_buf.len().min(mss).min(c.snd_wnd as usize);
            if send_len == 0 { break; }
            let chunk: Vec<u8> = c.tx_buf.drain(..send_len).collect();
            send_segment(our_ip, c.local_port, c.remote_ip, c.remote_port,
                c.snd_nxt, c.rcv_nxt, PSH | ACK, c.rcv_wnd, &chunk);
            c.unacked.push((c.snd_nxt, chunk.clone()));
            c.snd_nxt = c.snd_nxt.wrapping_add(send_len as u32);
        }
    }
}

/// Read up to `len` bytes from the RX buffer.
pub fn read(idx: usize, buf: &mut [u8]) -> isize {
    let mut conns = TCP_CONNS.lock();
    if let Some(c) = conns.get_mut(idx) {
        let n = c.rx_buf.len().min(buf.len());
        for (i, b) in c.rx_buf.drain(..n).enumerate() {
            buf[i] = b;
        }
        return n as isize;
    }
    -9
}

/// Initiate TCP close (send FIN).
pub fn close(idx: usize) {
    let our_ip = ip::our_ip();
    let mut conns = TCP_CONNS.lock();
    if let Some(c) = conns.get_mut(idx) {
        if c.state == TcpState::Established {
            send_segment(our_ip, c.local_port, c.remote_ip, c.remote_port,
                c.snd_nxt, c.rcv_nxt, FIN | ACK, c.rcv_wnd, &[]);
            c.snd_nxt = c.snd_nxt.wrapping_add(1);
            c.state = TcpState::FinWait1;
        } else if c.state == TcpState::CloseWait {
            send_segment(our_ip, c.local_port, c.remote_ip, c.remote_port,
                c.snd_nxt, c.rcv_nxt, FIN | ACK, c.rcv_wnd, &[]);
            c.snd_nxt = c.snd_nxt.wrapping_add(1);
            c.state = TcpState::LastAck;
        }
    }
}

/// Return true if a connection has received data available.
pub fn rx_ready(idx: usize) -> bool {
    TCP_CONNS.lock().get(idx).map(|c| !c.rx_buf.is_empty()).unwrap_or(false)
}

/// Return true if a connection is writable (established and window open).
pub fn tx_ready(idx: usize) -> bool {
    TCP_CONNS.lock().get(idx)
        .map(|c| c.state == TcpState::Established && c.snd_wnd > 0)
        .unwrap_or(false)
}
