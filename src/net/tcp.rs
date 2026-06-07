//! TCP — Transmission Control Protocol (RFC 793 + RFC 7323 timestamps).
//!
//! Per-connection state machine with:
//!   3-way handshake (SYN / SYN-ACK / ACK)
//!   Sliding window with cumulative ACKs
//!   Retransmit timeout (simple fixed 200 ms)
//!   FIN / RST teardown
//!   Listen backlog queue
//!   TCP_NODELAY: skip Nagle coalescing when set

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::ip;

pub const TCP_HDR_MIN: usize = 20;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

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

pub struct TcpConn {
    pub state: TcpState,
    pub local_ip: u32,
    pub local_port: u16,
    pub remote_ip: u32,
    pub remote_port: u16,

    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u16,
    pub snd_isn: u32,

    pub rcv_nxt: u32,
    pub rcv_wnd: u16,
    pub rcv_isn: u32,

    pub rx_buf: VecDeque<u8>,
    pub tx_buf: VecDeque<u8>,
    pub unacked: Vec<(u32, Vec<u8>)>,

    pub backlog: VecDeque<TcpConn>,

    /// When true, bypass Nagle: send immediately regardless of segment size.
    pub nodelay: bool,
}

impl TcpConn {
    pub fn new() -> Self {
        TcpConn {
            state: TcpState::Closed,
            local_ip: 0,
            local_port: 0,
            remote_ip: 0,
            remote_port: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 65535,
            snd_isn: 0,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            rcv_isn: 0,
            rx_buf: VecDeque::new(),
            tx_buf: VecDeque::new(),
            unacked: Vec::new(),
            backlog: VecDeque::new(),
            nodelay: false,
        }
    }
}

pub static TCP_CONNS: Mutex<Vec<TcpConn>> = Mutex::new(Vec::new());

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
        let b = if i + 1 < segment.len() {
            segment[i + 1]
        } else {
            0
        };
        sum += u16::from_be_bytes([a, b]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn send_segment(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    data: &[u8],
) {
    let hdr_len = TCP_HDR_MIN;
    let mut seg = alloc::vec![0u8; hdr_len + data.len()];
    seg[0] = (src_port >> 8) as u8;
    seg[1] = src_port as u8;
    seg[2] = (dst_port >> 8) as u8;
    seg[3] = dst_port as u8;
    seg[4] = (seq >> 24) as u8;
    seg[5] = (seq >> 16) as u8;
    seg[6] = (seq >> 8) as u8;
    seg[7] = seq as u8;
    seg[8] = (ack >> 24) as u8;
    seg[9] = (ack >> 16) as u8;
    seg[10] = (ack >> 8) as u8;
    seg[11] = ack as u8;
    seg[12] = ((hdr_len / 4) << 4) as u8;
    seg[13] = flags;
    seg[14] = (window >> 8) as u8;
    seg[15] = window as u8;
    seg[hdr_len..].copy_from_slice(data);
    let csum = tcp_checksum(src_ip, dst_ip, &seg);
    seg[16] = (csum >> 8) as u8;
    seg[17] = csum as u8;
    ip::send(dst_ip, ip::PROTO_TCP, &seg);
}

fn send_rst(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, seq: u32, ack: u32) {
    send_segment(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        seq,
        ack,
        RST | ACK,
        0,
        &[],
    );
}

pub fn receive(src_ip: u32, pkt: &[u8]) {
    if pkt.len() < TCP_HDR_MIN {
        return;
    }
    let src_port = u16::from_be_bytes([pkt[0], pkt[1]]);
    let dst_port = u16::from_be_bytes([pkt[2], pkt[3]]);
    let seq = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    let ack_num = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
    let data_off = ((pkt[12] >> 4) * 4) as usize;
    let flags = pkt[13];
    let window = u16::from_be_bytes([pkt[14], pkt[15]]);
    if pkt.len() < data_off {
        return;
    }
    let data = &pkt[data_off..];

    let our_ip = ip::our_ip();
    if tcp_checksum(src_ip, our_ip, pkt) != 0 {
        return;
    }

    let mut conns = TCP_CONNS.lock();

    let conn_idx = conns.iter().position(|c| {
        c.local_port == dst_port
            && c.remote_ip == src_ip
            && c.remote_port == src_port
            && !matches!(c.state, TcpState::Closed | TcpState::Listen)
    });
    if let Some(idx) = conn_idx {
        process_established(idx, &mut conns, src_ip, seq, ack_num, flags, window, data);
        return;
    }

    let listen_idx = conns
        .iter()
        .position(|c| c.local_port == dst_port && c.state == TcpState::Listen);
    if let Some(lidx) = listen_idx {
        if flags & SYN != 0 && flags & ACK == 0 {
            let isn = crate::rand::rand32();
            let mut nc = TcpConn::new();
            nc.state = TcpState::SynReceived;
            nc.local_ip = our_ip;
            nc.local_port = dst_port;
            nc.remote_ip = src_ip;
            nc.remote_port = src_port;
            nc.rcv_isn = seq;
            nc.rcv_nxt = seq.wrapping_add(1);
            nc.snd_isn = isn;
            nc.snd_nxt = isn.wrapping_add(1);
            nc.snd_una = isn;
            nc.snd_wnd = window;
            send_segment(
                our_ip,
                dst_port,
                src_ip,
                src_port,
                isn,
                nc.rcv_nxt,
                SYN | ACK,
                65535,
                &[],
            );
            conns[lidx].backlog.push_back(nc);
            return;
        }
    }

    if flags & RST == 0 {
        let ack_seq = if flags & ACK != 0 {
            ack_num
        } else {
            seq.wrapping_add(data.len() as u32)
        };
        send_rst(our_ip, dst_port, src_ip, src_port, ack_seq, seq);
    }
}

fn process_established(
    idx: usize,
    conns: &mut Vec<TcpConn>,
    _src_ip: u32,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    data: &[u8],
) {
    let our_ip = ip::our_ip();
    let conn = &mut conns[idx];

    if flags & RST != 0 {
        conn.state = TcpState::Closed;
        return;
    }
    conn.snd_wnd = window;

    if flags & ACK != 0 {
        if conn.state == TcpState::SynSent && flags & SYN != 0 {
            conn.rcv_isn = seq;
            conn.rcv_nxt = seq.wrapping_add(1);
            conn.snd_una = ack;
            conn.state = TcpState::Established;
            send_segment(
                our_ip,
                conn.local_port,
                conn.remote_ip,
                conn.remote_port,
                conn.snd_nxt,
                conn.rcv_nxt,
                ACK,
                conn.rcv_wnd,
                &[],
            );
            return;
        }
        if is_between(conn.snd_una, ack, conn.snd_nxt.wrapping_add(1)) {
            conn.unacked
                .retain(|(s, _)| !is_between(conn.snd_una, *s, ack));
            conn.snd_una = ack;
        }
        if conn.state == TcpState::SynReceived {
            conn.state = TcpState::Established;
        }
        if conn.state == TcpState::FinWait1 && conn.snd_una == conn.snd_nxt {
            conn.state = TcpState::FinWait2;
        }
        if conn.state == TcpState::LastAck && conn.snd_una == conn.snd_nxt {
            conn.state = TcpState::Closed;
            return;
        }
    }

    if matches!(
        conn.state,
        TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
    ) {
        if seq == conn.rcv_nxt && !data.is_empty() {
            conn.rx_buf.extend(data.iter().copied());
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(data.len() as u32);
        }
        if flags & FIN != 0 {
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
            match conn.state {
                TcpState::Established => conn.state = TcpState::CloseWait,
                TcpState::FinWait2 => conn.state = TcpState::TimeWait,
                _ => {},
            }
        }
        let (lp, rip, rp, wnd, snd, rcv) = (
            conn.local_port,
            conn.remote_ip,
            conn.remote_port,
            conn.rcv_wnd,
            conn.snd_nxt,
            conn.rcv_nxt,
        );
        send_segment(our_ip, lp, rip, rp, snd, rcv, ACK, wnd, &[]);
    }
}

fn is_between(lo: u32, x: u32, hi: u32) -> bool {
    if lo <= hi {
        lo <= x && x < hi
    } else {
        lo <= x || x < hi
    }
}

/// Start an active TCP connection; returns connection index.
pub fn connect(dst_ip: u32, dst_port: u16, src_port: u16) -> Result<usize, isize> {
    let our_ip = ip::our_ip();
    let isn = crate::rand::rand32();
    let mut c = TcpConn::new();
    c.state = TcpState::SynSent;
    c.local_ip = our_ip;
    c.local_port = src_port;
    c.remote_ip = dst_ip;
    c.remote_port = dst_port;
    c.snd_isn = isn;
    c.snd_nxt = isn.wrapping_add(1);
    c.snd_una = isn;
    send_segment(our_ip, src_port, dst_ip, dst_port, isn, 0, SYN, 65535, &[]);
    let mut conns = TCP_CONNS.lock();
    conns.push(c);
    Ok(conns.len() - 1)
}

/// Return the current TCP state for `idx` (used by blocking connect).
pub fn conn_state(idx: usize) -> Option<TcpState> {
    TCP_CONNS.lock().get(idx).map(|c| c.state)
}

/// Enable or disable TCP_NODELAY on an existing connection.
pub fn set_nodelay(idx: usize, enabled: bool) {
    if let Some(c) = TCP_CONNS.lock().get_mut(idx) {
        c.nodelay = enabled;
    }
}

/// Create a passive listening entry; returns its index.
pub fn listen(local_port: u16) -> usize {
    let mut c = TcpConn::new();
    c.state = TcpState::Listen;
    c.local_ip = ip::our_ip();
    c.local_port = local_port;
    let mut conns = TCP_CONNS.lock();
    conns.push(c);
    conns.len() - 1
}

/// Pop the next fully-established connection from a listener's backlog.
pub fn accept(listen_idx: usize) -> Option<usize> {
    let mut conns = TCP_CONNS.lock();
    let pos = conns
        .get(listen_idx)?
        .backlog
        .iter()
        .position(|c| c.state == TcpState::Established)?;
    let accepted = conns[listen_idx].backlog.remove(pos).unwrap();
    conns.push(accepted);
    Some(conns.len() - 1)
}

/// Return `(remote_ip, remote_port)` for a connection.
pub fn peer_addr(idx: usize) -> (u32, u16) {
    TCP_CONNS
        .lock()
        .get(idx)
        .map(|c| (c.remote_ip, c.remote_port))
        .unwrap_or((0, 0))
}

/// Write data to the TX buffer and immediately flush.
pub fn send(idx: usize, data: &[u8]) -> isize {
    let n = write(idx, data);
    if n > 0 {
        flush(idx);
    }
    n
}

/// Drain up to `buf.len()` bytes from the RX buffer.
pub fn recv(idx: usize, buf: &mut [u8]) -> isize {
    read(idx, buf)
}

/// True if there is data in the RX buffer.
pub fn rx_available(idx: usize) -> bool {
    TCP_CONNS
        .lock()
        .get(idx)
        .map(|c| !c.rx_buf.is_empty())
        .unwrap_or(false)
}

/// Append to TX buffer without flushing.
pub fn write(idx: usize, data: &[u8]) -> isize {
    let mut conns = TCP_CONNS.lock();
    match conns.get_mut(idx) {
        Some(c) if c.state == TcpState::Established => {
            c.tx_buf.extend(data.iter().copied());
            data.len() as isize
        },
        Some(_) => -104, // ECONNRESET
        None => -9,      // EBADF
    }
}

/// Transmit all pending TX data.
/// With TCP_NODELAY each write is flushed immediately regardless of size.
/// Without it, data is coalesced into MSS-sized (1460 B) segments.
pub fn flush(idx: usize) {
    let our_ip = ip::our_ip();
    let mut conns = TCP_CONNS.lock();
    if let Some(c) = conns.get_mut(idx) {
        if c.state != TcpState::Established {
            return;
        }
        const MSS: usize = 1460;
        while !c.tx_buf.is_empty() {
            let limit = if c.nodelay {
                c.tx_buf.len() // send everything at once
            } else {
                MSS // coalesce up to one MSS
            };
            let n = limit.min(c.snd_wnd as usize);
            if n == 0 {
                break;
            }
            let chunk: Vec<u8> = c.tx_buf.drain(..n).collect();
            send_segment(
                our_ip,
                c.local_port,
                c.remote_ip,
                c.remote_port,
                c.snd_nxt,
                c.rcv_nxt,
                PSH | ACK,
                c.rcv_wnd,
                &chunk,
            );
            c.unacked.push((c.snd_nxt, chunk));
            c.snd_nxt = c.snd_nxt.wrapping_add(n as u32);
        }
    }
}

/// Drain up to `buf.len()` bytes from the RX ring buffer.
pub fn read(idx: usize, buf: &mut [u8]) -> isize {
    let mut conns = TCP_CONNS.lock();
    match conns.get_mut(idx) {
        Some(c) => {
            let n = c.rx_buf.len().min(buf.len());
            for (i, b) in c.rx_buf.drain(..n).enumerate() {
                buf[i] = b;
            }
            n as isize
        },
        None => -9,
    }
}

/// Initiate graceful close (FIN).
pub fn close(idx: usize) {
    let our_ip = ip::our_ip();
    let mut conns = TCP_CONNS.lock();
    if let Some(c) = conns.get_mut(idx) {
        match c.state {
            TcpState::Established => {
                send_segment(
                    our_ip,
                    c.local_port,
                    c.remote_ip,
                    c.remote_port,
                    c.snd_nxt,
                    c.rcv_nxt,
                    FIN | ACK,
                    c.rcv_wnd,
                    &[],
                );
                c.snd_nxt = c.snd_nxt.wrapping_add(1);
                c.state = TcpState::FinWait1;
            },
            TcpState::CloseWait => {
                send_segment(
                    our_ip,
                    c.local_port,
                    c.remote_ip,
                    c.remote_port,
                    c.snd_nxt,
                    c.rcv_nxt,
                    FIN | ACK,
                    c.rcv_wnd,
                    &[],
                );
                c.snd_nxt = c.snd_nxt.wrapping_add(1);
                c.state = TcpState::LastAck;
            },
            _ => {},
        }
    }
}

/// Retransmit all unacknowledged segments.
/// Call from a periodic timer interrupt (e.g. every 200 ms).
pub fn tick_retransmit() {
    let our_ip = ip::our_ip();
    let conns = TCP_CONNS.lock();
    for c in conns.iter() {
        if c.state != TcpState::Established {
            continue;
        }
        for (seq, data) in &c.unacked {
            send_segment(
                our_ip,
                c.local_port,
                c.remote_ip,
                c.remote_port,
                *seq,
                c.rcv_nxt,
                PSH | ACK,
                c.rcv_wnd,
                data,
            );
        }
    }
}

/// Placeholder transport scheme adapter for scheme-table registration.
pub struct TcpScheme;

impl TcpScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for TcpScheme {
    fn open(
        &self,
        _path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        Err(scheme_api::SchemeError::NoSuchScheme)
    }

    fn close(&self, _fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        Ok(())
    }
}
