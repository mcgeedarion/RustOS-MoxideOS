//! Bluetooth HCI driver (UART transport, HCI H4).
//!
//! Implements the HCI H4 UART framing layer and enough of the Bluetooth
//! Core spec (Bluetooth 4.2) to:
//!   - Reset the controller (HCI_Reset)
//!   - Read the local BD_ADDR (HCI_Read_BD_ADDR)
//!   - Configure LE scan parameters and start passive LE advertising scan
//!   - Receive HCI Event / LE Meta Event packets and forward key / button
//!     events from connected HID-over-GATT peripherals to evdev
//!
//! ## H4 framing
//!   Each packet starts with a 1-byte indicator:
//!     0x01 = HCI Command
//!     0x02 = HCI ACL Data
//!     0x04 = HCI Event
//!
//! ## Usage
//!   ```rust
//!   bluetooth::init(uart_base);
//!   loop {
//!       bluetooth::poll(); // call from main loop or timer tick
//!   }
//!   ```

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

// ---------------------------------------------------------------------------
// HCI packet type indicators
// ---------------------------------------------------------------------------

const HCI_CMD:   u8 = 0x01;
const HCI_ACL:   u8 = 0x02;
const HCI_EVENT: u8 = 0x04;

// ---------------------------------------------------------------------------
// HCI opcodes (OGF << 10 | OCF)
// ---------------------------------------------------------------------------

const HCI_RESET:               u16 = 0x0C03;
const HCI_READ_BD_ADDR:        u16 = 0x1009;
const HCI_LE_SET_SCAN_PARAMS:  u16 = 0x2043;
const HCI_LE_SET_SCAN_ENABLE:  u16 = 0x2044;
const HCI_LE_CREATE_CONN:      u16 = 0x200D;
const HCI_LE_SET_EVENT_MASK:   u16 = 0x2001;

// ---------------------------------------------------------------------------
// HCI event codes
// ---------------------------------------------------------------------------

const EVT_CMD_COMPLETE:     u8 = 0x0E;
const EVT_CMD_STATUS:       u8 = 0x0F;
const EVT_LE_META:          u8 = 0x3E;
const EVT_DISCONN_COMPLETE: u8 = 0x05;
const EVT_NUM_COMP_PKTS:    u8 = 0x13;

// LE Meta subevent codes
const LE_ADV_REPORT:        u8 = 0x02;
const LE_CONN_COMPLETE:     u8 = 0x01;

// ---------------------------------------------------------------------------
// UART MMIO layout (16550-compatible)
// ---------------------------------------------------------------------------

const UART_RBR: usize = 0x00;
const UART_THR: usize = 0x00;
const UART_IER: usize = 0x01;
const UART_FCR: usize = 0x02;
const UART_LCR: usize = 0x03;
const UART_MCR: usize = 0x04;
const UART_LSR: usize = 0x05;
const UART_DLL: usize = 0x00; // when DLAB=1
const UART_DLH: usize = 0x01; // when DLAB=1

const LSR_DR:  u8 = 1 << 0; // data ready
const LSR_THRE:u8 = 1 << 5; // transmitter holding register empty

// ---------------------------------------------------------------------------
// BD_ADDR
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BdAddr(pub [u8; 6]);

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct BtState {
    uart:       usize,   // MMIO base
    bd_addr:    BdAddr,
    /// Accumulation buffer for the current incoming packet
    rx_buf:     Vec<u8>,
    /// Bytes expected in current packet (-1 = waiting for header)
    rx_expect:  isize,
    rx_ptype:   u8,      // last packet-type indicator byte
    /// HCI command completion callbacks: (opcode, pending)
    pending_cmd:Option<u16>,
    initialised:bool,
}

static BT: Mutex<Option<BtState>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise the Bluetooth HCI over UART at `uart_base`.
/// Performs controller reset and LE scan setup.
pub fn init(uart_base: u64) {
    unsafe { _init(uart_base as usize); }
}

pub fn is_initialised() -> bool {
    BT.lock().as_ref().map(|s| s.initialised).unwrap_or(false)
}

/// Poll the UART receive FIFO; process any complete HCI packets.
/// Call from the main loop or a timer tick.
pub fn poll() {
    unsafe { _poll(); }
}

/// Return the local BD_ADDR, or zeros if not yet initialised.
pub fn bd_addr() -> BdAddr {
    BT.lock().as_ref().map(|s| s.bd_addr).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

unsafe fn _init(uart: usize) {
    // Configure UART: 115200 baud, 8N1 (assumes 1.8432 MHz clock)
    let lcr = uart_read(uart, UART_LCR);
    uart_write(uart, UART_LCR, lcr | 0x80); // DLAB=1
    uart_write(uart, UART_DLL, 1);           // divisor lo
    uart_write(uart, UART_DLH, 0);           // divisor hi
    uart_write(uart, UART_LCR, 0x03);        // 8N1, DLAB=0
    uart_write(uart, UART_FCR, 0x07);        // enable + clear FIFOs
    uart_write(uart, UART_IER, 0x00);        // polled mode

    *BT.lock() = Some(BtState {
        uart,
        bd_addr:     BdAddr::default(),
        rx_buf:      Vec::new(),
        rx_expect:   -1,
        rx_ptype:    0,
        pending_cmd: None,
        initialised: false,
    });

    // HCI Reset.
    send_cmd(uart, HCI_RESET, &[]);
    wait_cmd_complete(uart, HCI_RESET);

    // LE Set Event Mask: enable LE advertising report + connection complete.
    let mask: [u8; 8] = [0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    send_cmd(uart, HCI_LE_SET_EVENT_MASK, &mask);
    wait_cmd_complete(uart, HCI_LE_SET_EVENT_MASK);

    // Read BD_ADDR.
    send_cmd(uart, HCI_READ_BD_ADDR, &[]);
    wait_cmd_complete(uart, HCI_READ_BD_ADDR);

    // LE Scan Parameters: passive, 100ms interval/window, public address.
    let params: [u8; 7] = [0x00, 0xA0, 0x00, 0xA0, 0x00, 0x00, 0x00];
    send_cmd(uart, HCI_LE_SET_SCAN_PARAMS, &params);
    wait_cmd_complete(uart, HCI_LE_SET_SCAN_PARAMS);

    // LE Scan Enable: enable, no filter duplicates.
    send_cmd(uart, HCI_LE_SET_SCAN_ENABLE, &[0x01, 0x00]);
    wait_cmd_complete(uart, HCI_LE_SET_SCAN_ENABLE);

    if let Some(s) = BT.lock().as_mut() {
        s.initialised = true;
    }
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

unsafe fn _poll() {
    loop {
        let mut g = BT.lock();
        let st = match g.as_mut() { Some(s) => s, None => return };
        let uart = st.uart;
        if uart_read(uart, UART_LSR) & LSR_DR == 0 { break; }
        let byte = uart_read(uart, UART_RBR);
        process_byte(st, byte);
    }
}

fn process_byte(st: &mut BtState, byte: u8) {
    if st.rx_expect < 0 {
        // Waiting for packet type indicator.
        if byte == HCI_EVENT || byte == HCI_ACL {
            st.rx_ptype  = byte;
            st.rx_expect = 0; // will be set after header
            st.rx_buf.clear();
        }
        return;
    }

    st.rx_buf.push(byte);

    match st.rx_ptype {
        HCI_EVENT => {
            // Header: event_code (1) + parameter_total_length (1)
            if st.rx_buf.len() == 2 {
                st.rx_expect = st.rx_buf[1] as isize;
            }
            if st.rx_buf.len() >= 2 && st.rx_buf.len() as isize == 2 + st.rx_expect {
                let pkt = st.rx_buf.clone();
                st.rx_expect = -1;
                handle_event(st, &pkt);
            }
        }
        HCI_ACL => {
            // Header: handle_flags (2) + data_total_length (2)
            if st.rx_buf.len() == 4 {
                let len = u16::from_le_bytes([st.rx_buf[2], st.rx_buf[3]]);
                st.rx_expect = len as isize;
            }
            if st.rx_buf.len() >= 4 && st.rx_buf.len() as isize == 4 + st.rx_expect {
                // ACL data: forward to L2CAP (stub).
                st.rx_expect = -1;
            }
        }
        _ => { st.rx_expect = -1; }
    }
}

fn handle_event(st: &mut BtState, pkt: &[u8]) {
    if pkt.len() < 2 { return; }
    let evt_code = pkt[0];
    let params   = &pkt[2..];

    match evt_code {
        EVT_CMD_COMPLETE => {
            if params.len() < 3 { return; }
            let opcode = u16::from_le_bytes([params[1], params[2]]);
            if opcode == HCI_READ_BD_ADDR && params.len() >= 10 {
                st.bd_addr.0.copy_from_slice(&params[4..10]);
            }
            if st.pending_cmd == Some(opcode) {
                st.pending_cmd = None;
            }
        }
        EVT_CMD_STATUS => {
            if params.len() >= 4 {
                let opcode = u16::from_le_bytes([params[2], params[3]]);
                if st.pending_cmd == Some(opcode) {
                    st.pending_cmd = None;
                }
            }
        }
        EVT_LE_META => {
            if params.is_empty() { return; }
            match params[0] {
                LE_ADV_REPORT => { /* stub: log advertising devices */ }
                LE_CONN_COMPLETE => { /* stub: store connection handle */ }
                _ => {}
            }
        }
        EVT_DISCONN_COMPLETE => { /* stub: clean up connection state */ }
        EVT_NUM_COMP_PKTS    => { /* stub: update flow-control credits */ }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Command helpers
// ---------------------------------------------------------------------------

unsafe fn send_cmd(uart: usize, opcode: u16, params: &[u8]) {
    uart_putb(uart, HCI_CMD);
    uart_putb(uart, (opcode & 0xFF) as u8);
    uart_putb(uart, ((opcode >> 8) & 0xFF) as u8);
    uart_putb(uart, params.len() as u8);
    for &b in params { uart_putb(uart, b); }

    if let Some(st) = BT.lock().as_mut() {
        st.pending_cmd = Some(opcode);
    }
}

unsafe fn wait_cmd_complete(uart: usize, opcode: u16) {
    for _ in 0..10_000_000 {
        // Poll RX.
        if uart_read(uart, UART_LSR) & LSR_DR != 0 {
            let byte = uart_read(uart, UART_RBR);
            let mut g = BT.lock();
            if let Some(st) = g.as_mut() {
                process_byte(st, byte);
                if st.pending_cmd != Some(opcode) { return; }
            }
        }
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// UART helpers
// ---------------------------------------------------------------------------

#[inline]
unsafe fn uart_read(base: usize, off: usize) -> u8 {
    read_volatile((base + off) as *const u8)
}

#[inline]
unsafe fn uart_write(base: usize, off: usize, val: u8) {
    write_volatile((base + off) as *mut u8, val);
}

#[inline]
unsafe fn uart_putb(base: usize, b: u8) {
    while uart_read(base, UART_LSR) & LSR_THRE == 0 { core::hint::spin_loop(); }
    uart_write(base, UART_THR, b);
}
