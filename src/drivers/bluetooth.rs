//! Bluetooth HCI driver — USB transport (H2 / H4 framing over xHCI bulk+interrupt).
//!
//! ## Architecture
//!
//! ```text
//!   USB xHCI (usb.rs)
//!     └─ Bulk OUT  EP  ──► hci_send_cmd() / hci_send_acl()
//!     └─ Interrupt IN EP ─► bt_irq()  (HCI events)
//!     └─ Bulk IN  EP   ──► bt_bulk_in_irq() (ACL data)
//!
//!   HCI layer
//!     ├─ Command path:  bt_hci_reset()  bt_set_event_mask()  bt_inquiry()
//!     ├─ Event path:    EVT_CMD_COMPLETE  EVT_CONN_COMPLETE  EVT_DISCONN_COMPLETE
//!     │                 EVT_INQUIRY_RESULT  EVT_LE_META
//!     ├─ ACL path:      acl_rx_reassemble()  →  l2cap_rx()
//!     └─ LE:            LE_SET_SCAN_PARAM  LE_SET_SCAN_ENABLE  LE_CREATE_CONN
//!
//!   L2CAP
//!     └─ CID 0x0001  Signalling  (conn req / resp / config / disconnect)
//!     └─ CID 0x0004  Attribute Protocol (ATT) stub
//!     └─ CID 0x0005  LE Signalling
//!
//! ## Bluetooth class codes (USB)
//!   Class 0xE0, Subclass 0x01, Protocol 0x01  — Primary BT controller
//!
//! ## Public API
//!   bt_probe()          — USB discovery + HCI reset
//!   bt_irq()            — call from xHCI interrupt IN completion
//!   bt_bulk_in_irq()    — call from xHCI bulk IN completion
//!   bt_inquiry_start()  — begin BR/EDR inquiry scan
//!   bt_le_scan_start()  — begin LE advertisement scan
//!   bt_le_scan_stop()   — stop LE scan
//!   bt_connect()        — initiate ACL connection to BD_ADDR
//!   bt_disconnect()     — tear down connection by handle

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;
use crate::mm::pmm;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// USB class/subclass/protocol for primary Bluetooth controller.
const BT_USB_CLASS:    u8 = 0xE0;
const BT_USB_SUBCLASS: u8 = 0x01;
const BT_USB_PROTO:    u8 = 0x01;

// HCI packet indicator bytes (UART H4; also used as in-band type tags).
const HCI_CMD_PKT:   u8 = 0x01;
const HCI_ACL_PKT:   u8 = 0x02;
const HCI_SCO_PKT:   u8 = 0x03;
const HCI_EVENT_PKT: u8 = 0x04;

// ── HCI OGF / OCF codes ───────────────────────────────────────────────────────

const OGF_LINK_CTL: u16 = 0x01;
const OGF_CTRL_BB:  u16 = 0x03;
const OGF_INFO:     u16 = 0x04;
const OGF_LE:       u16 = 0x08;

// Link Control
const OCF_INQUIRY:         u16 = 0x0001;
const OCF_INQUIRY_CANCEL:  u16 = 0x0002;
const OCF_CREATE_CONN:     u16 = 0x0005;
const OCF_DISCONNECT:      u16 = 0x0006;
const OCF_ACCEPT_CONN_REQ: u16 = 0x0009;
const OCF_REJECT_CONN_REQ: u16 = 0x000A;

// Controller & Baseband
const OCF_RESET:            u16 = 0x0003;
const OCF_SET_EVENT_MASK:   u16 = 0x0001;
const OCF_WRITE_LOCAL_NAME: u16 = 0x0013;
const OCF_WRITE_SCAN_ENABLE:u16 = 0x001A;

// Informational
const OCF_READ_BD_ADDR:       u16 = 0x0009;
const OCF_READ_LOCAL_VERSION: u16 = 0x0001;

// LE Controller
const OCF_LE_SET_SCAN_PARAMS: u16 = 0x000B;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
const OCF_LE_CREATE_CONN:     u16 = 0x000D;
const OCF_LE_SET_EVENT_MASK:  u16 = 0x0001;
const OCF_LE_READ_BD_ADDR:    u16 = 0x0009;

#[inline]
const fn hci_opcode(ogf: u16, ocf: u16) -> u16 { (ogf << 10) | ocf }

// ── HCI event codes ───────────────────────────────────────────────────────────

const EVT_INQUIRY_COMPLETE:     u8 = 0x01;
const EVT_INQUIRY_RESULT:       u8 = 0x02;
const EVT_CONN_COMPLETE:        u8 = 0x03;
const EVT_CONN_REQUEST:         u8 = 0x04;
const EVT_DISCONN_COMPLETE:     u8 = 0x05;
const EVT_AUTH_COMPLETE:        u8 = 0x06;
const EVT_REMOTE_NAME_REQ_COMP: u8 = 0x07;
const EVT_CMD_COMPLETE:         u8 = 0x0E;
const EVT_CMD_STATUS:           u8 = 0x0F;
const EVT_HARDWARE_ERROR:       u8 = 0x10;
const EVT_NUM_COMP_PKTS:        u8 = 0x13;
const EVT_LE_META:              u8 = 0x3E;

// LE meta sub-event codes
const LE_META_CONN_COMPLETE:     u8 = 0x01;
const LE_META_ADV_REPORT:        u8 = 0x02;
const LE_META_CONN_UPDATE_COMPL: u8 = 0x03;
const LE_META_READ_REMOTE_FEAT:  u8 = 0x04;
const LE_META_LONG_TERM_KEY_REQ: u8 = 0x05;

// ── L2CAP CIDs ───────────────────────────────────────────────────────────────

const L2CAP_CID_SIGNALLING: u16 = 0x0001;
const L2CAP_CID_CONNLESS:   u16 = 0x0002;
const L2CAP_CID_ATT:        u16 = 0x0004;
const L2CAP_CID_LE_SIGNAL:  u16 = 0x0005;
const L2CAP_CID_SMP:        u16 = 0x0006;

// L2CAP signalling codes
const L2CAP_SIG_CONN_REQ: u8 = 0x02;
const L2CAP_SIG_CONN_RSP: u8 = 0x03;
const L2CAP_SIG_CFG_REQ:  u8 = 0x04;
const L2CAP_SIG_CFG_RSP:  u8 = 0x05;
const L2CAP_SIG_DISC_REQ: u8 = 0x06;
const L2CAP_SIG_DISC_RSP: u8 = 0x07;
const L2CAP_SIG_ECHO_REQ: u8 = 0x08;
const L2CAP_SIG_ECHO_RSP: u8 = 0x09;
const L2CAP_SIG_INFO_REQ: u8 = 0x0A;
const L2CAP_SIG_INFO_RSP: u8 = 0x0B;

// ── Buffer sizes ──────────────────────────────────────────────────────────────

const HCI_MAX_CMD_LEN:  usize = 256;
const HCI_MAX_EVT_LEN:  usize = 256;
const HCI_MAX_ACL_LEN:  usize = 1024;
const MAX_CONNECTIONS:  usize = 8;
const BD_ADDR_LEN:      usize = 6;
const MAX_SCAN_RESULTS: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

/// BD_ADDR — 6-byte Bluetooth device address (little-endian on wire).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct BdAddr(pub [u8; BD_ADDR_LEN]);

impl BdAddr {
    pub const fn zero() -> Self { Self([0u8; BD_ADDR_LEN]) }
    pub fn is_zero(&self) -> bool { self.0 == [0u8; BD_ADDR_LEN] }
}

impl core::fmt::Display for BdAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = &self.0;
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
               b[5], b[4], b[3], b[2], b[1], b[0])
    }
}

/// HCI connection state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Free,
    Connecting,
    Connected,
    Disconnecting,
}

/// A single ACL connection slot.
#[derive(Clone, Copy)]
pub struct AclConn {
    pub handle:   u16,
    pub addr:     BdAddr,
    pub state:    ConnState,
    /// Reassembly buffer for fragmented L2CAP frames.
    pub rx_buf:   [u8; HCI_MAX_ACL_LEN],
    pub rx_len:   usize,
    pub rx_total: usize,
}

impl AclConn {
    const fn zeroed() -> Self {
        Self {
            handle: 0, addr: BdAddr::zero(), state: ConnState::Free,
            rx_buf: [0u8; HCI_MAX_ACL_LEN], rx_len: 0, rx_total: 0,
        }
    }
}

/// LE advertisement report.
#[derive(Clone, Copy)]
pub struct AdvReport {
    pub addr:      BdAddr,
    pub addr_type: u8,
    pub evt_type:  u8,
    pub rssi:      i8,
    pub data:      [u8; 31],
    pub data_len:  u8,
}

impl AdvReport {
    const fn zeroed() -> Self {
        Self {
            addr: BdAddr::zero(), addr_type: 0, evt_type: 0,
            rssi: 0, data: [0u8; 31], data_len: 0,
        }
    }
}

/// Sequenced HCI initialisation state machine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InitStep {
    Idle,
    WaitReset,
    WaitSetEventMask,
    WaitLeSetEventMask,
    WaitReadBdAddr,
    WaitWriteScanEnable,
    Done,
}

/// Global Bluetooth controller state.
struct BtController {
    ready:       bool,
    local_addr:  BdAddr,
    conns:       [AclConn; MAX_CONNECTIONS],
    scan_results:[AdvReport; MAX_SCAN_RESULTS],
    scan_count:  usize,
    num_hci_cmds:u8,
    init_step:   InitStep,
    cmd_buf:     [u8; HCI_MAX_CMD_LEN],
    evt_buf:     [u8; HCI_MAX_EVT_LEN],
    evt_pos:     usize,
}

unsafe impl Send for BtController {}
unsafe impl Sync for BtController {}

impl BtController {
    const fn zeroed() -> Self {
        const CONN_INIT: AclConn   = AclConn::zeroed();
        const ADV_INIT:  AdvReport = AdvReport::zeroed();
        Self {
            ready: false,
            local_addr: BdAddr::zero(),
            conns: [CONN_INIT; MAX_CONNECTIONS],
            scan_results: [ADV_INIT; MAX_SCAN_RESULTS],
            scan_count: 0,
            num_hci_cmds: 1,
            init_step: InitStep::Idle,
            cmd_buf: [0u8; HCI_MAX_CMD_LEN],
            evt_buf: [0u8; HCI_MAX_EVT_LEN],
            evt_pos: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// USB transport glue  (xHCI endpoint handles)
// ─────────────────────────────────────────────────────────────────────────────

/// USB slot ID for the Bluetooth dongle (0 = not assigned).
static BT_USB_SLOT: AtomicU16  = AtomicU16::new(0);
/// True once the controller has been enumerated and reset.
static BT_READY:    AtomicBool = AtomicBool::new(false);
/// Global controller state.
static BT: Mutex<BtController> = Mutex::new(BtController::zeroed());

// ─────────────────────────────────────────────────────────────────────────────
// PMM helper
// ─────────────────────────────────────────────────────────────────────────────

#[allow(unused)]
unsafe fn alloc_zeroed(bytes: usize) -> *mut u8 {
    let pages = (bytes + 4095) / 4096;
    let pa = pmm::alloc_pages(pages).expect("bt: OOM");
    core::slice::from_raw_parts_mut(pa as *mut u8, pages * 4096).fill(0);
    pa as *mut u8
}

// ─────────────────────────────────────────────────────────────────────────────
// HCI command builder / sender
// ─────────────────────────────────────────────────────────────────────────────

/// Write an HCI command packet into `buf` and return the total byte length.
/// Layout: opcode(2) | param_total_len(1) | params...
fn build_hci_cmd(buf: &mut [u8], opcode: u16, params: &[u8]) -> usize {
    assert!(params.len() <= 255);
    buf[0] = (opcode & 0xFF) as u8;
    buf[1] = (opcode >> 8)   as u8;
    buf[2] = params.len()    as u8;
    buf[3..3 + params.len()].copy_from_slice(params);
    3 + params.len()
}

/// Transmit an HCI command over USB.
/// BT spec §7: commands go on the USB control endpoint (EP0).
/// We route through a bulk-out hook so xHCI can queue the TRB.
pub fn hci_send_cmd(opcode: u16, params: &[u8]) {
    let slot = BT_USB_SLOT.load(Ordering::Relaxed) as usize;
    if slot == 0 { return; }
    let mut bt = BT.lock();
    if bt.num_hci_cmds == 0 { return; }
    bt.num_hci_cmds -= 1;
    let len = build_hci_cmd(&mut bt.cmd_buf, opcode, params);
    // SAFETY: cmd_buf owned for this scope; USB layer copies before return.
    unsafe { usb_bulk_out_submit(slot, &bt.cmd_buf[..len]); }
}

/// Transmit an HCI ACL data packet.
pub fn hci_send_acl(handle: u16, pb: u8, bc: u8, payload: &[u8]) {
    let slot = BT_USB_SLOT.load(Ordering::Relaxed) as usize;
    if slot == 0 { return; }
    let total = 4 + payload.len();
    let mut buf = [0u8; HCI_MAX_ACL_LEN + 4];
    buf[0] = (handle & 0xFF) as u8;
    buf[1] = ((handle >> 8) & 0x0F) as u8 | ((pb & 0x3) << 4) | ((bc & 0x3) << 6);
    buf[2] = (payload.len() & 0xFF) as u8;
    buf[3] = (payload.len() >> 8)   as u8;
    buf[4..4 + payload.len()].copy_from_slice(payload);
    unsafe { usb_bulk_out_submit(slot, &buf[..total]); }
}

/// Stub: wire to `crate::drivers::usb::xhci_bulk_out_submit(slot, data)`
/// once the xHCI driver exposes that function.
#[allow(unused_variables)]
unsafe fn usb_bulk_out_submit(slot: usize, data: &[u8]) {
    // TODO: queue a Normal TRB on the bulk-out transfer ring for `slot`,
    //       copy `data` to a DMA buffer, ring EP doorbell.
    //       Wire-up: crate::drivers::usb::xhci_bulk_out_submit(slot, data)
    crate::println!("bt: TX {} bytes (slot {})", data.len(), slot);
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe
// ─────────────────────────────────────────────────────────────────────────────

/// Scan USB devices and initialise the first Bluetooth dongle found.
/// Call after `xhci_probe()` has enumerated all ports.
pub fn bt_probe() {
    let slot = match find_bt_usb_slot() {
        Some(s) => s,
        None    => {
            crate::println!("bt: no Bluetooth USB dongle found");
            return;
        }
    };
    crate::println!("bt: found controller at xHCI slot {}", slot);
    BT_USB_SLOT.store(slot as u16, Ordering::Relaxed);
    BT.lock().init_step = InitStep::WaitReset;
    bt_hci_reset();
}

/// Walk the xHCI slot table for USB class 0xE0/0x01/0x01.
/// Returns the slot index or None.
fn find_bt_usb_slot() -> Option<usize> {
    // TODO: replace stub with:
    //   crate::drivers::usb::find_slot_by_class(BT_USB_CLASS, BT_USB_SUBCLASS, BT_USB_PROTO)
    // That requires adding a `find_slot_by_class` export to usb.rs that
    // iterates the XHCI.slots array and checks the stored interface class.
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// HCI init state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Step 1 — HCI Reset.
pub fn bt_hci_reset() {
    hci_send_cmd(hci_opcode(OGF_CTRL_BB, OCF_RESET), &[]);
}

/// Step 2 — Set event mask (all standard events enabled).
fn bt_set_event_mask() {
    // 0xFF FF FB FF 07 F8 BF 3D — enable all except reserved bits
    let mask: [u8; 8] = [0xFF, 0xFF, 0xFB, 0xFF, 0x07, 0xF8, 0xBF, 0x3D];
    hci_send_cmd(hci_opcode(OGF_CTRL_BB, OCF_SET_EVENT_MASK), &mask);
}

/// Step 3 — LE Set Event Mask.
fn bt_le_set_event_mask() {
    let mask: [u8; 8] = [0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    hci_send_cmd(hci_opcode(OGF_LE, OCF_LE_SET_EVENT_MASK), &mask);
}

/// Step 4 — Read BD_ADDR.
fn bt_read_bd_addr() {
    hci_send_cmd(hci_opcode(OGF_INFO, OCF_READ_BD_ADDR), &[]);
}

/// Step 5 — Write Scan Enable (inquiry + page scan).
fn bt_write_scan_enable() {
    hci_send_cmd(hci_opcode(OGF_CTRL_BB, OCF_WRITE_SCAN_ENABLE), &[0x03]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Begin a BR/EDR inquiry scan (~10 seconds, unlimited results).
pub fn bt_inquiry_start() {
    if !BT_READY.load(Ordering::Relaxed) { return; }
    // LAP = 0x9E8B33 (GIAC), length = 0x08 (~10s), num_responses = 0 (unlimited)
    let params: [u8; 5] = [0x33, 0x8B, 0x9E, 0x08, 0x00];
    hci_send_cmd(hci_opcode(OGF_LINK_CTL, OCF_INQUIRY), &params);
    crate::println!("bt: BR/EDR inquiry started");
}

/// Begin passive LE advertisement scanning.
pub fn bt_le_scan_start() {
    if !BT_READY.load(Ordering::Relaxed) { return; }
    // passive, interval=10ms, window=10ms, own=public, filter=none
    let params: [u8; 7] = [0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00];
    hci_send_cmd(hci_opcode(OGF_LE, OCF_LE_SET_SCAN_PARAMS), &params);
    hci_send_cmd(hci_opcode(OGF_LE, OCF_LE_SET_SCAN_ENABLE), &[0x01, 0x00]);
    crate::println!("bt: LE scan started");
}

/// Stop LE scanning.
pub fn bt_le_scan_stop() {
    hci_send_cmd(hci_opcode(OGF_LE, OCF_LE_SET_SCAN_ENABLE), &[0x00, 0x00]);
    crate::println!("bt: LE scan stopped");
}

/// Initiate an ACL connection to `addr`.
pub fn bt_connect(addr: BdAddr) {
    if !BT_READY.load(Ordering::Relaxed) { return; }
    let mut p = [0u8; 13];
    p[0..6].copy_from_slice(&addr.0);
    p[6]  = 0x18; // packet type low
    p[7]  = 0xCC; // packet type high
    p[8]  = 0x01; // page scan rep mode R1
    p[9]  = 0x00; // reserved
    p[10] = 0x00; // clock offset low
    p[11] = 0x00; // clock offset high
    p[12] = 0x01; // allow role switch
    hci_send_cmd(hci_opcode(OGF_LINK_CTL, OCF_CREATE_CONN), &p);
    crate::println!("bt: connecting to {}", addr);
    let mut bt = BT.lock();
    if let Some(slot) = bt.conns.iter_mut().find(|c| c.state == ConnState::Free) {
        slot.addr  = addr;
        slot.state = ConnState::Connecting;
    }
}

/// Disconnect by ACL handle.
pub fn bt_disconnect(handle: u16) {
    let params: [u8; 3] = [
        (handle & 0xFF) as u8,
        (handle >> 8)   as u8,
        0x13, // Remote User Terminated
    ];
    hci_send_cmd(hci_opcode(OGF_LINK_CTL, OCF_DISCONNECT), &params);
    let mut bt = BT.lock();
    if let Some(conn) = bt.conns.iter_mut().find(|c| c.handle == handle) {
        conn.state = ConnState::Disconnecting;
    }
}

/// Return a snapshot of LE scan results.
pub fn bt_le_scan_results() -> ([AdvReport; MAX_SCAN_RESULTS], usize) {
    let bt = BT.lock();
    (bt.scan_results, bt.scan_count)
}

// ─────────────────────────────────────────────────────────────────────────────
// IRQ handlers  (called from xHCI interrupt/bulk-in completions)
// ─────────────────────────────────────────────────────────────────────────────

/// Called by xHCI when an interrupt-IN TRB completes for a BT slot.
/// `data` is the raw HCI event packet (without H4 type byte).
pub fn bt_irq(data: &[u8]) {
    if data.len() < 2 { return; }
    let evt_code = data[0];
    let params   = if data.len() > 2 { &data[2..] } else { &[] };
    handle_hci_event(evt_code, params);
}

/// Called by xHCI when a bulk-IN TRB completes for a BT slot.
/// `data` is the raw HCI ACL packet (without H4 type byte).
pub fn bt_bulk_in_irq(data: &[u8]) {
    if data.len() < 4 { return; }
    let handle_flags = u16::from_le_bytes([data[0], data[1]]);
    let handle   = handle_flags & 0x0FFF;
    let pb       = (handle_flags >> 12) & 0x3;
    let data_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + data_len { return; }
    acl_rx(handle, pb, &data[4..4 + data_len]);
}

// ─────────────────────────────────────────────────────────────────────────────
// HCI event dispatcher
// ─────────────────────────────────────────────────────────────────────────────

fn handle_hci_event(code: u8, params: &[u8]) {
    match code {
        EVT_CMD_COMPLETE     => on_cmd_complete(params),
        EVT_CMD_STATUS       => on_cmd_status(params),
        EVT_CONN_COMPLETE    => on_conn_complete(params),
        EVT_CONN_REQUEST     => on_conn_request(params),
        EVT_DISCONN_COMPLETE => on_disconn_complete(params),
        EVT_INQUIRY_RESULT   => on_inquiry_result(params),
        EVT_INQUIRY_COMPLETE => on_inquiry_complete(params),
        EVT_NUM_COMP_PKTS    => on_num_comp_pkts(params),
        EVT_HARDWARE_ERROR   => crate::println!("bt: hardware error 0x{:02X}", params.get(0).copied().unwrap_or(0)),
        EVT_LE_META          => on_le_meta(params),
        other                => crate::println!("bt: unhandled event 0x{:02X}", other),
    }
}

/// EVT_CMD_COMPLETE — drives the sequenced HCI init state machine.
fn on_cmd_complete(params: &[u8]) {
    if params.len() < 3 { return; }
    let num_cmds = params[0];
    let opcode   = u16::from_le_bytes([params[1], params[2]]);
    let status   = params.get(3).copied().unwrap_or(0xFF);
    BT.lock().num_hci_cmds = num_cmds;
    if status != 0 {
        crate::println!("bt: cmd 0x{:04X} failed status=0x{:02X}", opcode, status);
        return;
    }
    let step = BT.lock().init_step;
    match (step, opcode) {
        (InitStep::WaitReset, op) if op == hci_opcode(OGF_CTRL_BB, OCF_RESET) => {
            BT.lock().init_step = InitStep::WaitSetEventMask;
            bt_set_event_mask();
        }
        (InitStep::WaitSetEventMask, op) if op == hci_opcode(OGF_CTRL_BB, OCF_SET_EVENT_MASK) => {
            BT.lock().init_step = InitStep::WaitLeSetEventMask;
            bt_le_set_event_mask();
        }
        (InitStep::WaitLeSetEventMask, op) if op == hci_opcode(OGF_LE, OCF_LE_SET_EVENT_MASK) => {
            BT.lock().init_step = InitStep::WaitReadBdAddr;
            bt_read_bd_addr();
        }
        (InitStep::WaitReadBdAddr, op) if op == hci_opcode(OGF_INFO, OCF_READ_BD_ADDR) => {
            if params.len() >= 10 {
                let mut addr = BdAddr::zero();
                addr.0.copy_from_slice(&params[4..10]);
                crate::println!("bt: local BD_ADDR = {}", addr);
                BT.lock().local_addr = addr;
            }
            BT.lock().init_step = InitStep::WaitWriteScanEnable;
            bt_write_scan_enable();
        }
        (InitStep::WaitWriteScanEnable, op) if op == hci_opcode(OGF_CTRL_BB, OCF_WRITE_SCAN_ENABLE) => {
            BT.lock().init_step = InitStep::Done;
            BT_READY.store(true, Ordering::Release);
            crate::println!("bt: controller ready");
        }
        _ => {}
    }
}

fn on_cmd_status(params: &[u8]) {
    if params.len() < 4 { return; }
    let status   = params[0];
    let num_cmds = params[1];
    let opcode   = u16::from_le_bytes([params[2], params[3]]);
    BT.lock().num_hci_cmds = num_cmds;
    if status != 0 {
        crate::println!("bt: cmd_status opcode=0x{:04X} status=0x{:02X}", opcode, status);
    }
}

fn on_conn_complete(params: &[u8]) {
    if params.len() < 11 { return; }
    let status = params[0];
    let handle = u16::from_le_bytes([params[1], params[2]]);
    let mut addr = BdAddr::zero();
    addr.0.copy_from_slice(&params[3..9]);
    if status != 0 {
        crate::println!("bt: connection to {} failed status=0x{:02X}", addr, status);
        let mut bt = BT.lock();
        if let Some(c) = bt.conns.iter_mut().find(|c| c.addr == addr) { c.state = ConnState::Free; }
        return;
    }
    crate::println!("bt: connected to {} handle=0x{:04X}", addr, handle);
    let mut bt = BT.lock();
    if let Some(c) = bt.conns.iter_mut()
        .find(|c| c.addr == addr || c.state == ConnState::Connecting)
    {
        c.handle = handle;
        c.addr   = addr;
        c.state  = ConnState::Connected;
    }
}

fn on_conn_request(params: &[u8]) {
    if params.len() < 10 { return; }
    let mut addr = BdAddr::zero();
    addr.0.copy_from_slice(&params[0..6]);
    crate::println!("bt: incoming connection request from {}", addr);
    let mut p = [0u8; 7];
    p[0..6].copy_from_slice(&addr.0);
    p[6] = 0x01; // role: slave
    hci_send_cmd(hci_opcode(OGF_LINK_CTL, OCF_ACCEPT_CONN_REQ), &p);
}

fn on_disconn_complete(params: &[u8]) {
    if params.len() < 4 { return; }
    let handle = u16::from_le_bytes([params[1], params[2]]);
    let reason = params[3];
    crate::println!("bt: disconnected handle=0x{:04X} reason=0x{:02X}", handle, reason);
    let mut bt = BT.lock();
    if let Some(c) = bt.conns.iter_mut().find(|c| c.handle == handle) {
        *c = AclConn::zeroed();
    }
}

fn on_inquiry_result(params: &[u8]) {
    if params.is_empty() { return; }
    let num = params[0] as usize;
    for i in 0..num {
        let off = 1 + i * 14;
        if off + 6 > params.len() { break; }
        let mut addr = BdAddr::zero();
        addr.0.copy_from_slice(&params[off..off + 6]);
        crate::println!("bt: inquiry result [{}] addr={}", i, addr);
    }
}

fn on_inquiry_complete(params: &[u8]) {
    let status = params.get(0).copied().unwrap_or(0);
    crate::println!("bt: inquiry complete status=0x{:02X}", status);
}

fn on_num_comp_pkts(_params: &[u8]) {
    // Re-credits host ACL flow control — extend when tracking per-conn quotas.
}

fn on_le_meta(params: &[u8]) {
    if params.is_empty() { return; }
    match params[0] {
        LE_META_CONN_COMPLETE    => on_le_conn_complete(&params[1..]),
        LE_META_ADV_REPORT       => on_le_adv_report(&params[1..]),
        LE_META_CONN_UPDATE_COMPL => {}
        other => crate::println!("bt: LE meta sub-event 0x{:02X}", other),
    }
}

fn on_le_conn_complete(params: &[u8]) {
    if params.len() < 18 { return; }
    let status = params[0];
    let handle = u16::from_le_bytes([params[1], params[2]]);
    let mut addr = BdAddr::zero();
    addr.0.copy_from_slice(&params[4..10]);
    if status != 0 {
        crate::println!("bt: LE connection failed status=0x{:02X}", status);
        return;
    }
    crate::println!("bt: LE connected addr={} handle=0x{:04X}", addr, handle);
    let mut bt = BT.lock();
    if let Some(c) = bt.conns.iter_mut().find(|c| c.state == ConnState::Free) {
        c.handle = handle;
        c.addr   = addr;
        c.state  = ConnState::Connected;
    }
}

fn on_le_adv_report(params: &[u8]) {
    if params.len() < 2 { return; }
    let num = params[0] as usize;
    let mut pos = 1usize;
    for _ in 0..num {
        if pos + 9 > params.len() { break; }
        let evt_type  = params[pos]; pos += 1;
        let addr_type = params[pos]; pos += 1;
        let mut addr = BdAddr::zero();
        addr.0.copy_from_slice(&params[pos..pos + 6]); pos += 6;
        let data_len = params[pos] as usize; pos += 1;
        if pos + data_len + 1 > params.len() { break; }
        let rssi = params[pos + data_len] as i8;

        let mut report = AdvReport::zeroed();
        report.addr      = addr;
        report.addr_type = addr_type;
        report.evt_type  = evt_type;
        report.rssi      = rssi;
        report.data_len  = data_len as u8;
        let copy_len = data_len.min(31);
        report.data[..copy_len].copy_from_slice(&params[pos..pos + copy_len]);
        pos += data_len + 1;

        crate::println!("bt: LE adv addr={} rssi={} dBm", addr, rssi);

        let mut bt = BT.lock();
        if bt.scan_count < MAX_SCAN_RESULTS {
            if !bt.scan_results[..bt.scan_count].iter().any(|r| r.addr == addr) {
                bt.scan_results[bt.scan_count] = report;
                bt.scan_count += 1;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ACL reassembly
// ─────────────────────────────────────────────────────────────────────────────

fn acl_rx(handle: u16, pb: u8, payload: &[u8]) {
    let mut bt = BT.lock();
    let conn = match bt.conns.iter_mut()
        .find(|c| c.handle == handle && c.state == ConnState::Connected)
    {
        Some(c) => c,
        None    => return,
    };
    match pb {
        0b10 => {
            // First fragment — read L2CAP length from header.
            if payload.len() < 4 { return; }
            let l2cap_len  = u16::from_le_bytes([payload[0], payload[1]]) as usize;
            conn.rx_total  = 4 + l2cap_len;
            conn.rx_len    = payload.len().min(conn.rx_total);
            conn.rx_buf[..conn.rx_len].copy_from_slice(&payload[..conn.rx_len]);
        }
        0b01 => {
            // Continuation fragment.
            let remaining = conn.rx_total.saturating_sub(conn.rx_len);
            let copy      = payload.len().min(remaining);
            conn.rx_buf[conn.rx_len..conn.rx_len + copy].copy_from_slice(&payload[..copy]);
            conn.rx_len  += copy;
        }
        _ => return,
    }
    if conn.rx_len >= conn.rx_total && conn.rx_total >= 4 {
        let frame: [u8; HCI_MAX_ACL_LEN] = conn.rx_buf;
        let frame_len   = conn.rx_total;
        let handle_copy = handle;
        conn.rx_len   = 0;
        conn.rx_total = 0;
        drop(bt);
        l2cap_rx(handle_copy, &frame[..frame_len]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// L2CAP
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch a complete L2CAP PDU.
fn l2cap_rx(handle: u16, frame: &[u8]) {
    if frame.len() < 4 { return; }
    let pdu_len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
    let cid     = u16::from_le_bytes([frame[2], frame[3]]);
    let payload = &frame[4..4 + pdu_len.min(frame.len().saturating_sub(4))];
    match cid {
        L2CAP_CID_SIGNALLING => l2cap_signal(handle, payload, false),
        L2CAP_CID_LE_SIGNAL  => l2cap_signal(handle, payload, true),
        L2CAP_CID_ATT        => l2cap_att(handle, payload),
        _                    => crate::println!("bt: l2cap unhandled CID 0x{:04X}", cid),
    }
}

fn l2cap_signal(handle: u16, data: &[u8], le: bool) {
    if data.len() < 4 { return; }
    let code  = data[0];
    let ident = data[1];
    let dlen  = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + dlen { return; }
    let params = &data[4..4 + dlen];
    let sig_cid = if le { L2CAP_CID_LE_SIGNAL } else { L2CAP_CID_SIGNALLING };
    match code {
        L2CAP_SIG_CONN_REQ => {
            if params.len() < 4 { return; }
            let psm     = u16::from_le_bytes([params[0], params[1]]);
            let src_cid = u16::from_le_bytes([params[2], params[3]]);
            crate::println!("bt: L2CAP conn req PSM=0x{:04X} src_cid=0x{:04X}", psm, src_cid);
            let rsp: [u8; 12] = [
                L2CAP_SIG_CONN_RSP, ident, 8, 0,
                src_cid as u8, (src_cid >> 8) as u8,
                src_cid as u8, (src_cid >> 8) as u8,
                0, 0, 0, 0, // result=0 (success), status=0
            ];
            l2cap_send(handle, sig_cid, &rsp);
        }
        L2CAP_SIG_DISC_REQ => {
            if params.len() < 4 { return; }
            let dcid = u16::from_le_bytes([params[0], params[1]]);
            let scid = u16::from_le_bytes([params[2], params[3]]);
            crate::println!("bt: L2CAP disc req dcid=0x{:04X}", dcid);
            let rsp: [u8; 8] = [
                L2CAP_SIG_DISC_RSP, ident, 4, 0,
                dcid as u8, (dcid >> 8) as u8,
                scid as u8, (scid >> 8) as u8,
            ];
            l2cap_send(handle, sig_cid, &rsp);
        }
        L2CAP_SIG_ECHO_REQ => {
            let mut rsp = [0u8; 260];
            rsp[0] = L2CAP_SIG_ECHO_RSP;
            rsp[1] = ident;
            rsp[2] = params.len() as u8;
            rsp[3] = (params.len() >> 8) as u8;
            rsp[4..4 + params.len()].copy_from_slice(params);
            l2cap_send(handle, sig_cid, &rsp[..4 + params.len()]);
        }
        other => crate::println!("bt: L2CAP sig code=0x{:02X} le={}", other, le),
    }
}

/// Minimal ATT stub — returns ATT_ERROR_RSP (Request Not Supported) for all ops.
fn l2cap_att(handle: u16, data: &[u8]) {
    if data.is_empty() { return; }
    let opcode = data[0];
    crate::println!("bt: ATT opcode=0x{:02X}", opcode);
    // ATT_ERROR_RSP: 0x01 | req_opcode | handle(2) | error_code
    let rsp: [u8; 5] = [0x01, opcode, 0x00, 0x00, 0x06 /* Request Not Supported */];
    l2cap_send(handle, L2CAP_CID_ATT, &rsp);
}

/// Build and send an L2CAP PDU over ACL.
fn l2cap_send(handle: u16, cid: u16, payload: &[u8]) {
    let mut frame = [0u8; HCI_MAX_ACL_LEN];
    let pdu_len = payload.len();
    frame[0] = (pdu_len & 0xFF) as u8;
    frame[1] = (pdu_len >> 8)   as u8;
    frame[2] = (cid & 0xFF)     as u8;
    frame[3] = (cid >> 8)       as u8;
    frame[4..4 + pdu_len].copy_from_slice(payload);
    hci_send_acl(handle, 0b10 /* first+complete */, 0, &frame[..4 + pdu_len]);
}
