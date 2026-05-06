//! Ethernet frame layer — stub.

/// 6-byte MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const ZERO: Self = MacAddr([0u8; 6]);
    pub const BROADCAST: Self = MacAddr([0xFF; 6]);
}
