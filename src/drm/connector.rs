//! Connector management.
//!
//! A connector represents a physical display output port. It reports
//! connection status and the list of modes supported by the attached display.

use super::DisplayMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorType {
    Unknown,
    Vga,
    DviI,
    DviD,
    DviA,
    Composite,
    Hdmia,
    Hdmib,
    DisplayPort,
    Lvds,
    Component,
    Virtual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Unknown,
}

pub struct Connector {
    pub id: u32,
    pub connector_type: ConnectorType,
    pub status: ConnectionStatus,
    pub modes: &'static [DisplayMode],
}

impl Connector {
    pub fn new(
        id: u32,
        connector_type: ConnectorType,
        status: ConnectionStatus,
        modes: &'static [DisplayMode],
    ) -> Self {
        Self {
            id,
            connector_type,
            status,
            modes,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.status == ConnectionStatus::Connected
    }
}
