//! Wayland protocol server.
//!
//! Accepts client connections over a Unix domain socket and dispatches
//! Wayland protocol messages to the compositor.

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Connecting,
    Active,
    Disconnecting,
    Dead,
}

pub struct WaylandClient {
    pub id: u32,
    pub state: ClientState,
    pub surface_ids: Vec<u32>,
}

impl WaylandClient {
    pub fn new(id: u32) -> Self {
        Self { id, state: ClientState::Connecting, surface_ids: Vec::new() }
    }

    pub fn activate(&mut self) {
        self.state = ClientState::Active;
    }

    pub fn disconnect(&mut self) {
        self.state = ClientState::Disconnecting;
    }

    pub fn is_active(&self) -> bool {
        self.state == ClientState::Active
    }
}

pub struct WaylandServer {
    clients: Vec<WaylandClient>,
    next_client_id: u32,
}

impl WaylandServer {
    pub fn new() -> Self {
        Self { clients: Vec::new(), next_client_id: 1 }
    }

    pub fn connect_client(&mut self) -> u32 {
        let id = self.next_client_id;
        self.next_client_id += 1;
        let mut client = WaylandClient::new(id);
        client.activate();
        self.clients.push(client);
        id
    }

    pub fn disconnect_client(&mut self, id: u32) {
        if let Some(c) = self.clients.iter_mut().find(|c| c.id == id) {
            c.disconnect();
        }
    }

    pub fn active_clients(&self) -> impl Iterator<Item = &WaylandClient> {
        self.clients.iter().filter(|c| c.is_active())
    }

    pub fn purge_dead_clients(&mut self) {
        self.clients.retain(|c| c.state != ClientState::Dead);
    }
}
