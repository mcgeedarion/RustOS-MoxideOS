//! TCP socket state helpers.
use super::super::types::SocketState;

pub fn is_connected(state: &SocketState) -> bool {
    matches!(state, SocketState::Connected)
}

pub fn is_listening(state: &SocketState) -> bool {
    matches!(state, SocketState::Listening)
}
