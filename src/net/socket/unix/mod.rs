//! Unix-domain socket support (AF_UNIX).
pub mod stream;

pub use stream::{unix_accept, unix_bind, unix_connect, unix_listen};
