//! Unix-domain socket support (AF_UNIX).
pub mod stream;

pub use stream::{unix_bind, unix_listen, unix_accept, unix_connect};