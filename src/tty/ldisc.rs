//! N_TTY line discipline.
//!
//! Sits between the raw byte stream (PTY master writes) and the
//! application's `read(2)` on the slave side.  Implements:
//!
//!   - **Canonical mode** (`ICANON`): accumulates a line buffer; delivers
//!     a complete line on `\n`, `EOF` (`^D`), or `EOL`/`EOL2`.  Supports
//!     ERASE (`DEL`/`^H`), KILL (`^U`), WERASE (`^W`).
//!   - **Raw / non-canonical mode**: passes bytes through immediately,
//!     respecting `VMIN` and `VTIME`.
//!   - **Signal generation** (`ISIG`): `VINTR` → `SIGINT` (2),
//!     `VQUIT` → `SIGQUIT` (3), `VSUSP` → `SIGTSTP` (20).
//!   - **Output processing** (`OPOST`): `ONLCR` (NL → CR+NL),
//!     `OCRNL` (CR → NL).
//!   - **Echo** back to the master's read side.
//!   - **XON/XOFF** flow control (`IXON`).

extern crate alloc;
use crate::tty::termios::{self, cc, Termios};
use alloc::vec::Vec;

/// Signal numbers delivered to the foreground process group.
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGTSTP: u8 = 20;
pub const SIGHUP: u8 = 1;

/// Maximum line buffer for canonical mode (POSIX MAX_CANON = 4096).
pub const MAX_CANON: usize = 4096;

/// Action returned by `process_input` for each input byte.
#[derive(Debug)]
pub enum LdiscAction {
    /// Byte should be appended to the read buffer (raw) or line buffer (canonical).
    Append(u8),
    /// Canonical line is complete — deliver `Vec<u8>` to the reader.
    LineReady(Vec<u8>),
    /// Erase the last byte from the line buffer.
    Erase,
    /// Kill (erase) the entire line buffer.
    Kill,
    /// Erase the last word from the line buffer.
    WerasWord,
    /// Deliver signal to the foreground process group.
    Signal(u8),
    /// XON — resume output.
    Xon,
    /// XOFF — stop output.
    Xoff,
    /// Byte was discarded (e.g. NUL in canonical, non-printing control).
    Discard,
}

/// Stateless input processor: given `termios` settings and one input byte,
/// return the `LdiscAction` the line discipline should take.
///
/// The caller (PtySlave) maintains the actual line buffer and read queue.
pub fn process_input(t: &Termios, byte: u8) -> LdiscAction {
    // ── Signal generation ──────────────────────────────────────────────────
    if t.is_isig() {
        if byte == t.c_cc[cc::VINTR] {
            return LdiscAction::Signal(SIGINT);
        }
        if byte == t.c_cc[cc::VQUIT] {
            return LdiscAction::Signal(SIGQUIT);
        }
        if byte == t.c_cc[cc::VSUSP] {
            return LdiscAction::Signal(SIGTSTP);
        }
    }

    // ── XON / XOFF ─────────────────────────────────────────────────────────
    if t.c_iflag & termios::iflag::IXON != 0 {
        if byte == t.c_cc[cc::VSTOP] {
            return LdiscAction::Xoff;
        }
        if byte == t.c_cc[cc::VSTART] {
            return LdiscAction::Xon;
        }
    }

    // ── ICRNL: translate CR → NL on input ─────────────────────────────────
    let byte = if t.is_icrnl() && byte == b'\r' {
        b'\n'
    } else {
        byte
    };

    // ── Canonical mode ─────────────────────────────────────────────────────
    if t.is_canonical() {
        // EOF (^D) — deliver whatever is in the line buffer immediately.
        if byte == t.c_cc[cc::VEOF] {
            return LdiscAction::LineReady(Vec::new()); // signal EOF with empty vec
        }
        // ERASE
        if byte == t.c_cc[cc::VERASE] || byte == 0x08 {
            return LdiscAction::Erase;
        }
        // KILL
        if byte == t.c_cc[cc::VKILL] {
            return LdiscAction::Kill;
        }
        // WERASE
        if byte == t.c_cc[cc::VWERASE] {
            return LdiscAction::WerasWord;
        }
        // Line delimiter: NL, EOL, EOL2
        if byte == b'\n' || byte == t.c_cc[cc::VEOL] || byte == t.c_cc[cc::VEOL2] {
            return LdiscAction::Append(byte); // caller flushes line on \n
        }
        return LdiscAction::Append(byte);
    }

    // ── Raw mode ───────────────────────────────────────────────────────────
    LdiscAction::Append(byte)
}

/// Output processing: apply OPOST transforms to an outgoing byte.
/// Returns one or two bytes (ONLCR expands \n → \r\n).
pub fn process_output(t: &Termios, byte: u8) -> OutputBytes {
    if !t.is_opost() {
        return OutputBytes::One(byte);
    }
    if t.is_onlcr() && byte == b'\n' {
        return OutputBytes::Two(b'\r', b'\n');
    }
    if t.c_oflag & termios::oflag::OCRNL != 0 && byte == b'\r' {
        return OutputBytes::One(b'\n');
    }
    OutputBytes::One(byte)
}

pub enum OutputBytes {
    One(u8),
    Two(u8, u8),
}
