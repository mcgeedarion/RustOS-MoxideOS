//! N_TTY line discipline.

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
    Append(u8),
    LineReady(Vec<u8>),
    Erase,
    Kill,
    WerasWord,
    Signal(u8),
    Xon,
    Xoff,
    Discard,
}

/// Stateless input processor: given `termios` settings and one input byte,
/// return the `LdiscAction` the line discipline should take.
pub fn process_input(t: &Termios, byte: u8) -> LdiscAction {
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

    if t.c_iflag & termios::iflag::IXON != 0 {
        if byte == t.c_cc[cc::VSTOP] {
            return LdiscAction::Xoff;
        }
        if byte == t.c_cc[cc::VSTART] {
            return LdiscAction::Xon;
        }
    }

    let byte = if t.is_icrnl() && byte == b'\r' {
        b'\n'
    } else {
        byte
    };

    if t.is_canonical() {
        // EOF (^D) — deliver whatever is in the line buffer immediately.
        if byte == t.c_cc[cc::VEOF] {
            return LdiscAction::LineReady(Vec::new()); // signal EOF with empty
                                                       // vec
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
