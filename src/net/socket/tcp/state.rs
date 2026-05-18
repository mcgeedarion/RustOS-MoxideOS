#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    Established,
    CloseWait,
    FinWait1,
    Closing,
    TimeWait,
    LastAck,
}
