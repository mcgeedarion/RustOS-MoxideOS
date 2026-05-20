//! Network interface drivers.
//!
//! ## Modules
//!   e1000e           — Intel e1000e Gigabit Ethernet
//!   nic              — NIC abstraction layer (send_frame / rx_poll_all)
//!   virtio_net       — VirtIO network device (PCIe, x86_64)
//!   virtio_net_mmio  — VirtIO network device (MMIO, RISC-V virt machine)

pub mod e1000e;
pub mod nic;
pub mod virtio_net;
pub mod virtio_net_mmio;
