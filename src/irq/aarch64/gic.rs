//! Minimal GICv2/GICv3 abstraction used during ARM64 bring-up.

#![allow(dead_code)]

use crate::arch::aarch64::mem_layout::gic as defaults;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GicVersion {
    V2,
    V3,
}

#[derive(Clone, Copy, Debug)]
pub struct GicConfig {
    pub version: GicVersion,
    pub distributor: usize,
    pub cpu_interface: Option<usize>,
    pub redistributor: Option<usize>,
}

impl GicConfig {
    pub const fn qemu_virt_v2() -> Self {
        Self {
            version: GicVersion::V2,
            distributor: defaults::GICV2_DIST_BASE,
            cpu_interface: Some(defaults::GICV2_CPU_BASE),
            redistributor: None,
        }
    }

    pub const fn qemu_virt_v3() -> Self {
        Self {
            version: GicVersion::V3,
            distributor: defaults::GICV3_DIST_BASE,
            cpu_interface: None,
            redistributor: Some(defaults::GICV3_REDIST_BASE),
        }
    }
}

static mut CONFIG: Option<GicConfig> = None;

pub fn init(config: GicConfig) {
    unsafe {
        CONFIG = Some(config);
    }
    match config.version {
        GicVersion::V2 => init_v2(config),
        GicVersion::V3 => init_v3(config),
    }
}

pub fn current_config() -> Option<GicConfig> {
    unsafe { CONFIG }
}

fn init_v2(config: GicConfig) {
    let dist = config.distributor as *mut u32;
    let cpu = config
        .cpu_interface
        .expect("GICv2 requires CPU interface base") as *mut u32;
    unsafe {
        // GICD_CTLR.EnableGrp0/1, GICC_CTLR.EnableGrp0/1, priority mask all.
        dist.add(0).write_volatile(0x3);
        cpu.add(0).write_volatile(0x3);
        cpu.add(1).write_volatile(0xff);
    }
}

fn init_v3(config: GicConfig) {
    let dist = config.distributor as *mut u32;
    unsafe {
        // Enable distributor groups. Redistributor wake-up and ICC_*_EL1 setup
        // are platform/EL-state dependent and will be extended as ACPI/DT CPU
        // discovery comes online.
        dist.add(0).write_volatile(0x3);
        core::arch::asm!(
            "msr ICC_PMR_EL1, {pmr}",
            "msr ICC_IGRPEN1_EL1, {enable}",
            pmr = in(reg) 0xffusize,
            enable = in(reg) 1usize,
            options(nostack),
        );
    }
}

pub fn eoi(irq: u32) {
    if let Some(config) = current_config() {
        match config.version {
            GicVersion::V2 => unsafe {
                let cpu = config.cpu_interface.unwrap() as *mut u32;
                cpu.add(4).write_volatile(irq);
            },
            GicVersion::V3 => unsafe {
                core::arch::asm!("msr ICC_EOIR1_EL1, {irq}", irq = in(reg) irq as usize, options(nostack));
            },
        }
    }
}
