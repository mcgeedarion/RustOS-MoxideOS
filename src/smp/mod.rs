//! SMP subsystem — CPU topology, AP bringup, per-CPU orchestration.
//!
//! Boot sequence (x86_64):
//!   BSP: kernel_main → smp::init() → enumerate MADTs →
//! ap_boot::start_all_aps()   AP:  trampoline (real→long) → ap_entry() →
//! percpu_init() → scheduler::ap_idle()
//!
//! Boot sequence (RISC-V):
//!   Hart 0: kernel_main → smp::init() → sbi_hsm_hart_start() per hart
//!   AP hart: ap_entry() → percpu_init() → scheduler::ap_idle()

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub mod ipi;
pub mod percpu;

/// Maximum CPUs this build supports.
pub const MAX_CPUS: usize = 256;

/// Global count of CPUs that have completed bringup and are online.
pub static ONLINE_CPUS: AtomicU32 = AtomicU32::new(0);

/// Set to true by BSP once all subsystems are ready for APs to proceed.
pub static AP_GO: AtomicBool = AtomicBool::new(false);

/// Heterogeneous core classification (big.LITTLE / Intel P+E).
/// Populated from MADT GICC cpu-capacity (ARM64) or CPUID (x86 hybrid).
/// Defaults to `Performance` on homogeneous platforms so
/// `perf_core_count()` always returns a useful value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreType {
    Performance,
    Efficiency,
}

/// Per-CPU descriptor held in the global topology table.
#[derive(Debug, Clone)]
pub struct CpuInfo {
    /// Logical CPU id assigned by us (0-based, stable).
    pub cpu_id: u32,
    /// x86_64: Local APIC id.  RISC-V: hart id.
    pub hw_id: u32,
    /// NUMA node this CPU belongs to.
    pub node: u32,
    pub online: bool,
    pub is_bsp: bool,
    /// Core type for heterogeneous platforms; defaults to Performance.
    pub core_type: CoreType,
}

/// Global CPU topology table populated during `init()`.
static mut CPU_TABLE: [Option<CpuInfo>; MAX_CPUS] = [const { None }; MAX_CPUS];
static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

/// Register a CPU discovered from MADT / device-tree.
pub fn register_cpu(hw_id: u32, node: u32, is_bsp: bool) -> u32 {
    let cpu_id = CPU_COUNT.fetch_add(1, Ordering::Relaxed);
    assert!((cpu_id as usize) < MAX_CPUS, "too many CPUs");
    unsafe {
        CPU_TABLE[cpu_id as usize] = Some(CpuInfo {
            cpu_id,
            hw_id,
            node,
            online: is_bsp,
            is_bsp,
            core_type: CoreType::Performance,
        });
    }
    cpu_id
}

/// Register a CPU with an explicit core type (ARM64 big.LITTLE, x86 hybrid).
pub fn register_cpu_typed(hw_id: u32, node: u32, is_bsp: bool, core_type: CoreType) -> u32 {
    let cpu_id = register_cpu(hw_id, node, is_bsp);
    unsafe {
        if let Some(info) = CPU_TABLE[cpu_id as usize].as_mut() {
            info.core_type = core_type;
        }
    }
    cpu_id
}

/// Returns the CpuInfo for logical cpu_id.
pub fn cpu_info(cpu_id: u32) -> Option<&'static CpuInfo> {
    unsafe { CPU_TABLE[cpu_id as usize].as_ref() }
}

/// Total CPUs registered (online + pending).
pub fn num_cpus() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// Total CPUs currently online.
pub fn num_online_cpus() -> u32 {
    ONLINE_CPUS.load(Ordering::Relaxed)
}

/// Number of online Performance-class cores.
/// On homogeneous platforms (all cores default to Performance) this equals
/// `num_online_cpus()`. On hybrid platforms it returns only the P-cores,
/// which is the right value to use when sizing VFS / IO worker pools to
/// avoid pinning work on slow E-cores.
pub fn perf_core_count() -> u32 {
    let total = CPU_COUNT.load(Ordering::Relaxed) as usize;
    let mut count = 0u32;
    for i in 0..total {
        if let Some(info) = unsafe { CPU_TABLE[i].as_ref() } {
            if info.online && info.core_type == CoreType::Performance {
                count += 1;
            }
        }
    }
    // Always return at least 1 so callers never divide by zero during early
    // boot before any CPU has been registered.
    count.max(1)
}

/// Called by each AP once it has finished its own percpu init.
pub fn ap_online() {
    ONLINE_CPUS.fetch_add(1, Ordering::Release);
}

/// BSP: enumerate topology, bring up APs, wait for all to come online.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::apic;
        // MADT parsing happens in acpi::init(); CPUs have been registered.
        // Mark BSP online.
        ONLINE_CPUS.fetch_add(1, Ordering::Relaxed);
        let total = num_cpus();
        if total > 1 {
            log::info!("smp: starting {} APs", total - 1);
            apic::start_all_aps();
            // Ungate APs.
            AP_GO.store(true, Ordering::Release);
            // Spin until all APs report online.
            while ONLINE_CPUS.load(Ordering::Acquire) < total {
                core::hint::spin_loop();
            }
            log::info!("smp: all {} CPUs online", total);
        } else {
            AP_GO.store(true, Ordering::Release);
            log::info!("smp: uniprocessor mode");
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        use crate::arch::riscv64::smp as rv_smp;
        ONLINE_CPUS.fetch_add(1, Ordering::Relaxed);
        let total = num_cpus();
        if total > 1 {
            log::info!("smp: starting {} harts", total - 1);
            rv_smp::start_all_harts();
            AP_GO.store(true, Ordering::Release);
            while ONLINE_CPUS.load(Ordering::Acquire) < total {
                core::hint::spin_loop();
            }
            log::info!("smp: all {} harts online", total);
        } else {
            AP_GO.store(true, Ordering::Release);
        }
    }
}

/// AP C-level entry point (called from arch trampoline after paging is on).
/// `cpu_id` is the logical id assigned during topology enumeration.
#[no_mangle]
pub extern "C" fn ap_entry(cpu_id: u32) -> ! {
    // Per-CPU storage must be first.
    unsafe { percpu::init(cpu_id) };

    #[cfg(target_arch = "x86_64")]
    unsafe {
        use crate::arch::x86_64::{gdt, idt};
        gdt::init_ap(cpu_id);
        idt::load();
        // Enable local APIC and set up timer vector.
        crate::arch::x86_64::apic::ap_init_local();
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        crate::arch::riscv64::trap::init_hart();
        crate::arch::riscv64::smp::ap_init_plic();
    }

    ap_online();

    // Wait for BSP to finish all global init.
    while !AP_GO.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    crate::proc::scheduler::ap_idle()
}
