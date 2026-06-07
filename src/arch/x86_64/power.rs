//! x86_64 power-management hooks used by ACPI sleep code.

/// Save and flush CPU state before entering a firmware sleep transition.
///
/// The full S3 resume path does not yet have architecture-specific state save
/// support. Keep this hook as a conservative compiler/CPU fence so ACPI code
/// can call a stable arch facade without depending on a missing module.
pub fn save_and_flush() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}
