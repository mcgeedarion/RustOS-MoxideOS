// Legacy shim — code has moved to src/firmware/acpi/
// This file is retained so that `crate::acpi` continues to compile.
// Update callers to use `crate::firmware::acpi` and remove this file.
pub use crate::firmware::acpi::*;
pub mod power {
    pub use crate::firmware::acpi::power::*;
}
