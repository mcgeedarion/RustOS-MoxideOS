#!/usr/bin/env bash
# Compatibility wrapper — delegates to scripts/ci/run_qemu.sh with ARCH=x86_64.
# Kept for backwards compatibility with older xtask smoke flows.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH=x86_64 exec "${ROOT_DIR}/scripts/ci/run_qemu.sh" "$@"
