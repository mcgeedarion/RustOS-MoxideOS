#!/usr/bin/env bash
# Compatibility wrapper for the unified QEMU runner.
#
# Older xtask smoke flows invoke this top-level script. Keep that entry point
# working while delegating all launch logic to scripts/ci/qemu-run.sh.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH=x86_64 exec "${ROOT_DIR}/scripts/ci/qemu-run.sh" "$@"
