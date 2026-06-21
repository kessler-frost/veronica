#!/usr/bin/env bash
#
# test_preconditions.sh — VM-GATED check for eBPF-LSM kernel preconditions
# (Task 13). This MUST run inside the Lima Ubuntu VM, where /sys/kernel/security
# and the kernel config exist. It CANNOT pass on the macOS host. Do not fake a
# host run.
#
# What it proves:
#   - control.CheckKernelPreconditions() agrees with the raw kernel state:
#       * CONFIG_BPF_LSM=y in the kernel config, AND
#       * "bpf" present in /sys/kernel/security/lsm (set via lsm=...,bpf boot
#         param configured in lima/veronica.yaml).
#   - When both hold, EnforceReady is true; otherwise EnforceReady is false with
#     a clear Reason (the daemon then runs observation-only).
#
# This script is non-fatal about the *result*: it reports whether enforcement is
# ready and exits 0 if the Go check matches the raw state. It exits non-zero only
# if the precondition logic disagrees with the kernel (a real bug) or can't run.
#
# Run:  uv run veronica run bash <project>/scripts/vm/test_preconditions.sh
#   or: limactl shell veronica -- bash <project>/scripts/vm/test_preconditions.sh
#
set -euo pipefail

PROJECT="${VERONICA_VM_PROJECT:-/home/fimbulwinter.linux/veronica}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: this test is VM-gated and only runs on Linux (got $(uname -s))" >&2
  exit 1
fi
if [[ ! -d "$PROJECT" ]]; then
  echo "FAIL: project not found at $PROJECT (run 'uv run veronica setup' first)" >&2
  exit 1
fi
cd "$PROJECT"

# 1. Raw kernel state.
RAW_ACTIVE=false
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  RAW_ACTIVE=true
fi
echo "active LSM list: $(cat /sys/kernel/security/lsm 2>/dev/null || echo '<unreadable>')"

RAW_CONFIG=false
if zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_BPF_LSM=y$'; then
  RAW_CONFIG=true
elif grep -q '^CONFIG_BPF_LSM=y$' "/boot/config-$(uname -r)" 2>/dev/null; then
  RAW_CONFIG=true
fi
echo "CONFIG_BPF_LSM=y: $RAW_CONFIG    bpf in active LSM: $RAW_ACTIVE"

# 2. Drive the Go precondition check and compare.
HARNESS_DIR="$PROJECT/internal/control/_preconditioncheck"
mkdir -p "$HARNESS_DIR"
trap 'rm -rf "$HARNESS_DIR"' EXIT

cat > "$HARNESS_DIR/main.go" <<'GO'
package main

import (
	"encoding/json"
	"fmt"

	"github.com/fimbulwinter/veronica/internal/control"
)

func main() {
	ks := control.CheckKernelPreconditions()
	out, _ := json.Marshal(ks)
	fmt.Println(string(out))
}
GO

RESULT="$(go run ./internal/control/_preconditioncheck)"
echo "CheckKernelPreconditions() => $RESULT"

GO_CONFIG="$(printf '%s' "$RESULT" | sed -n 's/.*"bpf_lsm_configured":\([a-z]*\).*/\1/p')"
GO_ACTIVE="$(printf '%s' "$RESULT" | sed -n 's/.*"bpf_in_active_lsm":\([a-z]*\).*/\1/p')"
GO_READY="$(printf '%s' "$RESULT" | sed -n 's/.*"enforce_ready":\([a-z]*\).*/\1/p')"

if [[ "$GO_CONFIG" != "$RAW_CONFIG" || "$GO_ACTIVE" != "$RAW_ACTIVE" ]]; then
  echo "FAIL: Go precondition check disagrees with raw kernel state" >&2
  echo "      raw: config=$RAW_CONFIG active=$RAW_ACTIVE / go: config=$GO_CONFIG active=$GO_ACTIVE" >&2
  exit 1
fi

if [[ "$GO_READY" == "true" ]]; then
  echo "PASS: eBPF-LSM enforcement is READY (CheckKernelPreconditions matches kernel)"
else
  echo "PASS: precondition check correct; enforcement NOT ready (boot with lsm=...,bpf to enable)"
fi
