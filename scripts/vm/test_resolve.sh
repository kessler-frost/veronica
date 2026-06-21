#!/usr/bin/env bash
#
# test_resolve.sh — VM-GATED acceptance test for the Linux proc/cgroup resolver
# (Task 10). This MUST run inside the Lima Ubuntu VM, where /proc + cgroup v2
# exist. It CANNOT pass on the macOS host (the resolver is behind //go:build
# linux and the host stub errors). Do not fake a host run.
#
# What it proves:
#   - control.NewProcSource() reads /proc/<pid>/comm + /proc/<pid>/cgroup,
#   - control.MatchApp(name, procs) finds a known process's PID and its
#     non-empty cgroup v2 path.
#
# How it runs:
#   From the host:  uv run veronica run bash /home/fimbulwinter.linux/veronica/scripts/vm/test_resolve.sh
#   Or in the VM:   limactl shell veronica -- bash <project>/scripts/vm/test_resolve.sh
#   Or inside an interactive VM shell:  bash scripts/vm/test_resolve.sh
#
set -euo pipefail

PROJECT="${VERONICA_VM_PROJECT:-/home/fimbulwinter.linux/veronica}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

if [[ ! -d "$PROJECT" ]]; then
  echo "FAIL: project not found at $PROJECT (run 'uv run veronica setup' first)" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: this test is VM-gated and only runs on Linux (got $(uname -s))" >&2
  exit 1
fi

cd "$PROJECT"

# 1. Start a known long-lived process with a recognizable comm in its own
#    transient cgroup (systemd-run gives it a dedicated cgroup v2 scope).
MARKER="vrresolveprobe"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"; [[ -n "${PROBE_PID:-}" ]] && kill "$PROBE_PID" 2>/dev/null || true; [[ -n "${PROBE_SCOPE:-}" ]] && systemctl stop "$PROBE_SCOPE" 2>/dev/null || true' EXIT

# Copy a sleep binary under a marker name so comm == MARKER (comm is the
# basename, truncated to 15 chars; MARKER is 14 chars).
cp "$(command -v sleep)" "$WORKDIR/$MARKER"

if command -v systemd-run >/dev/null 2>&1; then
  PROBE_SCOPE="vrresolve-$$.scope"
  systemd-run --quiet --unit="$PROBE_SCOPE" --scope "$WORKDIR/$MARKER" 120 &
  sleep 0.5
  PROBE_PID="$(pgrep -n -x "$MARKER" || true)"
else
  # Fallback: no systemd-run; the process still lands in some cgroup v2 path.
  "$WORKDIR/$MARKER" 120 &
  PROBE_PID=$!
fi

if [[ -z "${PROBE_PID:-}" ]]; then
  echo "FAIL: could not start probe process" >&2
  exit 1
fi
echo "started probe '$MARKER' pid=$PROBE_PID"

# 2. Generate a tiny Go harness that drives the real resolver and prints the
#    resolved AppRef as JSON. It lives in the module so the import resolves.
HARNESS_DIR="$PROJECT/internal/control/_resolvecheck"
mkdir -p "$HARNESS_DIR"
trap 'rm -rf "$WORKDIR" "$HARNESS_DIR"; [[ -n "${PROBE_PID:-}" ]] && kill "$PROBE_PID" 2>/dev/null || true; [[ -n "${PROBE_SCOPE:-}" ]] && systemctl stop "$PROBE_SCOPE" 2>/dev/null || true' EXIT

cat > "$HARNESS_DIR/main.go" <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fimbulwinter/veronica/internal/control"
)

func main() {
	name := os.Args[1]
	procs, err := control.NewProcSource().Procs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Procs:", err)
		os.Exit(2)
	}
	ref, err := control.MatchApp(name, procs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MatchApp:", err)
		os.Exit(3)
	}
	out, _ := json.Marshal(ref)
	fmt.Println(string(out))
}
GO

# 3. Run the harness and assert the AppRef has the probe PID + a cgroup path.
RESULT="$(go run ./internal/control/_resolvecheck "$MARKER")"
echo "resolve_app($MARKER) => $RESULT"

CGROUP="$(printf '%s' "$RESULT" | sed -n 's/.*"cgroup_path":"\([^"]*\)".*/\1/p')"
if [[ -z "$CGROUP" ]]; then
  echo "FAIL: resolved AppRef has empty cgroup_path" >&2
  exit 1
fi

if ! printf '%s' "$RESULT" | grep -q "\"pids\":\[.*${PROBE_PID}.*\]"; then
  echo "FAIL: resolved PIDs do not include probe pid $PROBE_PID" >&2
  exit 1
fi

echo "PASS: resolve_app found pid=$PROBE_PID cgroup=$CGROUP"
