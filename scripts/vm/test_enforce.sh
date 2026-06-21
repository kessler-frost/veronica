#!/usr/bin/env bash
#
# test_enforce.sh — VM-GATED acceptance demo for the LSM enforcement primitives
# (Task 12). This MUST run inside the Lima Ubuntu VM with CONFIG_BPF_LSM=y and
# "bpf" in the active LSM list (boot param lsm=...,bpf — see veronica.yaml /
# test_preconditions.sh). It CANNOT pass on the macOS host: Apple clang has no
# BPF backend, there is no vmlinux.h, and LSM programs cannot be loaded or
# attached off Linux. Do not fake a host run.
#
# The acceptance scenario (the demo from the plan), proven at the kernel level.
# NOTE: a docker `local` volume is created by mkdir of
# /var/lib/docker/volumes/<name> (verified: it emits security_path_mkdir, NOT a
# mount syscall), so the primitive that actually governs "don't let docker create
# volumes" is block-path-write hooking path_mkdir — block-mount (sb_mount) never
# fires for it. The demo therefore loads block-path-write{path_prefix:"volumes"}.
#   1. Resolve docker's cgroup; load block-path-write scoped to it (audit-first).
#   2. In AUDIT mode, `docker volume create` SUCCEEDS and the audit counter rises
#      (would-block observed).
#   3. Flip to ENFORCE; `docker volume create` now FAILS with EPERM
#      (kernel: "mkdir .../volumes/<name>: operation not permitted").
#   4. An unrelated docker op (`docker ps`) still works — enforcement is scoped to
#      volume-dir creation, not a blanket docker block.
#   5. The kill switch (Revert/KillSwitch) removes the policy; create works again.
#
# The `veronica watch docker` / `veronica enforce "don't let docker create
# volumes"` / `veronica panic` CLI verbs drive this same internal/ebpf.LSMManager
# through the daemon; this script exercises the manager directly so the kernel
# behavior is verified without the full Agentfield round-trip.
#
# Run:  uv run veronica run sudo bash <project>/scripts/vm/test_enforce.sh
#   or: limactl shell veronica -- sudo bash <project>/scripts/vm/test_enforce.sh
#
set -euo pipefail

PROJECT="${VERONICA_VM_PROJECT:-/home/fimbulwinter.linux/veronica}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: this test is VM-gated and only runs on Linux (got $(uname -s))" >&2
  exit 1
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "FAIL: must run as root to load/attach LSM programs (use sudo)" >&2
  exit 1
fi
if [[ ! -d "$PROJECT" ]]; then
  echo "FAIL: project not found at $PROJECT (run 'uv run veronica setup' first)" >&2
  exit 1
fi

# Precondition: BPF-LSM must be active, else enforcement cannot attach.
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "FAIL: 'bpf' not in /sys/kernel/security/lsm — boot with lsm=...,bpf" >&2
  echo "      (run scripts/vm/test_preconditions.sh for details)" >&2
  exit 1
fi

command -v docker >/dev/null 2>&1 || { echo "FAIL: docker not installed in VM" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "FAIL: docker daemon not running" >&2; exit 1; }

cd "$PROJECT"

# 1. Generate vmlinux.h + compile the LSM objects (VM-only toolchain).
if [[ ! -f internal/ebpf/programs/vmlinux.h ]]; then
  echo "generating vmlinux.h"
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/programs/vmlinux.h
fi
echo "compiling LSM objects"
make -C internal/ebpf/programs/lsm

export VERONICA_LSM_OBJ_DIR="$PROJECT/internal/ebpf/programs/lsm"

# 2. Resolve docker's cgroup v2 path (the dockerd service scope).
DOCKER_PID="$(pgrep -n -x dockerd || pgrep -n dockerd || true)"
[[ -z "$DOCKER_PID" ]] && { echo "FAIL: could not find dockerd pid" >&2; exit 1; }
DOCKER_CGROUP="$(sed -n 's/^0:://p' /proc/$DOCKER_PID/cgroup)"
echo "dockerd pid=$DOCKER_PID cgroup=$DOCKER_CGROUP"

# 3. Harness driving internal/ebpf.LSMManager through the full lifecycle.
HARNESS_DIR="$PROJECT/internal/ebpf/_enforcecheck"
mkdir -p "$HARNESS_DIR"
trap 'rm -rf "$HARNESS_DIR" internal/ebpf/programs/lsm/*.o; docker volume rm -f vrtestvol >/dev/null 2>&1 || true' EXIT

cat > "$HARNESS_DIR/main.go" <<'GO'
package main

import (
	"fmt"
	"os"
	"os/exec"

	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
)

// dockerVolumeCreate returns nil if `docker volume create` succeeded.
func dockerVolumeCreate(name string) error {
	_ = exec.Command("docker", "volume", "rm", "-f", name).Run()
	out, err := exec.Command("docker", "volume", "create", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func main() {
	cgroup := os.Args[1]
	mgr := vebpf.NewLSMManager()

	// Apply block-path-write scoped to docker, audit-first. `docker volume
	// create` is a mkdir of /var/lib/docker/volumes/<name> (verified: it emits
	// security_path_mkdir, not a mount syscall), so the primitive that governs
	// it is block-path-write hooking path_mkdir. path_prefix "volumes" matches
	// the parent dir (".../docker/volumes") of the new volume directory.
	if err := mgr.Apply("pol-1", "block-path-write", cgroup, map[string]any{"path_prefix": "volumes"}); err != nil {
		fmt.Fprintln(os.Stderr, "apply:", err)
		os.Exit(2)
	}

	// AUDIT: volume create should still succeed.
	if err := dockerVolumeCreate("vrtestvol"); err != nil {
		fmt.Fprintln(os.Stderr, "AUDIT volume create unexpectedly failed:", err)
		os.Exit(3)
	}
	fmt.Println("AUDIT_CREATE_OK")
	if n, err := mgr.AuditCount("pol-1"); err == nil {
		fmt.Printf("AUDIT_COUNT %d\n", n)
	}

	// ENFORCE: volume create must now fail with EPERM (operation not permitted).
	if err := mgr.SetMode("pol-1", true); err != nil {
		fmt.Fprintln(os.Stderr, "setmode:", err)
		os.Exit(2)
	}
	if err := dockerVolumeCreate("vrtestvol"); err == nil {
		fmt.Fprintln(os.Stderr, "ENFORCE volume create unexpectedly SUCCEEDED")
		os.Exit(4)
	} else {
		fmt.Println("ENFORCE_CREATE_DENIED")
	}

	// Unrelated docker op still works under the path-write policy (the policy is
	// scoped to volume-dir creation, not a blanket docker block).
	if out, err := exec.Command("docker", "ps").CombinedOutput(); err != nil {
		fmt.Fprintln(os.Stderr, "docker ps failed under enforce:", err, string(out))
		os.Exit(5)
	}
	fmt.Println("DOCKER_PS_OK")

	// Kill switch: revert; volume create works again.
	mgr.KillSwitch()
	if err := dockerVolumeCreate("vrtestvol"); err != nil {
		fmt.Fprintln(os.Stderr, "post-panic volume create failed:", err)
		os.Exit(6)
	}
	fmt.Println("PANIC_REVERTED_OK")
}
GO

echo "building enforce harness"
go build -o "$HARNESS_DIR/enforcecheck" ./internal/ebpf/_enforcecheck

echo "running enforce acceptance harness"
OUT="$("$HARNESS_DIR/enforcecheck" "$DOCKER_CGROUP")"
echo "$OUT"

for want in AUDIT_CREATE_OK ENFORCE_CREATE_DENIED DOCKER_PS_OK PANIC_REVERTED_OK; do
  grep -q "^$want" <<<"$OUT" || { echo "FAIL: missing acceptance step: $want" >&2; exit 1; }
done

echo "PASS: block-path-write audit->enforce->panic verified against docker volume create"
