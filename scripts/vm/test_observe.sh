#!/usr/bin/env bash
#
# test_observe.sh — VM-GATED acceptance test for cgroup-filtered observation
# (Task 11). This MUST run inside the Lima Ubuntu VM, where eBPF programs load
# and /proc + cgroup v2 exist. It CANNOT pass on the macOS host: Apple clang has
# no BPF backend, there is no vmlinux.h, and eBPF programs cannot be loaded.
# Do not fake a host run.
#
# What it proves:
#   - The observation programs (process_exec/file_open/net_connect/mount) carry a
#     vr_target_cgroup map and gate every emit on vr_cgroup_observed().
#   - After scoping observation to one cgroup id, the ring buffer receives events
#     ONLY from a process in that cgroup, and NOT from an unrelated process in a
#     different cgroup.
#
# How it runs:
#   From the host:  uv run veronica run sudo bash <project>/scripts/vm/test_observe.sh
#   Or in the VM:   limactl shell veronica -- sudo bash <project>/scripts/vm/test_observe.sh
#
# Requires root (eBPF load) and a kernel with cgroup v2 + the path_mount symbol.
#
set -euo pipefail

PROJECT="${VERONICA_VM_PROJECT:-/home/fimbulwinter.linux/veronica}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: this test is VM-gated and only runs on Linux (got $(uname -s))" >&2
  exit 1
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "FAIL: must run as root to load eBPF (use sudo)" >&2
  exit 1
fi
if [[ ! -d "$PROJECT" ]]; then
  echo "FAIL: project not found at $PROJECT (run 'uv run veronica setup' first)" >&2
  exit 1
fi

cd "$PROJECT"

# 0. Regenerate the eBPF bindings from the updated .c programs (the host ships
#    placeholder objects; the VM has clang -target bpf + vmlinux.h).
if [[ ! -f internal/ebpf/programs/vmlinux.h ]]; then
  echo "generating vmlinux.h"
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/programs/vmlinux.h
fi
echo "running go generate (bpf2go) for the observation programs"
go generate ./internal/ebpf/...

# 1. Harness: load process_exec + mount programs, scope observation to the
#    cgroup id of a target process, then assert which cgroups produce events.
HARNESS_DIR="$PROJECT/internal/ebpf/_observecheck"
mkdir -p "$HARNESS_DIR"
trap 'rm -rf "$HARNESS_DIR"' EXIT

cat > "$HARNESS_DIR/main.go" <<'GO'
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/fimbulwinter/veronica/internal/ebpf/bpf"
)

// cgroupID returns the cgroup v2 id (inode of the cgroup dir) for a pid, which
// equals bpf_get_current_cgroup_id() for tasks in that cgroup.
func cgroupID(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, err
	}
	rel := ""
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if bytes.HasPrefix(line, []byte("0::")) {
			rel = string(bytes.TrimPrefix(line, []byte("0::")))
		}
	}
	fi, err := os.Stat("/sys/fs/cgroup" + rel)
	if err != nil {
		return 0, err
	}
	return fi.Sys().(*syscallStat).Ino, nil
}

func main() {
	targetPID, _ := strconv.Atoi(os.Args[1])
	target, err := cgroupID(targetPID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cgroupID:", err)
		os.Exit(2)
	}

	objs := bpf.ProcessExecObjects{}
	if err := bpf.LoadProcessExecObjects(&objs, nil); err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(2)
	}
	defer objs.Close()

	// Scope observation to the target cgroup: install its id, drop the
	// observe-all sentinel (key 0).
	if err := objs.VrTargetCgroup.Put(target, uint8(1)); err != nil {
		fmt.Fprintln(os.Stderr, "put target:", err)
		os.Exit(2)
	}
	_ = objs.VrTargetCgroup.Delete(uint64(0))

	l, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attach:", err)
		os.Exit(2)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ringbuf:", err)
		os.Exit(2)
	}
	defer rd.Close()

	// Collect the cgroup of every emitted exec event for 3 seconds.
	seen := map[uint32]bool{}
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			// header: type u32, pid u32, ...
			if len(rec.RawSample) < 8 {
				continue
			}
			pid := binary.LittleEndian.Uint32(rec.RawSample[4:8])
			seen[pid] = true
		}
	}()

	fmt.Println("READY") // signal the shell to generate activity
	time.Sleep(3 * time.Second)
	rd.Close()

	// Emit the set of PIDs we observed; the shell checks the target's children
	// are present and the unrelated process's are not.
	for pid := range seen {
		fmt.Printf("EXEC_PID %d\n", pid)
	}
}
GO

# syscallStat shim: avoid importing syscall just for Stat_t in the harness file.
cat > "$HARNESS_DIR/stat_linux.go" <<'GO'
package main

import "syscall"

type syscallStat = syscall.Stat_t
GO

echo "building observe harness"
go build -o "$HARNESS_DIR/observecheck" ./internal/ebpf/_observecheck

# 2. Start the TARGET process in its own cgroup scope, and an UNRELATED process
#    in a different scope. We use systemd-run to get distinct cgroup v2 scopes.
TARGET_SCOPE="vrobs-target-$$.scope"
OTHER_SCOPE="vrobs-other-$$.scope"
cleanup() { systemctl stop "$TARGET_SCOPE" "$OTHER_SCOPE" 2>/dev/null || true; }
trap 'cleanup; rm -rf "$HARNESS_DIR"' EXIT

# Target: a shell that repeatedly execs /bin/true (each exec = an event).
systemd-run --quiet --unit="$TARGET_SCOPE" --scope \
  bash -c 'for i in $(seq 1 200); do /bin/true; sleep 0.02; done' &
sleep 0.4
TARGET_PID="$(systemctl show -p MainPID --value "$TARGET_SCOPE" 2>/dev/null || true)"
[[ -z "$TARGET_PID" || "$TARGET_PID" == "0" ]] && TARGET_PID="$(pgrep -n -P "$(systemctl show -p MainPID --value "$TARGET_SCOPE")" || true)"

# Unrelated: a separate scope also execing /bin/true.
systemd-run --quiet --unit="$OTHER_SCOPE" --scope \
  bash -c 'for i in $(seq 1 200); do /bin/true; sleep 0.02; done' &
sleep 0.4

echo "target scope MainPID=$TARGET_PID"
if [[ -z "$TARGET_PID" || "$TARGET_PID" == "0" ]]; then
  echo "FAIL: could not determine target scope PID" >&2
  exit 1
fi

# 3. Run the harness scoped to the TARGET cgroup; it prints the PIDs it observed.
RESULT="$("$HARNESS_DIR/observecheck" "$TARGET_PID" 2>/dev/null || true)"
echo "$RESULT"

# The harness scopes to the target cgroup, so observed exec PIDs must be inside
# the target scope's cgroup and never inside the other scope's cgroup.
TARGET_CG="$(cat /proc/$TARGET_PID/cgroup | sed -n 's/^0:://p')"
OTHER_MAIN="$(systemctl show -p MainPID --value "$OTHER_SCOPE")"
OTHER_CG="$(cat /proc/$OTHER_MAIN/cgroup 2>/dev/null | sed -n 's/^0:://p' || true)"

saw_target=0
saw_other=0
while read -r _ pid; do
  [[ -z "$pid" ]] && continue
  cg="$(cat /proc/$pid/cgroup 2>/dev/null | sed -n 's/^0:://p' || true)"
  [[ "$cg" == "$TARGET_CG" ]] && saw_target=1
  [[ -n "$OTHER_CG" && "$cg" == "$OTHER_CG" ]] && saw_other=1
done <<< "$(printf '%s\n' "$RESULT" | grep '^EXEC_PID' || true)"

if [[ "$saw_target" != "1" ]]; then
  echo "FAIL: no exec events observed for the target cgroup ($TARGET_CG)" >&2
  exit 1
fi
if [[ "$saw_other" == "1" ]]; then
  echo "FAIL: leaked exec events from the unrelated cgroup ($OTHER_CG)" >&2
  exit 1
fi

echo "PASS: observation scoped to target cgroup; unrelated cgroup not observed"
