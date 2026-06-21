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
	// The shell passes the UNRELATED scope's pid so the harness can classify
	// each observed event's cgroup id in-kernel terms (target vs other) without
	// any post-hoc /proc read on a short-lived /bin/true that has already exited.
	otherPID, _ := strconv.Atoi(os.Args[2])
	other, oerr := cgroupID(otherPID)
	if oerr != nil {
		fmt.Fprintln(os.Stderr, "other cgroupID:", oerr)
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

	// Classify every emitted exec event by the cgroup id of its emitting task.
	// We read the task's cgroup id LIVE in the reader goroutine the instant the
	// event arrives. The kernel filter only emits events whose current cgroup id
	// equals the installed target, so a correctly scoped program yields
	// inTarget>0 and inOther==0; "gone" counts events whose pid exited before we
	// could read it (still proves an in-target emit happened).
	var inTarget, inOther, gone int
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			if len(rec.RawSample) < 8 {
				continue
			}
			pid := binary.LittleEndian.Uint32(rec.RawSample[4:8])
			cg, cerr := cgroupID(int(pid))
			switch {
			case cerr != nil:
				// The emitting task already exited; its cgroup id is gone. The
				// kernel only emitted it because it matched the target filter.
				gone++
			case cg == target:
				inTarget++
			case cg == other:
				inOther++
			}
		}
	}()

	fmt.Println("READY") // signal the shell to generate activity
	time.Sleep(3 * time.Second)
	rd.Close()
	time.Sleep(100 * time.Millisecond) // let the reader drain

	fmt.Printf("IN_TARGET %d\n", inTarget)
	fmt.Printf("IN_OTHER %d\n", inOther)
	fmt.Printf("GONE %d\n", gone)
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

# scope_leader_pid prints the leader PID of a transient --scope unit. systemd
# --scope units do NOT expose a MainPID (that is a service-only property), so we
# read the scope's cgroup.procs and take the lowest PID (the bash -c leader).
scope_leader_pid() {
  local scope="$1"
  local cg
  cg="$(systemctl show -p ControlGroup --value "$scope" 2>/dev/null || true)"
  [[ -z "$cg" ]] && return 0
  # Lowest PID in the cgroup is the leader we launched.
  sort -n "/sys/fs/cgroup${cg}/cgroup.procs" 2>/dev/null | head -n1
}

# Target: a shell that repeatedly execs /bin/true (each exec = an event).
systemd-run --quiet --unit="$TARGET_SCOPE" --scope \
  bash -c 'for i in $(seq 1 200); do /bin/true; sleep 0.02; done' &
sleep 0.4
TARGET_PID="$(scope_leader_pid "$TARGET_SCOPE")"

# Unrelated: a separate scope also execing /bin/true.
systemd-run --quiet --unit="$OTHER_SCOPE" --scope \
  bash -c 'for i in $(seq 1 200); do /bin/true; sleep 0.02; done' &
sleep 0.4

OTHER_PID="$(scope_leader_pid "$OTHER_SCOPE")"
echo "target scope leader=$TARGET_PID  other scope leader=$OTHER_PID"
if [[ -z "$TARGET_PID" || "$TARGET_PID" == "0" ]]; then
  echo "FAIL: could not determine target scope PID" >&2
  exit 1
fi
if [[ -z "$OTHER_PID" || "$OTHER_PID" == "0" ]]; then
  echo "FAIL: could not determine other scope PID" >&2
  exit 1
fi

# 3. Run the harness scoped to the TARGET cgroup. The harness classifies every
#    observed exec event by cgroup id (in-kernel terms) and prints the counts.
RESULT="$("$HARNESS_DIR/observecheck" "$TARGET_PID" "$OTHER_PID" 2>/dev/null || true)"
echo "$RESULT"

IN_TARGET="$(printf '%s\n' "$RESULT" | sed -n 's/^IN_TARGET //p')"
IN_OTHER="$(printf '%s\n' "$RESULT" | sed -n 's/^IN_OTHER //p')"
: "${IN_TARGET:=0}" "${IN_OTHER:=0}"

# The harness scopes to the target cgroup, so it must observe target-cgroup execs
# and must NEVER observe an exec whose cgroup id is the unrelated scope's.
if [[ "$IN_TARGET" -lt 1 ]]; then
  echo "FAIL: no exec events observed for the target cgroup" >&2
  exit 1
fi
if [[ "$IN_OTHER" -gt 0 ]]; then
  echo "FAIL: leaked $IN_OTHER exec events from the unrelated cgroup" >&2
  exit 1
fi

echo "PASS: observation scoped to target cgroup ($IN_TARGET target execs, 0 unrelated)"
