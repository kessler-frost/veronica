//go:build linux

package control

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procRoot is the base of the proc filesystem. Overridable in VM tests that
// stage a fake /proc tree.
var procRoot = "/proc"

// linuxProcSource reads the live process list from /proc, supplying ProcInfo to
// the pure resolver (MatchApp). This is the VM-gated half of Task 3's resolver:
// it only compiles and runs on Linux, where /proc + cgroup v2 exist.
type linuxProcSource struct{}

// NewProcSource returns the Linux /proc-backed proc-source used by the daemon.
func NewProcSource() ProcSource { return linuxProcSource{} }

// Procs walks /proc/<pid>, reading each process's comm and cgroup path, and
// returns the assembled ProcInfo slice. Processes that vanish mid-scan
// (race with exit) are skipped rather than failing the whole read.
func (linuxProcSource) Procs() ([]ProcInfo, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}

	var procs []ProcInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory
		}
		comm, ok := readComm(pid)
		if !ok {
			continue
		}
		procs = append(procs, ProcInfo{
			PID:        pid,
			Comm:       comm,
			CgroupPath: readCgroup(pid),
		})
	}
	return procs, nil
}

// readComm reads /proc/<pid>/comm, trimming the trailing newline. ok is false
// if the process disappeared.
func readComm(pid int) (string, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// readCgroup reads /proc/<pid>/cgroup and returns the cgroup v2 path. The v2
// line is "0::/<path>"; we return the "/<path>" portion. Empty if unreadable.
func readCgroup(pid int) string {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// cgroup v2: "0::/system.slice/docker.service"
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}
