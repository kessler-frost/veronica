package control

import (
	"fmt"
	"strings"
)

// MatchApp resolves an app name to the set of matching processes, returning the
// app's live PIDs and the longest common cgroup path of those processes. It is
// pure: the caller supplies the ProcInfo slice (read from /proc + cgroup in the
// VM, Task 10). Matching is start-anchored on comm — name "docker" matches
// "dockerd" / "docker-proxy" but not "mydocker" — mirroring the classifier's
// HasPrefix convention. It errors if no process matches.
func MatchApp(name string, procs []ProcInfo) (AppRef, error) {
	var pids []int
	var cgroups []string
	for _, p := range procs {
		if !strings.HasPrefix(p.Comm, name) {
			continue
		}
		pids = append(pids, p.PID)
		cgroups = append(cgroups, p.CgroupPath)
	}

	if len(pids) == 0 {
		return AppRef{}, fmt.Errorf("no process matching app %q", name)
	}

	return AppRef{Name: name, CgroupPath: commonCgroup(cgroups), PIDs: pids}, nil
}

// commonCgroup returns the longest common cgroup path of the given paths,
// trimmed at a path boundary so partial path components are never returned.
func commonCgroup(paths []string) string {
	prefix := paths[0]
	for _, p := range paths[1:] {
		prefix = commonPrefix(prefix, p)
	}
	return strings.TrimRight(prefix, "/")
}

// commonPrefix returns the longest shared prefix of a and b that ends on a "/"
// boundary (so "/a/abc" and "/a/def" share "/a", not "/a/").
func commonPrefix(a, b string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	shared := a[:i]
	if i < len(a) && i < len(b) {
		// Diverged mid-component: cut back to the last boundary.
		if idx := strings.LastIndex(shared, "/"); idx >= 0 {
			return shared[:idx]
		}
	}
	return shared
}
