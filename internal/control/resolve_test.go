package control

import (
	"reflect"
	"sort"
	"testing"
)

func dockerProcs() []ProcInfo {
	return []ProcInfo{
		{PID: 4521, Comm: "dockerd", CgroupPath: "/sys/fs/cgroup/system.slice/docker.service"},
		{PID: 4530, Comm: "docker-proxy", CgroupPath: "/sys/fs/cgroup/system.slice/docker.service"},
		{PID: 900, Comm: "sshd", CgroupPath: "/sys/fs/cgroup/system.slice/ssh.service"},
		{PID: 12, Comm: "bash", CgroupPath: "/sys/fs/cgroup/user.slice"},
	}
}

func TestMatchApp_FindsAllPIDsAndCommonCgroup(t *testing.T) {
	ref, err := MatchApp("docker", dockerProcs())
	if err != nil {
		t.Fatalf("MatchApp() error = %v", err)
	}
	if ref.Name != "docker" {
		t.Errorf("Name = %q, want docker", ref.Name)
	}
	wantPIDs := []int{4521, 4530}
	got := append([]int(nil), ref.PIDs...)
	sort.Ints(got)
	if !reflect.DeepEqual(got, wantPIDs) {
		t.Errorf("PIDs = %v, want %v", got, wantPIDs)
	}
	if ref.CgroupPath != "/sys/fs/cgroup/system.slice/docker.service" {
		t.Errorf("CgroupPath = %q, want the common docker cgroup", ref.CgroupPath)
	}
}

func TestMatchApp_CommonPrefixCgroup(t *testing.T) {
	// docker procs share a cgroup *prefix* but live in per-container subpaths;
	// the result is the longest common cgroup path.
	procs := []ProcInfo{
		{PID: 1, Comm: "dockerd", CgroupPath: "/sys/fs/cgroup/docker/abc"},
		{PID: 2, Comm: "docker-proxy", CgroupPath: "/sys/fs/cgroup/docker/def"},
	}
	ref, err := MatchApp("docker", procs)
	if err != nil {
		t.Fatalf("MatchApp() error = %v", err)
	}
	if ref.CgroupPath != "/sys/fs/cgroup/docker" {
		t.Errorf("CgroupPath = %q, want common prefix /sys/fs/cgroup/docker", ref.CgroupPath)
	}
}

func TestMatchApp_NoMatch(t *testing.T) {
	if _, err := MatchApp("nginx", dockerProcs()); err == nil {
		t.Fatal("MatchApp() with no matching process should error")
	}
}

func TestMatchApp_StartAnchored(t *testing.T) {
	procs := []ProcInfo{
		{PID: 1, Comm: "mydocker", CgroupPath: "/sys/fs/cgroup/x"},
		{PID: 2, Comm: "containerd", CgroupPath: "/sys/fs/cgroup/y"},
	}
	// "docker" must not match "mydocker" (start-anchored, not substring).
	if _, err := MatchApp("docker", procs); err == nil {
		t.Fatal("MatchApp() should be start-anchored, not substring; mydocker must not match")
	}
}

func TestMatchApp_PrefixMatches(t *testing.T) {
	procs := []ProcInfo{
		{PID: 1, Comm: "dockerd", CgroupPath: "/sys/fs/cgroup/docker"},
	}
	// "docker" should match "dockerd" (start-anchored prefix).
	ref, err := MatchApp("docker", procs)
	if err != nil {
		t.Fatalf("MatchApp() error = %v", err)
	}
	if len(ref.PIDs) != 1 || ref.PIDs[0] != 1 {
		t.Errorf("PIDs = %v, want [1]", ref.PIDs)
	}
}

func TestMatchApp_EmptyProcs(t *testing.T) {
	if _, err := MatchApp("docker", nil); err == nil {
		t.Fatal("MatchApp() with no procs should error")
	}
}
