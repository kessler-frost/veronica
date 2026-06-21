//go:build !linux

package control

import "fmt"

// stubProcSource is the non-Linux placeholder so the daemon compiles and unit
// tests run on darwin. The real /proc-backed source lives in resolve_linux.go
// (VM-gated); resolve_app is unavailable off-Linux because /proc + cgroup v2
// only exist there. Handler tests inject their own fake ProcSource, so this
// stub is never exercised by the host test suite.
type stubProcSource struct{}

// NewProcSource returns a proc-source that errors: process resolution requires
// Linux /proc, which is only present inside the VM.
func NewProcSource() ProcSource { return stubProcSource{} }

func (stubProcSource) Procs() ([]ProcInfo, error) {
	return nil, fmt.Errorf("process resolution requires Linux /proc (run in the VM)")
}
