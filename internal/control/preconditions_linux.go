//go:build linux

package control

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"os"
	"strings"
)

// lsmListPath is the active-LSM list exposed by securityfs.
var lsmListPath = "/sys/kernel/security/lsm"

// CheckKernelPreconditions inspects the running kernel for BPF-LSM support: it
// reads the active LSM list and the kernel config. The daemon calls this at
// startup and disables enforcement (observation-only) when EnforceReady is
// false, logging Reason. VM-gated in practice (the files only exist on Linux),
// but the decision logic is the pure evaluateKernelSupport tested on the host.
func CheckKernelPreconditions() KernelSupport {
	return evaluateKernelSupport(bpfLSMConfigured(), bpfInActiveLSM())
}

// bpfInActiveLSM reports whether "bpf" is one of the comma-separated entries in
// /sys/kernel/security/lsm.
func bpfInActiveLSM() bool {
	data, err := os.ReadFile(lsmListPath)
	if err != nil {
		return false
	}
	for _, name := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if name == "bpf" {
			return true
		}
	}
	return false
}

// bpfLSMConfigured reports whether the kernel config has CONFIG_BPF_LSM=y. It
// tries /proc/config.gz first (gzip), then /boot/config-$(uname -r).
func bpfLSMConfigured() bool {
	if v, ok := configContainsGz("/proc/config.gz", "CONFIG_BPF_LSM=y"); ok {
		return v
	}
	if v, ok := configContainsPlain("/boot/config-"+kernelRelease(), "CONFIG_BPF_LSM=y"); ok {
		return v
	}
	return false
}

// kernelRelease reads the running kernel release from /proc/sys/kernel/osrelease.
func kernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// configContainsGz reads a gzip-compressed kernel config and reports whether the
// line is present. ok is false when the file can't be read (caller falls back).
func configContainsGz(path, line string) (found, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return false, false
	}
	defer r.Close()
	return scanFor(r, line), true
}

// configContainsPlain reads a plaintext kernel config.
func configContainsPlain(path, line string) (found, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer f.Close()
	return scanFor(f, line), true
}

// scanFor reports whether any line equals the target line.
func scanFor(r interface{ Read([]byte) (int, error) }, line string) bool {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == line {
			return true
		}
	}
	return false
}
