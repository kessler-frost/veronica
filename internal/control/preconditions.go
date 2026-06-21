package control

// KernelSupport reports whether the kernel can load veronica's eBPF-LSM
// enforcement primitives. Observation (tracepoints/kprobes) works on any modern
// kernel; enforcement additionally needs CONFIG_BPF_LSM=y AND "bpf" present in
// the active LSM list (set via the lsm= boot parameter). When EnforceReady is
// false the daemon runs observation-only and refuses to apply enforce policies,
// surfacing Reason so the operator knows to reboot with lsm=...,bpf.
type KernelSupport struct {
	// BPFLSMConfigured is true when the kernel was built with CONFIG_BPF_LSM=y.
	BPFLSMConfigured bool `json:"bpf_lsm_configured"`
	// BPFInActiveLSM is true when "bpf" appears in the active LSM list
	// (/sys/kernel/security/lsm), which requires the lsm= boot parameter.
	BPFInActiveLSM bool `json:"bpf_in_active_lsm"`
	// EnforceReady is true only when both conditions above hold.
	EnforceReady bool `json:"enforce_ready"`
	// Reason is a human-readable explanation when EnforceReady is false.
	Reason string `json:"reason,omitempty"`
}

// evaluateKernelSupport derives EnforceReady + Reason from the two raw checks.
// It is pure so it is unit-tested on the host; the Linux file reads live in
// preconditions_linux.go (VM-gated).
func evaluateKernelSupport(configured, active bool) KernelSupport {
	ks := KernelSupport{
		BPFLSMConfigured: configured,
		BPFInActiveLSM:   active,
		EnforceReady:     configured && active,
	}
	switch {
	case ks.EnforceReady:
		ks.Reason = ""
	case !configured && !active:
		ks.Reason = "kernel lacks CONFIG_BPF_LSM and 'bpf' is not in the active LSM list; rebuild/boot a BPF-LSM kernel with lsm=...,bpf"
	case !configured:
		ks.Reason = "kernel was not built with CONFIG_BPF_LSM=y; enforcement unavailable (observation still works)"
	default: // !active
		ks.Reason = "'bpf' is not in the active LSM list (/sys/kernel/security/lsm); add it to the lsm= boot parameter and reboot"
	}
	return ks
}
