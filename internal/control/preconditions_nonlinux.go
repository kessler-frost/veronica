//go:build !linux

package control

// CheckKernelPreconditions is unavailable off Linux: BPF-LSM, the active LSM
// list, and the kernel config only exist on Linux (in the VM). The stub reports
// enforcement as not ready so a host build never claims it can enforce. The real
// check lives in preconditions_linux.go.
func CheckKernelPreconditions() KernelSupport {
	return KernelSupport{
		Reason: "kernel preconditions can only be checked on Linux (inside the VM)",
	}
}
