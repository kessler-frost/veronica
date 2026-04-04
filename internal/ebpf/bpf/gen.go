package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 ProcessExec ../programs/process_exec.c -- -I../programs -D__TARGET_ARCH_arm64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 FileOpen ../programs/file_open.c -- -I../programs -D__TARGET_ARCH_arm64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 NetConnect ../programs/net_connect.c -- -I../programs -D__TARGET_ARCH_arm64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target arm64 ProcessExit ../programs/process_exit.c -- -I../programs -D__TARGET_ARCH_arm64
