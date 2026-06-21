# VM-ONLY: builds the LSM enforcement objects. Requires clang with a BPF backend,
# libbpf headers, and vmlinux.h — all of which exist only inside the Lima VM (the
# macOS host's Apple clang has no BPF target). The Go loader
# (internal/ebpf/lsm_loader.go) loads these .o files at runtime via
# ebpf.LoadCollectionSpec.
#
# Usage (in the VM):  make -C internal/ebpf/programs/lsm
#
# vmlinux.h is generated one level up by the observe/setup flow:
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../vmlinux.h

CLANG ?= clang
ARCH ?= arm64
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I..

PROGRAMS := \
	block_path_write \
	block_mount \
	block_egress \
	block_exec \
	drop_capability

OBJECTS := $(PROGRAMS:%=%.o)

.PHONY: all clean
all: $(OBJECTS)

%.o: %.c common_lsm.h ../vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

../vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../vmlinux.h

clean:
	rm -f $(OBJECTS)
