//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// LSM enforcement modes mirror control.Mode (audit vs enforce) at the kernel
// level. The vr_mode map's index-0 byte holds these.
const (
	lsmModeAudit   uint8 = 0
	lsmModeEnforce uint8 = 1
)

// primitivePrograms maps each catalog primitive id to the object file (compiled
// in the VM by `make -C internal/ebpf/programs/lsm`) and the SEC()-named
// programs it attaches. The loader attaches every program in the object via
// link.AttachLSM. The object embeds the shared vr_mode / vr_scope /
// vr_audit_count maps plus the primitive's param map(s).
var primitivePrograms = map[string][]string{
	"block-path-write": {"vr_block_path_write_open", "vr_block_path_write_create", "vr_block_path_write_mkdir"},
	"block-mount":      {"vr_block_mount_sb", "vr_block_mount_move"},
	"block-egress":     {"vr_block_egress_connect"},
	"block-exec":       {"vr_block_exec_check"},
	"drop-capability":  {"vr_drop_capability_check"},
}

// LSMObjectDir is the directory holding the compiled LSM object files
// (<primitive>.o). Overridable via VERONICA_LSM_OBJ_DIR; defaults to the source
// tree's lsm program dir where the VM build writes the objects.
func LSMObjectDir() string {
	if d := os.Getenv("VERONICA_LSM_OBJ_DIR"); d != "" {
		return d
	}
	return "internal/ebpf/programs/lsm"
}

// LSMManager loads and attaches the LSM enforcement primitives and owns the
// kernel-side policy state (one loaded program set per applied policy). It is
// the kernel half of the control.PolicyStore: the daemon calls Apply/SetMode/
// Revert here as the warden drives the audit→confirm→enforce lifecycle.
type LSMManager struct {
	mu       sync.Mutex
	policies map[string]*lsmPolicy
}

// lsmPolicy is one applied primitive: its loaded collection, the attached links,
// and the shared control maps so mode can be flipped and audit counts read.
type lsmPolicy struct {
	primitive string
	coll      *ebpf.Collection
	links     []link.Link
}

// NewLSMManager returns an empty LSM manager.
func NewLSMManager() *LSMManager {
	return &LSMManager{policies: make(map[string]*lsmPolicy)}
}

// Apply loads the primitive's object, programs its scope (the target cgroup
// fd from cgroupPath) and params, attaches the LSM hooks in AUDIT mode, and
// records it under policyID. Audit-first: the program starts in audit mode and
// only Enforce flips it. Returns an error if the kernel lacks BPF-LSM.
func (m *LSMManager) Apply(policyID, primitiveID, cgroupPath string, params map[string]any) error {
	progs, ok := primitivePrograms[primitiveID]
	if !ok {
		return fmt.Errorf("unknown primitive %q", primitiveID)
	}

	objPath := filepath.Join(LSMObjectDir(), objFileName(primitiveID))
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load %s object: %w", primitiveID, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create %s collection: %w", primitiveID, err)
	}

	pol := &lsmPolicy{primitive: primitiveID, coll: coll}

	if err := setScope(coll, cgroupPath); err != nil {
		coll.Close()
		return err
	}
	if err := setMode(coll, lsmModeAudit); err != nil {
		coll.Close()
		return err
	}
	if err := programParams(coll, primitiveID, params); err != nil {
		coll.Close()
		return err
	}

	for _, name := range progs {
		prog := coll.Programs[name]
		if prog == nil {
			pol.detach()
			return fmt.Errorf("program %q missing from %s object", name, primitiveID)
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			pol.detach()
			return fmt.Errorf("attach %s: %w", name, err)
		}
		pol.links = append(pol.links, l)
	}

	m.mu.Lock()
	m.policies[policyID] = pol
	m.mu.Unlock()
	return nil
}

// SetMode flips a loaded policy between audit and enforce by writing vr_mode.
func (m *LSMManager) SetMode(policyID string, enforce bool) error {
	m.mu.Lock()
	pol, ok := m.policies[policyID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("policy %q not loaded", policyID)
	}
	mode := lsmModeAudit
	if enforce {
		mode = lsmModeEnforce
	}
	return setMode(pol.coll, mode)
}

// AuditCount reads the per-CPU would-block counter for a loaded policy.
func (m *LSMManager) AuditCount(policyID string) (uint64, error) {
	m.mu.Lock()
	pol, ok := m.policies[policyID]
	m.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("policy %q not loaded", policyID)
	}
	return readAuditCount(pol.coll)
}

// Revert detaches and unloads a policy's programs (its enforcement disappears).
func (m *LSMManager) Revert(policyID string) error {
	m.mu.Lock()
	pol, ok := m.policies[policyID]
	delete(m.policies, policyID)
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("policy %q not loaded", policyID)
	}
	pol.detach()
	return nil
}

// KillSwitch reverts every loaded policy and returns the count removed.
func (m *LSMManager) KillSwitch() int {
	m.mu.Lock()
	pols := m.policies
	m.policies = make(map[string]*lsmPolicy)
	m.mu.Unlock()
	for _, pol := range pols {
		pol.detach()
	}
	return len(pols)
}

func (p *lsmPolicy) detach() {
	for _, l := range p.links {
		_ = l.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
}

// objFileName is the compiled object name for a primitive id
// (block-path-write -> block_path_write.o).
func objFileName(primitiveID string) string {
	return strings.ReplaceAll(primitiveID, "-", "_") + ".o"
}

// setMode writes index 0 of vr_mode.
func setMode(coll *ebpf.Collection, mode uint8) error {
	m := coll.Maps["vr_mode"]
	if m == nil {
		return errors.New("vr_mode map missing")
	}
	return m.Put(uint32(0), mode)
}

// setScope installs the target cgroup fd at index 0 of the vr_scope cgroup
// array, so bpf_current_task_under_cgroup scopes enforcement to that cgroup.
func setScope(coll *ebpf.Collection, cgroupPath string) error {
	m := coll.Maps["vr_scope"]
	if m == nil {
		return errors.New("vr_scope map missing")
	}
	full := cgroupPath
	if !strings.HasPrefix(full, "/sys/fs/cgroup") {
		full = filepath.Join("/sys/fs/cgroup", cgroupPath)
	}
	f, err := os.Open(full)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", full, err)
	}
	defer f.Close()
	return m.Put(uint32(0), uint32(f.Fd()))
}

// readAuditCount sums the per-CPU vr_audit_count entry at index 0.
func readAuditCount(coll *ebpf.Collection) (uint64, error) {
	m := coll.Maps["vr_audit_count"]
	if m == nil {
		return 0, errors.New("vr_audit_count map missing")
	}
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// programParams writes the primitive-specific param maps from the validated
// policy params.
func programParams(coll *ebpf.Collection, primitiveID string, params map[string]any) error {
	switch primitiveID {
	case "block-path-write":
		return putPrefix(coll, "vr_prefix", stringParam(params, "path_prefix"))
	case "block-mount":
		return putPrefix(coll, "vr_mount_prefix", stringParam(params, "path_prefix"))
	case "block-egress":
		return putAllowCIDRs(coll, stringSliceParam(params, "allow_cidrs"))
	case "block-exec":
		return putBlockedBinaries(coll, stringSliceParam(params, "binaries"))
	case "drop-capability":
		return putDroppedCaps(coll, stringSliceParam(params, "caps"))
	}
	return fmt.Errorf("unknown primitive %q", primitiveID)
}

// putPrefix writes a NUL-terminated prefix string into a 256-byte array map.
func putPrefix(coll *ebpf.Collection, mapName, prefix string) error {
	m := coll.Maps[mapName]
	if m == nil {
		return fmt.Errorf("%s map missing", mapName)
	}
	var buf [256]byte
	copy(buf[:255], prefix)
	return m.Put(uint32(0), buf)
}

// cidrKey mirrors the C struct vr_cidr_key (prefixlen + 4 IPv4 bytes) for the
// LPM trie.
type cidrKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

// putAllowCIDRs parses each CIDR and inserts it into the vr_allow_cidrs LPM trie.
func putAllowCIDRs(coll *ebpf.Collection, cidrs []string) error {
	m := coll.Maps["vr_allow_cidrs"]
	if m == nil {
		return errors.New("vr_allow_cidrs map missing")
	}
	for _, c := range cidrs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			// Allow a bare IP to mean a /32.
			addr, aerr := netip.ParseAddr(c)
			if aerr != nil || !addr.Is4() {
				return fmt.Errorf("bad allow_cidr %q: %w", c, err)
			}
			pfx = netip.PrefixFrom(addr, 32)
		}
		if !pfx.Addr().Is4() {
			return fmt.Errorf("only IPv4 CIDRs are supported, got %q", c)
		}
		key := cidrKey{PrefixLen: uint32(pfx.Bits()), Addr: pfx.Addr().As4()}
		if err := m.Put(key, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

// putBlockedBinaries hashes each binary basename (FNV-1a 64-bit, matching the
// kernel program) and inserts it into vr_blocked_bins.
func putBlockedBinaries(coll *ebpf.Collection, binaries []string) error {
	m := coll.Maps["vr_blocked_bins"]
	if m == nil {
		return errors.New("vr_blocked_bins map missing")
	}
	for _, b := range binaries {
		key := fnv1a64(filepath.Base(b))
		if err := m.Put(key, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

// capNumbers maps capability names to their integer numbers (the subset the v1
// catalog cares about; extend as needed).
var capNumbers = map[string]int32{
	"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2,
	"CAP_FOWNER": 3, "CAP_FSETID": 4, "CAP_KILL": 5, "CAP_SETGID": 6,
	"CAP_SETUID": 7, "CAP_SETPCAP": 8, "CAP_NET_BIND_SERVICE": 10,
	"CAP_NET_RAW": 13, "CAP_NET_ADMIN": 12, "CAP_SYS_CHROOT": 18,
	"CAP_SYS_PTRACE": 19, "CAP_SYS_ADMIN": 21, "CAP_SYS_BOOT": 22,
	"CAP_SYS_NICE": 23, "CAP_SYS_TIME": 25, "CAP_MKNOD": 27,
	"CAP_AUDIT_WRITE": 29, "CAP_SETFCAP": 31, "CAP_BPF": 39,
}

// putDroppedCaps resolves each capability name to its number and inserts it.
func putDroppedCaps(coll *ebpf.Collection, caps []string) error {
	m := coll.Maps["vr_dropped_caps"]
	if m == nil {
		return errors.New("vr_dropped_caps map missing")
	}
	for _, name := range caps {
		num, ok := capNumbers[strings.ToUpper(strings.TrimSpace(name))]
		if !ok {
			return fmt.Errorf("unknown capability %q", name)
		}
		if err := m.Put(num, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

// fnv1a64 hashes a string identically to the kernel program's vr_fnv1a.
func fnv1a64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// putPrefix/putAllowCIDRs etc. write validated params; the daemon validates
// params against the catalog schema (internal/control.ValidateParams) before
// calling Apply, so these never see malformed shapes.

// stringParam extracts a string param, defaulting to "".
func stringParam(params map[string]any, key string) string {
	v, _ := params[key].(string)
	return v
}

// stringSliceParam extracts an array-of-string param, tolerating both []string
// and the []any shape JSON decoding produces.
func stringSliceParam(params map[string]any, key string) []string {
	switch v := params[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
