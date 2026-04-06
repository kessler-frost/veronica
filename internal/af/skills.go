package af

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	json "github.com/goccy/go-json"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
)

// --- Request types ---

type ExecRequest struct {
	Command string `json:"command"`
	Reason  string `json:"reason,omitempty"`
}

type EnforceRequest struct {
	Hook   string `json:"hook"`   // "file_open", "socket_connect", "xdp_drop"
	Target string `json:"target"` // path, IP, etc.
	Action string `json:"action"` // "deny" or "allow"
	Reason string `json:"reason"`
}

type TransformRequest struct {
	Interface string `json:"interface"`
	Match     string `json:"match"`
	Rewrite   string `json:"rewrite"`
	Reason    string `json:"reason"`
}

type ScheduleRequest struct {
	Target   string `json:"target"`   // PID or cgroup path
	Priority string `json:"priority"` // "latency-sensitive", "batch", "normal"
	Reason   string `json:"reason"`
}

type MeasureRequest struct {
	Target   string `json:"target"`
	Metric   string `json:"metric"`   // "cache_misses", "cycles", "bandwidth", "io"
	Duration string `json:"duration"` // "5s", "1m"
}

type MapReadRequest struct {
	Map string `json:"map"`
	Key string `json:"key,omitempty"` // hex-encoded; empty = dump all
}

type MapWriteRequest struct {
	Map   string `json:"map"`
	Key   string `json:"key"`   // hex-encoded
	Value string `json:"value"` // hex-encoded
}

type MapDeleteRequest struct {
	Map string `json:"map"`
	Key string `json:"key"` // hex-encoded
}

type ProgramLoadRequest struct {
	Path string `json:"path"` // path to compiled .o file
	Pin  string `json:"pin"`  // pin name under /sys/fs/bpf/
}

type ProgramDetachRequest struct {
	Pin string `json:"pin"` // pin name under /sys/fs/bpf/
}

type ToolResult struct {
	Ok    bool   `json:"ok"`
	Data  string `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// EBPFMaps provides access to loaded eBPF maps.
type EBPFMaps interface {
	List() []string
	Lookup(mapName string, key any, valueOut any) error
	Put(mapName string, key any, value any) error
	Delete(mapName string, key any) error
	DumpAll(mapName string) ([]vebpf.MapEntry, error)
}

// PIDTracker tracks executor PIDs to prevent feedback loops.
type PIDTracker struct {
	pids sync.Map
}

func NewPIDTracker() *PIDTracker { return &PIDTracker{} }

func (t *PIDTracker) Track(pid uint32)   { t.pids.Store(pid, true) }
func (t *PIDTracker) Untrack(pid uint32) { t.pids.Delete(pid) }
func (t *PIDTracker) IsTracked(pid uint32) bool {
	_, ok := t.pids.Load(pid)
	return ok
}

// --- Validation ---

var (
	reAlphaUnderscore = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	rePinName         = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

func validateIP(s string) error {
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP address: %q", s)
	}
	return nil
}

func validatePath(s string) error {
	if s == "" {
		return fmt.Errorf("empty path")
	}
	if strings.ContainsAny(s, ";|&$`\\\"'(){}!") {
		return fmt.Errorf("path contains shell metacharacters: %q", s)
	}
	return nil
}

func validateMapName(s string) error {
	if !reAlphaUnderscore.MatchString(s) {
		return fmt.Errorf("invalid map name: %q (must be alphanumeric + underscore)", s)
	}
	return nil
}

func validateHexKey(s string) error {
	clean := strings.ReplaceAll(s, " ", "")
	if clean == "" {
		return fmt.Errorf("empty hex key")
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}
	return nil
}

func validatePID(s string) error {
	pid, err := strconv.ParseUint(s, 10, 32)
	if err != nil || pid == 0 {
		return fmt.Errorf("invalid PID: %q", s)
	}
	return nil
}

func validatePinName(s string) error {
	if !rePinName.MatchString(s) {
		return fmt.Errorf("invalid pin name: %q", s)
	}
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if d <= 0 || d > 5*time.Minute {
		return 0, fmt.Errorf("duration must be between 0 and 5m, got %s", d)
	}
	return d, nil
}

func validateInterface(s string) error {
	if s == "" {
		return fmt.Errorf("empty interface name")
	}
	for _, c := range s {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' && c != '.' {
			return fmt.Errorf("invalid interface name: %q", s)
		}
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// --- Command builders (exported for testing) ---

func BuildEnforceCmd(req EnforceRequest) (string, error) {
	switch req.Hook {
	case "file_open":
		if err := validatePath(req.Target); err != nil {
			return "", err
		}
		switch req.Action {
		case "deny":
			return fmt.Sprintf("chmod a-rwx %s", shellQuote(req.Target)), nil
		case "allow":
			return fmt.Sprintf("chmod 644 %s", shellQuote(req.Target)), nil
		default:
			return "", fmt.Errorf("unknown action %q for file_open (want deny/allow)", req.Action)
		}

	case "xdp_drop", "socket_connect":
		if err := validateIP(req.Target); err != nil {
			return "", err
		}
		switch req.Action {
		case "deny":
			return fmt.Sprintf("iptables -I INPUT -s %s -j DROP && iptables -I OUTPUT -d %s -j DROP", req.Target, req.Target), nil
		case "allow":
			return fmt.Sprintf("iptables -D INPUT -s %s -j DROP 2>/dev/null; iptables -D OUTPUT -d %s -j DROP 2>/dev/null; true", req.Target, req.Target), nil
		default:
			return "", fmt.Errorf("unknown action %q (want deny/allow)", req.Action)
		}

	default:
		return "", fmt.Errorf("unknown hook %q (want file_open/xdp_drop/socket_connect)", req.Hook)
	}
}

func BuildTransformCmd(req TransformRequest) (string, error) {
	if err := validateInterface(req.Interface); err != nil {
		return "", err
	}

	matchParts := strings.SplitN(req.Match, "=", 2)
	if len(matchParts) != 2 {
		return "", fmt.Errorf("invalid match format %q (want key=value, e.g. dport=80)", req.Match)
	}
	matchKey, matchVal := matchParts[0], matchParts[1]

	rewriteParts := strings.SplitN(req.Rewrite, "=", 2)
	if len(rewriteParts) != 2 {
		return "", fmt.Errorf("invalid rewrite format %q (want key=value, e.g. dport=8080)", req.Rewrite)
	}
	rewriteKey, rewriteVal := rewriteParts[0], rewriteParts[1]

	switch {
	case matchKey == "dport" && rewriteKey == "dport":
		if _, err := strconv.Atoi(matchVal); err != nil {
			return "", fmt.Errorf("invalid match port: %q", matchVal)
		}
		if _, err := strconv.Atoi(rewriteVal); err != nil {
			return "", fmt.Errorf("invalid rewrite port: %q", rewriteVal)
		}
		return fmt.Sprintf("iptables -t nat -A PREROUTING -i %s -p tcp --dport %s -j REDIRECT --to-port %s",
			req.Interface, matchVal, rewriteVal), nil

	case matchKey == "dst" && rewriteKey == "dst":
		if err := validateIP(matchVal); err != nil {
			return "", fmt.Errorf("invalid match IP: %w", err)
		}
		if err := validateIP(rewriteVal); err != nil {
			return "", fmt.Errorf("invalid rewrite IP: %w", err)
		}
		return fmt.Sprintf("iptables -t nat -A PREROUTING -i %s -d %s -j DNAT --to-destination %s",
			req.Interface, matchVal, rewriteVal), nil

	default:
		return "", fmt.Errorf("unsupported transform: match %q rewrite %q (supported: dport→dport, dst→dst)", matchKey, rewriteKey)
	}
}

func BuildScheduleCmd(req ScheduleRequest) (string, error) {
	if err := validatePID(req.Target); err != nil {
		return "", err
	}
	switch req.Priority {
	case "latency-sensitive":
		return fmt.Sprintf("renice -n -10 -p %s", req.Target), nil
	case "batch":
		return fmt.Sprintf("renice -n 19 -p %s", req.Target), nil
	case "normal":
		return fmt.Sprintf("renice -n 0 -p %s", req.Target), nil
	default:
		return "", fmt.Errorf("unknown priority %q (want latency-sensitive/batch/normal)", req.Priority)
	}
}

func BuildMeasureCmd(req MeasureRequest) (string, error) {
	dur, err := parseDuration(req.Duration)
	if err != nil {
		return "", err
	}
	secs := fmt.Sprintf("%d", int(dur.Seconds()))

	switch req.Metric {
	case "cache_misses":
		if err := validatePID(req.Target); err != nil {
			return "", err
		}
		return fmt.Sprintf("perf stat -e cache-misses -p %s sleep %s 2>&1", req.Target, secs), nil
	case "cycles":
		if err := validatePID(req.Target); err != nil {
			return "", err
		}
		return fmt.Sprintf("perf stat -e cycles -p %s sleep %s 2>&1", req.Target, secs), nil
	case "bandwidth":
		return fmt.Sprintf("ss -tnip | grep -F %s || true", shellQuote(req.Target)), nil
	case "io":
		if err := validatePID(req.Target); err != nil {
			return "", err
		}
		return fmt.Sprintf("cat /proc/%s/io", req.Target), nil
	default:
		return "", fmt.Errorf("unknown metric %q (want cache_misses/cycles/bandwidth/io)", req.Metric)
	}
}

// --- Agentfield skill registration ---

// RegisterSkills registers all daemon functions as Agentfield reasoners.
func RegisterSkills(ag *agent.Agent, tracker *PIDTracker, maps EBPFMaps) {
	ag.RegisterReasoner("exec", handleExec(tracker),
		agent.WithDescription("Execute a shell command in the VM"),
	)
	ag.RegisterReasoner("enforce", handleEnforce(tracker),
		agent.WithDescription("Enforce file/network access policies"),
	)
	ag.RegisterReasoner("transform", handleTransform(tracker),
		agent.WithDescription("Apply packet transformation rules via iptables NAT"),
	)
	ag.RegisterReasoner("schedule", handleSchedule(tracker),
		agent.WithDescription("Set CPU scheduling priority for a process"),
	)
	ag.RegisterReasoner("measure", handleMeasure(tracker),
		agent.WithDescription("Measure performance counters for a process"),
	)
	ag.RegisterReasoner("map_read", handleMapRead(maps),
		agent.WithDescription("Read from an eBPF map"),
	)
	ag.RegisterReasoner("map_write", handleMapWrite(maps),
		agent.WithDescription("Write to an eBPF map"),
	)
	ag.RegisterReasoner("map_delete", handleMapDelete(maps),
		agent.WithDescription("Delete a key from an eBPF map"),
	)
	ag.RegisterReasoner("program_list", handleProgramList(maps),
		agent.WithDescription("List loaded eBPF programs and maps"),
	)
	ag.RegisterReasoner("program_load", handleProgramLoad(tracker),
		agent.WithDescription("Load and pin an eBPF program"),
	)
	ag.RegisterReasoner("program_detach", handleProgramDetach(tracker),
		agent.WithDescription("Detach/unpin an eBPF program"),
	)
}

// --- Handlers ---

func result(ok bool, data, errMsg string) map[string]any {
	r := ToolResult{Ok: ok, Data: data, Error: errMsg}
	b, _ := json.Marshal(r)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func okResult(data string) (any, error)    { return result(true, data, ""), nil }
func errResult(msg string) (any, error)    { return result(false, "", msg), nil }
func errResultf(f string, a ...any) (any, error) { return errResult(fmt.Sprintf(f, a...)) }

func parseInput[T any](input map[string]any) (T, error) {
	var req T
	data, err := json.Marshal(input)
	if err != nil {
		return req, err
	}
	err = json.Unmarshal(data, &req)
	return req, err
}

func handleExec(tracker *PIDTracker) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[ExecRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL exec [%s]: %s", req.Reason, req.Command)

		if isDangerous(req.Command) {
			log.Printf("SKILL exec DENIED (dangerous): %s", req.Command)
			return errResult("DENIED: command matches dangerous pattern")
		}

		output, err := runTracked(ctx, req.Command, tracker)
		if err != nil {
			return errResult(output)
		}
		return okResult(output)
	}
}

func handleEnforce(tracker *PIDTracker) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[EnforceRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL enforce [%s]: %s %s %s", req.Reason, req.Hook, req.Target, req.Action)

		cmd, err := BuildEnforceCmd(req)
		if err != nil {
			return errResult(err.Error())
		}

		output, err := runTracked(ctx, cmd, tracker)
		if err != nil {
			return errResult(output)
		}
		return okResult(fmt.Sprintf("enforce %s %s on %s", req.Action, req.Hook, req.Target))
	}
}

func handleTransform(tracker *PIDTracker) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[TransformRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL transform [%s]: iface=%s match=%s rewrite=%s", req.Reason, req.Interface, req.Match, req.Rewrite)

		cmd, err := BuildTransformCmd(req)
		if err != nil {
			return errResult(err.Error())
		}

		output, err := runTracked(ctx, cmd, tracker)
		if err != nil {
			return errResult(output)
		}
		return okResult(fmt.Sprintf("transform on %s: %s → %s", req.Interface, req.Match, req.Rewrite))
	}
}

func handleSchedule(tracker *PIDTracker) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[ScheduleRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL schedule [%s]: target=%s priority=%s", req.Reason, req.Target, req.Priority)

		cmd, err := BuildScheduleCmd(req)
		if err != nil {
			return errResult(err.Error())
		}

		output, err := runTracked(ctx, cmd, tracker)
		if err != nil {
			return errResult(output)
		}
		return okResult(fmt.Sprintf("scheduled %s as %s", req.Target, req.Priority))
	}
}

func handleMeasure(tracker *PIDTracker) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[MeasureRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL measure: target=%s metric=%s duration=%s", req.Target, req.Metric, req.Duration)

		cmd, err := BuildMeasureCmd(req)
		if err != nil {
			return errResult(err.Error())
		}

		output, err := runTracked(ctx, cmd, tracker)
		if err != nil {
			return errResult(output)
		}
		return okResult(output)
	}
}

func handleMapRead(maps EBPFMaps) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[MapReadRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL map_read: map=%s key=%q", req.Map, req.Key)

		if maps == nil {
			return errResult("eBPF maps not available")
		}
		if err := validateMapName(req.Map); err != nil {
			return errResult(err.Error())
		}

		if req.Key == "" {
			entries, err := maps.DumpAll(req.Map)
			if err != nil {
				return errResult(err.Error())
			}
			result := make([]map[string]string, 0, len(entries))
			for _, e := range entries {
				result = append(result, map[string]string{
					"key":   hex.EncodeToString(e.Key),
					"value": hex.EncodeToString(e.Value),
				})
			}
			data, _ := json.Marshal(result)
			return okResult(string(data))
		}

		if err := validateHexKey(req.Key); err != nil {
			return errResult(err.Error())
		}
		key, _ := hex.DecodeString(strings.ReplaceAll(req.Key, " ", ""))
		var value []byte
		if err := maps.Lookup(req.Map, key, &value); err != nil {
			return errResult(err.Error())
		}
		return okResult(hex.EncodeToString(value))
	}
}

func handleMapWrite(maps EBPFMaps) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[MapWriteRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL map_write: map=%s key=%q value=%q", req.Map, req.Key, req.Value)

		if maps == nil {
			return errResult("eBPF maps not available")
		}
		if err := validateMapName(req.Map); err != nil {
			return errResult(err.Error())
		}
		if err := validateHexKey(req.Key); err != nil {
			return errResult(err.Error())
		}
		if err := validateHexKey(req.Value); err != nil {
			return errResult(fmt.Errorf("invalid hex value: %w", err).Error())
		}

		key, _ := hex.DecodeString(strings.ReplaceAll(req.Key, " ", ""))
		value, _ := hex.DecodeString(strings.ReplaceAll(req.Value, " ", ""))
		if err := maps.Put(req.Map, key, value); err != nil {
			return errResult(err.Error())
		}
		return okResult(fmt.Sprintf("map write %s[%s]", req.Map, req.Key))
	}
}

func handleMapDelete(maps EBPFMaps) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[MapDeleteRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL map_delete: map=%s key=%q", req.Map, req.Key)

		if maps == nil {
			return errResult("eBPF maps not available")
		}
		if err := validateMapName(req.Map); err != nil {
			return errResult(err.Error())
		}
		if err := validateHexKey(req.Key); err != nil {
			return errResult(err.Error())
		}

		key, _ := hex.DecodeString(strings.ReplaceAll(req.Key, " ", ""))
		if err := maps.Delete(req.Map, key); err != nil {
			return errResult(err.Error())
		}
		return okResult(fmt.Sprintf("map delete %s[%s]", req.Map, req.Key))
	}
}

func handleProgramList(maps EBPFMaps) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		log.Printf("SKILL program_list")

		if maps == nil {
			return errResult("eBPF maps not available")
		}
		names := maps.List()
		data, _ := json.Marshal(names)
		return okResult(string(data))
	}
}

func handleProgramLoad(tracker *PIDTracker) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[ProgramLoadRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL program_load: path=%s pin=%s", req.Path, req.Pin)

		if err := validatePath(req.Path); err != nil {
			return errResult(err.Error())
		}
		if err := validatePinName(req.Pin); err != nil {
			return errResult(err.Error())
		}

		cmd := fmt.Sprintf("bpftool prog load %s /sys/fs/bpf/%s", shellQuote(req.Path), req.Pin)
		output, err := runTracked(ctx, cmd, tracker)
		if err != nil {
			return errResult(output)
		}
		return okResult(fmt.Sprintf("loaded %s pinned at /sys/fs/bpf/%s", req.Path, req.Pin))
	}
}

func handleProgramDetach(tracker *PIDTracker) func(ctx context.Context, input map[string]any) (any, error) {
	return func(ctx context.Context, input map[string]any) (any, error) {
		req, err := parseInput[ProgramDetachRequest](input)
		if err != nil {
			return errResultf("bad request: %v", err)
		}
		log.Printf("SKILL program_detach: pin=%s", req.Pin)

		if err := validatePinName(req.Pin); err != nil {
			return errResult(err.Error())
		}

		cmd := fmt.Sprintf("rm -f /sys/fs/bpf/%s", req.Pin)
		output, err := runTracked(ctx, cmd, tracker)
		if err != nil {
			return errResult(output)
		}
		return okResult(fmt.Sprintf("detached %s", req.Pin))
	}
}

// --- Helpers ---

func runTracked(ctx context.Context, command string, tracker *PIDTracker) (string, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return err.Error(), err
	}
	if tracker != nil {
		pid := uint32(cmd.Process.Pid)
		tracker.Track(pid)
		defer tracker.Untrack(pid)
	}

	err := cmd.Wait()
	output := strings.TrimSpace(buf.String())

	if err != nil {
		return output, err
	}
	return output, nil
}

func isDangerous(cmd string) bool {
	lower := strings.ToLower(cmd)

	rootDestructive := []string{
		"rm -rf /\n", "rm -rf /;", "rm -rf / ", "rm -rf /\"", "rm -rf /'",
		"rm -rf /*", "chmod -r 777 /\n", "chmod -r 777 / ", "chmod -r 777 /;",
	}
	padded := lower + "\n"
	for _, pattern := range rootDestructive {
		if strings.Contains(padded, pattern) {
			return true
		}
	}

	alwaysDangerous := []string{
		"mkfs", "dd if=/dev/zero", "dd if=/dev/urandom",
		":(){ :|:& };:", "> /dev/sda",
		"shutdown", "reboot", "init 0", "halt", "poweroff",
	}
	for _, pattern := range alwaysDangerous {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
