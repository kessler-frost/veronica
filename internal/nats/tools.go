package nats

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
	"time"
	"unicode"

	json "github.com/goccy/go-json"

	"github.com/nats-io/nats.go"

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

type ProgramListRequest struct{}

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

// EBPFMaps provides access to loaded eBPF maps. Nil-safe — handlers
// fall back to error responses when no maps are available.
type EBPFMaps interface {
	List() []string
	Lookup(mapName string, key any, valueOut any) error
	Put(mapName string, key any, value any) error
	Delete(mapName string, key any) error
	DumpAll(mapName string) ([]vebpf.MapEntry, error)
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

// shellQuote wraps a string in single quotes, escaping embedded quotes.
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

	// Parse match: "dport=80" or "dst=10.0.0.1"
	matchParts := strings.SplitN(req.Match, "=", 2)
	if len(matchParts) != 2 {
		return "", fmt.Errorf("invalid match format %q (want key=value, e.g. dport=80)", req.Match)
	}
	matchKey, matchVal := matchParts[0], matchParts[1]

	// Parse rewrite: "dport=8080" or "dst=10.0.0.2"
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
		// Target is an IP or interface — show socket stats
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

// --- Tool responder registration ---

// RegisterToolResponders sets up NATS request/reply handlers for all daemon tools.
// pub is used for PID tracking, maps provides direct eBPF map access (nil = map tools disabled).
func RegisterToolResponders(nc *nats.Conn, pub *Publisher, maps EBPFMaps) error {
	subs := []struct {
		subject string
		handler nats.MsgHandler
	}{
		{"tools.exec", handleExec(pub)},
		{"tools.enforce", handleEnforce(pub)},
		{"tools.transform", handleTransform(pub)},
		{"tools.schedule", handleSchedule(pub)},
		{"tools.measure", handleMeasure(pub)},
		{"tools.map.read", handleMapRead(maps)},
		{"tools.map.write", handleMapWrite(maps)},
		{"tools.map.delete", handleMapDelete(maps)},
		{"tools.program.list", handleProgramList(maps)},
		{"tools.program.load", handleProgramLoad(pub)},
		{"tools.program.detach", handleProgramDetach(pub)},
	}

	for _, s := range subs {
		if _, err := nc.Subscribe(s.subject, s.handler); err != nil {
			return fmt.Errorf("subscribe %s: %w", s.subject, err)
		}
	}
	return nil
}

// --- Handlers ---

func handleExec(pub *Publisher) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req ExecRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL exec [%s]: %s", req.Reason, req.Command)

		if isDangerous(req.Command) {
			log.Printf("TOOL exec DENIED (dangerous): %s", req.Command)
			respond(msg, ToolResult{Ok: false, Error: "DENIED: command matches dangerous pattern"})
			return
		}

		output, err := runTracked(context.Background(), req.Command, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: output})
	}
}

func handleEnforce(pub *Publisher) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req EnforceRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL enforce [%s]: %s %s %s", req.Reason, req.Hook, req.Target, req.Action)

		cmd, err := BuildEnforceCmd(req)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		output, err := runTracked(context.Background(), cmd, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("enforce %s %s on %s", req.Action, req.Hook, req.Target)})
	}
}

func handleTransform(pub *Publisher) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req TransformRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL transform [%s]: iface=%s match=%s rewrite=%s", req.Reason, req.Interface, req.Match, req.Rewrite)

		cmd, err := BuildTransformCmd(req)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		output, err := runTracked(context.Background(), cmd, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("transform on %s: %s → %s", req.Interface, req.Match, req.Rewrite)})
	}
}

func handleSchedule(pub *Publisher) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req ScheduleRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL schedule [%s]: target=%s priority=%s", req.Reason, req.Target, req.Priority)

		cmd, err := BuildScheduleCmd(req)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		output, err := runTracked(context.Background(), cmd, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("scheduled %s as %s", req.Target, req.Priority)})
	}
}

func handleMeasure(pub *Publisher) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req MeasureRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL measure: target=%s metric=%s duration=%s", req.Target, req.Metric, req.Duration)

		cmd, err := BuildMeasureCmd(req)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		output, err := runTracked(context.Background(), cmd, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: output})
	}
}

func handleMapRead(maps EBPFMaps) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req MapReadRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL map.read: map=%s key=%q", req.Map, req.Key)

		if maps == nil {
			respond(msg, ToolResult{Ok: false, Error: "eBPF maps not available"})
			return
		}
		if err := validateMapName(req.Map); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		if req.Key == "" {
			entries, err := maps.DumpAll(req.Map)
			if err != nil {
				respond(msg, ToolResult{Ok: false, Error: err.Error()})
				return
			}
			result := make([]map[string]string, 0, len(entries))
			for _, e := range entries {
				result = append(result, map[string]string{
					"key":   hex.EncodeToString(e.Key),
					"value": hex.EncodeToString(e.Value),
				})
			}
			data, _ := json.Marshal(result)
			respond(msg, ToolResult{Ok: true, Data: string(data)})
			return
		}

		if err := validateHexKey(req.Key); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		key, _ := hex.DecodeString(strings.ReplaceAll(req.Key, " ", ""))
		var value []byte
		if err := maps.Lookup(req.Map, key, &value); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: hex.EncodeToString(value)})
	}
}

func handleMapWrite(maps EBPFMaps) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req MapWriteRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL map.write: map=%s key=%q value=%q", req.Map, req.Key, req.Value)

		if maps == nil {
			respond(msg, ToolResult{Ok: false, Error: "eBPF maps not available"})
			return
		}
		if err := validateMapName(req.Map); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		if err := validateHexKey(req.Key); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		if err := validateHexKey(req.Value); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Errorf("invalid hex value: %w", err).Error()})
			return
		}

		key, _ := hex.DecodeString(strings.ReplaceAll(req.Key, " ", ""))
		value, _ := hex.DecodeString(strings.ReplaceAll(req.Value, " ", ""))
		if err := maps.Put(req.Map, key, value); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("map write %s[%s]", req.Map, req.Key)})
	}
}

func handleMapDelete(maps EBPFMaps) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req MapDeleteRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL map.delete: map=%s key=%q", req.Map, req.Key)

		if maps == nil {
			respond(msg, ToolResult{Ok: false, Error: "eBPF maps not available"})
			return
		}
		if err := validateMapName(req.Map); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		if err := validateHexKey(req.Key); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		key, _ := hex.DecodeString(strings.ReplaceAll(req.Key, " ", ""))
		if err := maps.Delete(req.Map, key); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("map delete %s[%s]", req.Map, req.Key)})
	}
}

func handleProgramList(maps EBPFMaps) nats.MsgHandler {
	return func(msg *nats.Msg) {
		log.Printf("TOOL program.list")

		if maps == nil {
			respond(msg, ToolResult{Ok: false, Error: "eBPF maps not available"})
			return
		}
		names := maps.List()
		data, _ := json.Marshal(names)
		respond(msg, ToolResult{Ok: true, Data: string(data)})
	}
}

func handleProgramLoad(pub *Publisher) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req ProgramLoadRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL program.load: path=%s pin=%s", req.Path, req.Pin)

		if err := validatePath(req.Path); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}
		if err := validatePinName(req.Pin); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		cmd := fmt.Sprintf("bpftool prog load %s /sys/fs/bpf/%s", shellQuote(req.Path), req.Pin)
		output, err := runTracked(context.Background(), cmd, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("loaded %s pinned at /sys/fs/bpf/%s", req.Path, req.Pin)})
	}
}

func handleProgramDetach(pub *Publisher) nats.MsgHandler {
	return func(msg *nats.Msg) {
		var req ProgramDetachRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			respond(msg, ToolResult{Ok: false, Error: fmt.Sprintf("bad request: %v", err)})
			return
		}
		log.Printf("TOOL program.detach: pin=%s", req.Pin)

		if err := validatePinName(req.Pin); err != nil {
			respond(msg, ToolResult{Ok: false, Error: err.Error()})
			return
		}

		cmd := fmt.Sprintf("rm -f /sys/fs/bpf/%s", req.Pin)
		output, err := runTracked(context.Background(), cmd, pub)
		if err != nil {
			respond(msg, ToolResult{Ok: false, Error: output})
			return
		}
		respond(msg, ToolResult{Ok: true, Data: fmt.Sprintf("detached %s", req.Pin)})
	}
}

// --- Helpers ---

func runTracked(ctx context.Context, command string, pub *Publisher) (string, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return err.Error(), err
	}
	if pub != nil {
		pid := uint32(cmd.Process.Pid)
		pub.TrackPID(pid)
		defer pub.UntrackPID(pid)
	}

	err := cmd.Wait()
	output := strings.TrimSpace(buf.String())

	if err != nil {
		return output, err
	}
	return output, nil
}

func respond(msg *nats.Msg, result ToolResult) {
	data, _ := json.Marshal(result)
	if err := msg.Respond(data); err != nil {
		log.Printf("respond: %v", err)
	}
}

func isDangerous(cmd string) bool {
	lower := strings.ToLower(cmd)

	// Exact root-destructive patterns (must not match subpaths like /tmp/foo)
	rootDestructive := []string{
		"rm -rf /\n", "rm -rf /;", "rm -rf / ", "rm -rf /\"", "rm -rf /'",
		"rm -rf /*", "chmod -r 777 /\n", "chmod -r 777 / ", "chmod -r 777 /;",
	}
	// Append newline to catch end-of-command
	padded := lower + "\n"
	for _, pattern := range rootDestructive {
		if strings.Contains(padded, pattern) {
			return true
		}
	}

	// Always dangerous regardless of path
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
