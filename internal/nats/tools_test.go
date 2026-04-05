package nats

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/fimbulwinter/veronica/internal/classifier"
)

// --- Command builder unit tests ---

func TestBuildEnforceCmd_FileDeny(t *testing.T) {
	cmd, err := BuildEnforceCmd(EnforceRequest{Hook: "file_open", Target: "/etc/shadow", Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "chmod a-rwx '/etc/shadow'" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildEnforceCmd_FileAllow(t *testing.T) {
	cmd, err := BuildEnforceCmd(EnforceRequest{Hook: "file_open", Target: "/etc/shadow", Action: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "chmod 644 '/etc/shadow'" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildEnforceCmd_XDPDeny(t *testing.T) {
	cmd, err := BuildEnforceCmd(EnforceRequest{Hook: "xdp_drop", Target: "1.2.3.4", Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	want := "iptables -I INPUT -s 1.2.3.4 -j DROP && iptables -I OUTPUT -d 1.2.3.4 -j DROP"
	if cmd != want {
		t.Fatalf("got: %s\nwant: %s", cmd, want)
	}
}

func TestBuildEnforceCmd_XDPAllow(t *testing.T) {
	cmd, err := BuildEnforceCmd(EnforceRequest{Hook: "xdp_drop", Target: "10.0.0.1", Action: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	want := "iptables -D INPUT -s 10.0.0.1 -j DROP 2>/dev/null; iptables -D OUTPUT -d 10.0.0.1 -j DROP 2>/dev/null; true"
	if cmd != want {
		t.Fatalf("got: %s\nwant: %s", cmd, want)
	}
}

func TestBuildEnforceCmd_InvalidIP(t *testing.T) {
	_, err := BuildEnforceCmd(EnforceRequest{Hook: "xdp_drop", Target: "not-an-ip", Action: "deny"})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestBuildEnforceCmd_ShellInjection(t *testing.T) {
	_, err := BuildEnforceCmd(EnforceRequest{Hook: "file_open", Target: "/etc/shadow; rm -rf /", Action: "deny"})
	if err == nil {
		t.Fatal("expected error for shell metacharacters")
	}
}

func TestBuildEnforceCmd_UnknownHook(t *testing.T) {
	_, err := BuildEnforceCmd(EnforceRequest{Hook: "bogus", Target: "x", Action: "deny"})
	if err == nil {
		t.Fatal("expected error for unknown hook")
	}
}

func TestBuildTransformCmd_PortRedirect(t *testing.T) {
	cmd, err := BuildTransformCmd(TransformRequest{Interface: "eth0", Match: "dport=80", Rewrite: "dport=8080"})
	if err != nil {
		t.Fatal(err)
	}
	want := "iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080"
	if cmd != want {
		t.Fatalf("got: %s\nwant: %s", cmd, want)
	}
}

func TestBuildTransformCmd_DNAT(t *testing.T) {
	cmd, err := BuildTransformCmd(TransformRequest{Interface: "eth0", Match: "dst=10.0.0.1", Rewrite: "dst=10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	want := "iptables -t nat -A PREROUTING -i eth0 -d 10.0.0.1 -j DNAT --to-destination 10.0.0.2"
	if cmd != want {
		t.Fatalf("got: %s\nwant: %s", cmd, want)
	}
}

func TestBuildTransformCmd_InvalidInterface(t *testing.T) {
	_, err := BuildTransformCmd(TransformRequest{Interface: "eth0; rm -rf /", Match: "dport=80", Rewrite: "dport=8080"})
	if err == nil {
		t.Fatal("expected error for invalid interface")
	}
}

func TestBuildTransformCmd_InvalidMatch(t *testing.T) {
	_, err := BuildTransformCmd(TransformRequest{Interface: "eth0", Match: "garbage", Rewrite: "dport=8080"})
	if err == nil {
		t.Fatal("expected error for bad match format")
	}
}

func TestBuildScheduleCmd_LatencySensitive(t *testing.T) {
	cmd, err := BuildScheduleCmd(ScheduleRequest{Target: "1234", Priority: "latency-sensitive"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "renice -n -10 -p 1234" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildScheduleCmd_Batch(t *testing.T) {
	cmd, err := BuildScheduleCmd(ScheduleRequest{Target: "5678", Priority: "batch"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "renice -n 19 -p 5678" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildScheduleCmd_Normal(t *testing.T) {
	cmd, err := BuildScheduleCmd(ScheduleRequest{Target: "999", Priority: "normal"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "renice -n 0 -p 999" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildScheduleCmd_InvalidPID(t *testing.T) {
	_, err := BuildScheduleCmd(ScheduleRequest{Target: "not-a-pid", Priority: "batch"})
	if err == nil {
		t.Fatal("expected error for invalid PID")
	}
}

func TestBuildScheduleCmd_UnknownPriority(t *testing.T) {
	_, err := BuildScheduleCmd(ScheduleRequest{Target: "123", Priority: "ultra-fast"})
	if err == nil {
		t.Fatal("expected error for unknown priority")
	}
}

func TestBuildMeasureCmd_CacheMisses(t *testing.T) {
	cmd, err := BuildMeasureCmd(MeasureRequest{Target: "1234", Metric: "cache_misses", Duration: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "perf stat -e cache-misses -p 1234 sleep 5 2>&1" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildMeasureCmd_Cycles(t *testing.T) {
	cmd, err := BuildMeasureCmd(MeasureRequest{Target: "42", Metric: "cycles", Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "perf stat -e cycles -p 42 sleep 1 2>&1" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildMeasureCmd_Bandwidth(t *testing.T) {
	cmd, err := BuildMeasureCmd(MeasureRequest{Target: "10.0.0.1", Metric: "bandwidth", Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "ss -tnip | grep -F '10.0.0.1' || true" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildMeasureCmd_IO(t *testing.T) {
	cmd, err := BuildMeasureCmd(MeasureRequest{Target: "1234", Metric: "io", Duration: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "cat /proc/1234/io" {
		t.Fatalf("unexpected cmd: %s", cmd)
	}
}

func TestBuildMeasureCmd_InvalidDuration(t *testing.T) {
	_, err := BuildMeasureCmd(MeasureRequest{Target: "1", Metric: "cycles", Duration: "10m"})
	if err == nil {
		t.Fatal("expected error for duration > 5m")
	}
}

func TestBuildMeasureCmd_UnknownMetric(t *testing.T) {
	_, err := BuildMeasureCmd(MeasureRequest{Target: "1", Metric: "bogus", Duration: "1s"})
	if err == nil {
		t.Fatal("expected error for unknown metric")
	}
}

// --- NATS integration tests ---

func newTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(srv.Close)

	pub := NewPublisher(srv.JS(), classifier.New())
	if err := RegisterToolResponders(srv.Conn(), pub, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	return srv
}

func natsRequest(t *testing.T, srv *Server, subject string, req any) ToolResult {
	t.Helper()
	data, _ := json.Marshal(req)
	msg, err := srv.Conn().Request(subject, data, 5*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subject, err)
	}
	var result ToolResult
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return result
}

func TestToolExec_EchoSucceeds(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.exec", ExecRequest{Command: "echo hello", Reason: "test"})
	if !result.Ok || result.Data != "hello" {
		t.Fatalf("expected ok=true data=hello, got ok=%v data=%q err=%q", result.Ok, result.Data, result.Error)
	}
}

func TestToolExec_DangerousCommandBlocked(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.exec", ExecRequest{Command: "rm -rf /", Reason: "test"})
	if result.Ok {
		t.Fatal("expected dangerous command to be blocked")
	}
}

func TestToolExec_BadJSONReturnsError(t *testing.T) {
	srv := newTestServer(t)
	msg, err := srv.Conn().Request("tools.exec", []byte("not json"), 5*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var result ToolResult
	_ = json.Unmarshal(msg.Data, &result)
	if result.Ok {
		t.Fatal("expected error for bad JSON")
	}
}

func TestToolEnforce_FileDeny(t *testing.T) {
	// Create a temp file and deny access via chmod
	tmp := filepath.Join(t.TempDir(), "testfile")
	_ = os.WriteFile(tmp, []byte("secret"), 0644)

	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.enforce", EnforceRequest{
		Hook: "file_open", Target: tmp, Action: "deny", Reason: "test",
	})
	if !result.Ok {
		t.Fatalf("expected ok, got error: %s", result.Error)
	}

	// Verify file is no longer readable
	info, _ := os.Stat(tmp)
	if info.Mode().Perm()&0444 != 0 {
		t.Fatalf("expected no read permissions, got %s", info.Mode())
	}
}

func TestToolEnforce_FileAllow(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "testfile")
	_ = os.WriteFile(tmp, []byte("data"), 0000)

	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.enforce", EnforceRequest{
		Hook: "file_open", Target: tmp, Action: "allow", Reason: "test",
	})
	if !result.Ok {
		t.Fatalf("expected ok, got error: %s", result.Error)
	}

	info, _ := os.Stat(tmp)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("expected 0644, got %s", info.Mode())
	}
}

func TestToolEnforce_InvalidIP(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.enforce", EnforceRequest{
		Hook: "xdp_drop", Target: "not-an-ip", Action: "deny", Reason: "test",
	})
	if result.Ok {
		t.Fatal("expected error for invalid IP")
	}
}

func TestToolTransform_ValidationError(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.transform", TransformRequest{
		Interface: "eth0", Match: "bad-format", Rewrite: "dport=8080", Reason: "test",
	})
	if result.Ok {
		t.Fatal("expected error for invalid match format")
	}
}

func TestToolSchedule_ValidationError(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.schedule", ScheduleRequest{
		Target: "not-a-pid", Priority: "batch", Reason: "test",
	})
	if result.Ok {
		t.Fatal("expected error for invalid PID")
	}
}

func TestToolMeasure_ValidationError(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.measure", MeasureRequest{
		Target: "1234", Metric: "bogus", Duration: "1s",
	})
	if result.Ok {
		t.Fatal("expected error for unknown metric")
	}
}

func TestToolMapRead_NilMaps(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.map.read", MapReadRequest{Map: "vr_file_policy"})
	if result.Ok {
		t.Fatal("expected error for nil maps")
	}
	if !strings.Contains(result.Error, "not available") {
		t.Fatalf("expected 'not available' error, got: %s", result.Error)
	}
}

func TestToolMapWrite_NilMaps(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.map.write", MapWriteRequest{Map: "vr_file_policy", Key: "01", Value: "01"})
	if result.Ok {
		t.Fatal("expected error for nil maps")
	}
}

func TestToolMapDelete_NilMaps(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.map.delete", MapDeleteRequest{Map: "vr_file_policy", Key: "01"})
	if result.Ok {
		t.Fatal("expected error for nil maps")
	}
}

func TestToolProgramList_NilMaps(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.program.list", ProgramListRequest{})
	if result.Ok {
		t.Fatal("expected error for nil maps")
	}
}

func TestToolProgramLoad_ValidationError(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.program.load", ProgramLoadRequest{Path: "/ok/path.o", Pin: "bad/pin"})
	if result.Ok {
		t.Fatal("expected error for invalid pin name")
	}
}

func TestToolProgramDetach_ValidationError(t *testing.T) {
	srv := newTestServer(t)
	result := natsRequest(t, srv, "tools.program.detach", ProgramDetachRequest{Pin: "../../etc"})
	if result.Ok {
		t.Fatal("expected error for path traversal")
	}
}
