package af

import (
	"strings"
	"testing"
)

func TestBuildEnforceCmd(t *testing.T) {
	tests := []struct {
		name      string
		req       EnforceRequest
		wantErr   bool
		wantParts []string // substrings that must all be present in the command
	}{
		{
			name:      "file_open_deny",
			req:       EnforceRequest{Hook: "file_open", Target: "/etc/shadow", Action: "deny"},
			wantParts: []string{"chmod a-rwx", "'/etc/shadow'"},
		},
		{
			name:      "file_open_allow",
			req:       EnforceRequest{Hook: "file_open", Target: "/etc/passwd", Action: "allow"},
			wantParts: []string{"chmod 644", "'/etc/passwd'"},
		},
		{
			name:    "file_open_unknown_action",
			req:     EnforceRequest{Hook: "file_open", Target: "/etc/x", Action: "frobnicate"},
			wantErr: true,
		},
		{
			name:    "file_open_path_with_metachars",
			req:     EnforceRequest{Hook: "file_open", Target: "/etc/x; rm -rf /", Action: "deny"},
			wantErr: true,
		},
		{
			name:      "xdp_drop_deny",
			req:       EnforceRequest{Hook: "xdp_drop", Target: "185.1.2.3", Action: "deny"},
			wantParts: []string{"iptables -I INPUT -s 185.1.2.3 -j DROP", "iptables -I OUTPUT -d 185.1.2.3 -j DROP"},
		},
		{
			name:      "socket_connect_allow",
			req:       EnforceRequest{Hook: "socket_connect", Target: "10.0.0.5", Action: "allow"},
			wantParts: []string{"iptables -D INPUT -s 10.0.0.5"},
		},
		{
			name:    "xdp_drop_invalid_ip",
			req:     EnforceRequest{Hook: "xdp_drop", Target: "not-an-ip", Action: "deny"},
			wantErr: true,
		},
		{
			name:    "unknown_hook",
			req:     EnforceRequest{Hook: "bogus", Target: "x", Action: "deny"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := BuildEnforceCmd(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got cmd %q", cmd)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, part := range tc.wantParts {
				if !strings.Contains(cmd, part) {
					t.Fatalf("cmd %q missing %q", cmd, part)
				}
			}
		})
	}
}

func TestBuildTransformCmd(t *testing.T) {
	tests := []struct {
		name      string
		req       TransformRequest
		wantErr   bool
		wantParts []string
	}{
		{
			name:      "dport_to_dport",
			req:       TransformRequest{Interface: "eth0", Match: "dport=80", Rewrite: "dport=8080"},
			wantParts: []string{"iptables -t nat", "PREROUTING", "-i eth0", "--dport 80", "--to-port 8080"},
		},
		{
			name:      "dst_to_dst",
			req:       TransformRequest{Interface: "eth0", Match: "dst=1.2.3.4", Rewrite: "dst=5.6.7.8"},
			wantParts: []string{"DNAT", "-d 1.2.3.4", "--to-destination 5.6.7.8"},
		},
		{
			name:    "bad_interface",
			req:     TransformRequest{Interface: "eth0;rm", Match: "dport=80", Rewrite: "dport=8080"},
			wantErr: true,
		},
		{
			name:    "bad_match_format",
			req:     TransformRequest{Interface: "eth0", Match: "dport", Rewrite: "dport=8080"},
			wantErr: true,
		},
		{
			name:    "non_numeric_port",
			req:     TransformRequest{Interface: "eth0", Match: "dport=http", Rewrite: "dport=8080"},
			wantErr: true,
		},
		{
			name:    "bad_dst_ip",
			req:     TransformRequest{Interface: "eth0", Match: "dst=nope", Rewrite: "dst=5.6.7.8"},
			wantErr: true,
		},
		{
			name:    "unsupported_pair",
			req:     TransformRequest{Interface: "eth0", Match: "sport=80", Rewrite: "sport=8080"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := BuildTransformCmd(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got cmd %q", cmd)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, part := range tc.wantParts {
				if !strings.Contains(cmd, part) {
					t.Fatalf("cmd %q missing %q", cmd, part)
				}
			}
		})
	}
}

func TestBuildScheduleCmd(t *testing.T) {
	tests := []struct {
		name     string
		req      ScheduleRequest
		wantErr  bool
		wantNice string
	}{
		{"latency", ScheduleRequest{Target: "1234", Priority: "latency-sensitive"}, false, "renice -n -10 -p 1234"},
		{"batch", ScheduleRequest{Target: "1234", Priority: "batch"}, false, "renice -n 19 -p 1234"},
		{"normal", ScheduleRequest{Target: "1234", Priority: "normal"}, false, "renice -n 0 -p 1234"},
		{"bad_pid", ScheduleRequest{Target: "0", Priority: "normal"}, true, ""},
		{"non_numeric_pid", ScheduleRequest{Target: "abc", Priority: "normal"}, true, ""},
		{"unknown_priority", ScheduleRequest{Target: "1234", Priority: "turbo"}, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := BuildScheduleCmd(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", cmd)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmd != tc.wantNice {
				t.Fatalf("cmd = %q, want %q", cmd, tc.wantNice)
			}
		})
	}
}

func TestBuildMeasureCmd(t *testing.T) {
	tests := []struct {
		name      string
		req       MeasureRequest
		wantErr   bool
		wantParts []string
	}{
		{"cache_misses", MeasureRequest{Target: "1234", Metric: "cache_misses", Duration: "5s"}, false, []string{"perf stat -e cache-misses -p 1234", "sleep 5"}},
		{"cycles", MeasureRequest{Target: "1234", Metric: "cycles", Duration: "1m"}, false, []string{"perf stat -e cycles -p 1234", "sleep 60"}},
		{"bandwidth", MeasureRequest{Target: "1.2.3.4", Metric: "bandwidth", Duration: "5s"}, false, []string{"ss -tnip", "'1.2.3.4'"}},
		{"io", MeasureRequest{Target: "1234", Metric: "io", Duration: "5s"}, false, []string{"cat /proc/1234/io"}},
		{"bad_duration_zero", MeasureRequest{Target: "1234", Metric: "cycles", Duration: "0s"}, true, nil},
		{"bad_duration_too_long", MeasureRequest{Target: "1234", Metric: "cycles", Duration: "10m"}, true, nil},
		{"unparseable_duration", MeasureRequest{Target: "1234", Metric: "cycles", Duration: "soon"}, true, nil},
		{"unknown_metric", MeasureRequest{Target: "1234", Metric: "flops", Duration: "5s"}, true, nil},
		{"cache_misses_bad_pid", MeasureRequest{Target: "x", Metric: "cache_misses", Duration: "5s"}, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := BuildMeasureCmd(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", cmd)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, part := range tc.wantParts {
				if !strings.Contains(cmd, part) {
					t.Fatalf("cmd %q missing %q", cmd, part)
				}
			}
		})
	}
}

func TestIsDangerous(t *testing.T) {
	dangerous := []string{
		"rm -rf /",
		"rm -rf / ",
		"rm -rf /*",
		"RM -RF /",            // case-insensitive
		"mkfs.ext4 /dev/sda1",
		"dd if=/dev/zero of=/dev/sda",
		":(){ :|:& };:",
		"echo x > /dev/sda",
		"shutdown -h now",
		"reboot",
		"poweroff",
		"sudo halt",
	}
	for _, cmd := range dangerous {
		t.Run("dangerous_"+cmd, func(t *testing.T) {
			if !isDangerous(cmd) {
				t.Fatalf("expected %q to be flagged dangerous", cmd)
			}
		})
	}

	safe := []string{
		"ls -la",
		"git status",
		"mkdir -p /tmp/foo",
		"rm -rf /tmp/foo", // scoped to /tmp, not root
		"chmod 644 /etc/hosts",
		"cat /proc/1234/io",
	}
	for _, cmd := range safe {
		t.Run("safe_"+cmd, func(t *testing.T) {
			if isDangerous(cmd) {
				t.Fatalf("expected %q to be allowed", cmd)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"/etc/hosts", false},
		{"/home/user/file.txt", false},
		{"", true},
		{"/etc/x; rm -rf /", true},
		{"/etc/$(whoami)", true},
		{"/etc/`id`", true},
		{"/etc/a|b", true},
		{"/etc/a&b", true},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			err := validatePath(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePath(%q) err=%v, wantErr=%v", tc.path, err, tc.wantErr)
			}
		})
	}
}

func TestValidateMapName(t *testing.T) {
	valid := []string{"process_exec_events", "events", "_x", "Map1"}
	invalid := []string{"", "1events", "has-dash", "has space", "has/slash"}
	for _, s := range valid {
		if err := validateMapName(s); err != nil {
			t.Errorf("expected %q valid, got %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := validateMapName(s); err == nil {
			t.Errorf("expected %q invalid", s)
		}
	}
}

func TestValidateHexKey(t *testing.T) {
	valid := []string{"00", "deadbeef", "DE AD BE EF", "01020304"}
	invalid := []string{"", "   ", "xyz", "0", "gg"}
	for _, s := range valid {
		if err := validateHexKey(s); err != nil {
			t.Errorf("expected %q valid, got %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := validateHexKey(s); err == nil {
			t.Errorf("expected %q invalid", s)
		}
	}
}

func TestValidatePinName(t *testing.T) {
	valid := []string{"my_prog", "prog-1", "ABC123"}
	invalid := []string{"", "../escape", "with/slash", "space here", "semi;colon"}
	for _, s := range valid {
		if err := validatePinName(s); err != nil {
			t.Errorf("expected %q valid, got %v", s, err)
		}
	}
	for _, s := range invalid {
		if err := validatePinName(s); err == nil {
			t.Errorf("expected %q invalid", s)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "'plain'"},
		{"with space", "'with space'"},
		{"it's", `'it'\''s'`},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := shellQuote(tc.in); got != tc.want {
				t.Fatalf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPIDTracker(t *testing.T) {
	tr := NewPIDTracker()
	if tr.IsTracked(42) {
		t.Fatal("expected 42 untracked initially")
	}
	tr.Track(42)
	if !tr.IsTracked(42) {
		t.Fatal("expected 42 tracked after Track")
	}
	tr.Untrack(42)
	if tr.IsTracked(42) {
		t.Fatal("expected 42 untracked after Untrack")
	}
}
