package control

import (
	"context"
	"testing"
	"time"
)

// fakeProcSource is an injectable proc-source returning a fixed slice, so the
// resolve_app handler is host-testable without /proc.
type fakeProcSource struct {
	procs []ProcInfo
	err   error
}

func (f fakeProcSource) Procs() ([]ProcInfo, error) { return f.procs, f.err }

// newTestHandlers wires Handlers with a fake proc-source and a frozen clock so
// audit/aggregation tests are deterministic.
func newTestHandlers(procs []ProcInfo) *Handlers {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	h := NewHandlers(fakeProcSource{procs: procs})
	h.store.now = func() time.Time { return now }
	return h
}

func TestResolveAppHandler(t *testing.T) {
	h := newTestHandlers(dockerProcs())
	ctx := context.Background()

	tests := []struct {
		name    string
		input   map[string]any
		wantErr bool
		wantPID []int
	}{
		{name: "resolves docker", input: map[string]any{"name": "docker"}, wantPID: []int{4521, 4530}},
		{name: "no match errors", input: map[string]any{"name": "nginx"}, wantErr: true},
		{name: "missing name errors", input: map[string]any{}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := h.ResolveApp(ctx, tc.input)
			ref, ok := out.(AppRef)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !ok {
				t.Fatalf("want AppRef, got %T", out)
			}
			if len(ref.PIDs) != len(tc.wantPID) {
				t.Fatalf("PIDs = %v, want %v", ref.PIDs, tc.wantPID)
			}
		})
	}
}

func TestListPrimitivesHandler(t *testing.T) {
	h := newTestHandlers(nil)
	out, err := h.ListPrimitives(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prims, ok := out.([]Primitive)
	if !ok {
		t.Fatalf("want []Primitive, got %T", out)
	}
	if len(prims) != 5 {
		t.Fatalf("want 5 primitives, got %d", len(prims))
	}
	for _, p := range prims {
		if len(p.Hooks) == 0 {
			t.Fatalf("primitive %q has no hooks", p.ID)
		}
	}
}

func TestApplyPolicyHandlerAuditFirst(t *testing.T) {
	h := newTestHandlers(dockerProcs())
	ctx := context.Background()
	app := AppRef{Name: "docker", CgroupPath: "/sys/fs/cgroup/system.slice/docker.service", PIDs: []int{100}}

	// Audit-first: applying in enforce mode is rejected.
	_, err := h.ApplyPolicy(ctx, map[string]any{
		"primitive_id": "block-mount",
		"params":       map[string]any{"path_prefix": "/var/lib/docker/volumes"},
		"mode":         "enforce",
		"app":          appToMap(app),
	})
	if err == nil {
		t.Fatal("expected enforce-on-create to be rejected (audit-first)")
	}

	// Audit mode is accepted and returns a Policy in audit mode.
	out, err := h.ApplyPolicy(ctx, map[string]any{
		"primitive_id": "block-mount",
		"params":       map[string]any{"path_prefix": "/var/lib/docker/volumes"},
		"mode":         "audit",
		"app":          appToMap(app),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, ok := out.(Policy)
	if !ok {
		t.Fatalf("want Policy, got %T", out)
	}
	if pol.Mode != ModeAudit {
		t.Fatalf("mode = %q, want audit", pol.Mode)
	}
}

func TestApplyPolicyHandlerGuardList(t *testing.T) {
	h := newTestHandlers(nil)
	ctx := context.Background()
	guarded := AppRef{Name: "sshd", CgroupPath: "/sys/fs/cgroup/system.slice/ssh.service", PIDs: []int{50}}

	_, err := h.ApplyPolicy(ctx, map[string]any{
		"primitive_id": "block-exec",
		"params":       map[string]any{"binaries": []any{"/bin/sh"}},
		"mode":         "audit",
		"app":          appToMap(guarded),
	})
	if err == nil {
		t.Fatal("expected guard list to refuse targeting sshd")
	}
}

func TestSetPolicyModeAndListPolicies(t *testing.T) {
	h := newTestHandlers(nil)
	ctx := context.Background()
	app := AppRef{Name: "docker", PIDs: []int{100}}

	out, err := h.ApplyPolicy(ctx, map[string]any{
		"primitive_id": "block-mount",
		"params":       map[string]any{},
		"mode":         "audit",
		"app":          appToMap(app),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	id := out.(Policy).ID

	// Flip to enforce via set_policy_mode.
	moved, err := h.SetPolicyMode(ctx, map[string]any{"policy_id": id, "mode": "enforce"})
	if err != nil {
		t.Fatalf("set mode: %v", err)
	}
	if moved.(Policy).Mode != ModeEnforce {
		t.Fatalf("mode = %q, want enforce", moved.(Policy).Mode)
	}

	listed, err := h.ListPolicies(ctx, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if n := len(listed.([]Policy)); n != 1 {
		t.Fatalf("want 1 policy, got %d", n)
	}
}

func TestRevertPolicyHandler(t *testing.T) {
	h := newTestHandlers(nil)
	ctx := context.Background()
	app := AppRef{Name: "docker", PIDs: []int{100}}

	out, _ := h.ApplyPolicy(ctx, map[string]any{
		"primitive_id": "block-mount",
		"params":       map[string]any{},
		"mode":         "audit",
		"app":          appToMap(app),
	})
	id := out.(Policy).ID

	res, err := h.RevertPolicy(ctx, map[string]any{"policy_id": id})
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if !res.(OK).Ok {
		t.Fatal("expected ok=true")
	}

	// Reverting an unknown id errors.
	if _, err := h.RevertPolicy(ctx, map[string]any{"policy_id": "pol-999"}); err == nil {
		t.Fatal("expected error reverting unknown policy")
	}
}

func TestKillSwitchHandlerRevertsAll(t *testing.T) {
	h := newTestHandlers(nil)
	ctx := context.Background()
	app := AppRef{Name: "docker", PIDs: []int{100}}

	for i := 0; i < 3; i++ {
		if _, err := h.ApplyPolicy(ctx, map[string]any{
			"primitive_id": "block-mount",
			"params":       map[string]any{},
			"mode":         "audit",
			"app":          appToMap(app),
		}); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}

	out, err := h.KillSwitch(ctx, nil)
	if err != nil {
		t.Fatalf("kill_switch: %v", err)
	}
	res := out.(OK)
	if !res.Ok {
		t.Fatal("expected ok=true")
	}
	if res.Reverted != 3 {
		t.Fatalf("reverted = %d, want 3", res.Reverted)
	}
	if got, _ := h.ListPolicies(ctx, nil); len(got.([]Policy)) != 0 {
		t.Fatal("expected all policies reverted")
	}
}

func TestObserveHandlerReturnsSnapshot(t *testing.T) {
	h := newTestHandlers(nil)
	ctx := context.Background()
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	// Seed the app's aggregator with in-window and out-of-window events.
	agg := h.aggregatorFor("docker")
	agg.now = func() time.Time { return now }
	agg.Add(Event{Kind: KindFile, At: now.Add(-5 * time.Second), Path: "/etc/hosts", Write: true})
	agg.Add(Event{Kind: KindFile, At: now.Add(-5 * time.Second), Path: "/etc/hosts", Write: true})
	agg.Add(Event{Kind: KindNet, At: now.Add(-2 * time.Second), DestAddr: "1.1.1.1", DestPort: 443})
	agg.Add(Event{Kind: KindExec, At: now.Add(-90 * time.Second), Path: "/bin/old"}) // outside window

	out, err := h.Observe(ctx, map[string]any{"app": "docker", "window_secs": 30})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	act, ok := out.(Activity)
	if !ok {
		t.Fatalf("want Activity, got %T", out)
	}
	if act.App != "docker" || act.Window != 30 {
		t.Fatalf("app/window = %q/%d, want docker/30", act.App, act.Window)
	}
	if len(act.Files) != 1 || act.Files[0].Count != 2 {
		t.Fatalf("files = %+v, want 1 entry count 2", act.Files)
	}
	if len(act.Net) != 1 {
		t.Fatalf("net = %+v, want 1 entry", act.Net)
	}
	if len(act.Execs) != 0 {
		t.Fatalf("execs = %+v, want 0 (out of window)", act.Execs)
	}
}

// appToMap mirrors how the warden would send an AppRef over the Agentfield
// JSON transport (map[string]any), so handler decoding is exercised honestly.
func appToMap(app AppRef) map[string]any {
	pids := make([]any, len(app.PIDs))
	for i, p := range app.PIDs {
		pids[i] = float64(p) // JSON numbers decode to float64
	}
	return map[string]any{
		"name":        app.Name,
		"cgroup_path": app.CgroupPath,
		"pids":        pids,
	}
}
