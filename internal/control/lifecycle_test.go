package control

import "testing"

func dockerApp() AppRef {
	return AppRef{Name: "docker", CgroupPath: "/sys/fs/cgroup/docker", PIDs: []int{4521, 4530}}
}

func TestApply_CreatesAuditPolicy(t *testing.T) {
	s := NewPolicyStore()
	p, err := s.Apply("block-mount", map[string]any{"path_prefix": "/var/lib/docker/volumes"}, dockerApp(), ModeAudit)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if p.Mode != ModeAudit {
		t.Errorf("new policy Mode = %q, want audit", p.Mode)
	}
	if p.ID == "" {
		t.Error("Apply() returned empty policy ID")
	}
	if p.CreatedAt.IsZero() {
		t.Error("Apply() did not set CreatedAt")
	}
	if got := s.List(); len(got) != 1 {
		t.Errorf("List() = %d policies, want 1", len(got))
	}
}

func TestApply_RejectsEnforceForNewPolicy(t *testing.T) {
	s := NewPolicyStore()
	_, err := s.Apply("block-mount", map[string]any{}, dockerApp(), ModeEnforce)
	if err == nil {
		t.Fatal("Apply(mode=enforce) on a new policy should be rejected (audit-first)")
	}
}

func TestApply_RejectsInvalidParams(t *testing.T) {
	s := NewPolicyStore()
	_, err := s.Apply("block-egress", map[string]any{}, dockerApp(), ModeAudit)
	if err == nil {
		t.Fatal("Apply() with missing required param should be rejected")
	}
}

func TestApply_RejectsUnknownPrimitive(t *testing.T) {
	s := NewPolicyStore()
	_, err := s.Apply("block-everything", map[string]any{}, dockerApp(), ModeAudit)
	if err == nil {
		t.Fatal("Apply() with unknown primitive should be rejected")
	}
}

func TestApply_GuardList(t *testing.T) {
	tests := []struct {
		name string
		app  AppRef
	}{
		{"daemon", AppRef{Name: "veronicad", CgroupPath: "/sys/fs/cgroup/veronicad", PIDs: []int{99}}},
		{"init", AppRef{Name: "init", CgroupPath: "/sys/fs/cgroup/init", PIDs: []int{1}}},
		{"pid1", AppRef{Name: "systemd", CgroupPath: "/sys/fs/cgroup", PIDs: []int{1}}},
		{"sshd", AppRef{Name: "sshd", CgroupPath: "/sys/fs/cgroup/ssh", PIDs: []int{777}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewPolicyStore()
			_, err := s.Apply("block-mount", map[string]any{}, tt.app, ModeAudit)
			if err == nil {
				t.Fatalf("Apply() on guarded app %q should be rejected", tt.name)
			}
		})
	}
}

func TestSetMode_AuditToEnforce(t *testing.T) {
	s := NewPolicyStore()
	p, err := s.Apply("block-mount", map[string]any{}, dockerApp(), ModeAudit)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	got, err := s.SetMode(p.ID, ModeEnforce)
	if err != nil {
		t.Fatalf("SetMode(enforce) error = %v", err)
	}
	if got.Mode != ModeEnforce {
		t.Errorf("Mode after SetMode = %q, want enforce", got.Mode)
	}
	// Confirm it stuck in the store.
	if s.List()[0].Mode != ModeEnforce {
		t.Error("stored policy mode not updated to enforce")
	}
}

func TestSetMode_EnforceToAudit(t *testing.T) {
	s := NewPolicyStore()
	p, _ := s.Apply("block-mount", map[string]any{}, dockerApp(), ModeAudit)
	if _, err := s.SetMode(p.ID, ModeEnforce); err != nil {
		t.Fatalf("SetMode(enforce) error = %v", err)
	}
	got, err := s.SetMode(p.ID, ModeAudit)
	if err != nil {
		t.Fatalf("SetMode(audit) error = %v", err)
	}
	if got.Mode != ModeAudit {
		t.Errorf("Mode = %q, want audit", got.Mode)
	}
}

func TestSetMode_UnknownPolicy(t *testing.T) {
	s := NewPolicyStore()
	if _, err := s.SetMode("nope", ModeEnforce); err == nil {
		t.Fatal("SetMode() on unknown id should error")
	}
}

func TestSetMode_InvalidMode(t *testing.T) {
	s := NewPolicyStore()
	p, _ := s.Apply("block-mount", map[string]any{}, dockerApp(), ModeAudit)
	if _, err := s.SetMode(p.ID, Mode("destroy")); err == nil {
		t.Fatal("SetMode() with invalid mode should error")
	}
}

func TestRevert(t *testing.T) {
	s := NewPolicyStore()
	p, _ := s.Apply("block-mount", map[string]any{}, dockerApp(), ModeAudit)
	if err := s.Revert(p.ID); err != nil {
		t.Fatalf("Revert() error = %v", err)
	}
	if len(s.List()) != 0 {
		t.Error("policy not removed after Revert")
	}
}

func TestRevert_UnknownPolicy(t *testing.T) {
	s := NewPolicyStore()
	if err := s.Revert("nope"); err == nil {
		t.Fatal("Revert() on unknown id should error")
	}
}

func TestKillSwitch(t *testing.T) {
	s := NewPolicyStore()
	s.Apply("block-mount", map[string]any{}, dockerApp(), ModeAudit)
	s.Apply("block-exec", map[string]any{"binaries": []any{"/bin/sh"}}, dockerApp(), ModeAudit)
	s.Apply("block-egress", map[string]any{"allow_cidrs": []any{"10.0.0.0/8"}}, dockerApp(), ModeAudit)

	n := s.KillSwitch()
	if n != 3 {
		t.Errorf("KillSwitch() = %d, want 3", n)
	}
	if len(s.List()) != 0 {
		t.Error("KillSwitch did not clear all policies")
	}
}

func TestKillSwitch_Empty(t *testing.T) {
	s := NewPolicyStore()
	if n := s.KillSwitch(); n != 0 {
		t.Errorf("KillSwitch() on empty store = %d, want 0", n)
	}
}
