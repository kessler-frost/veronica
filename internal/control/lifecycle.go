package control

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// guardedComms are process names that no policy may ever target. Denying these
// could wedge the VM (self-protection guard list from the design's §4 safety).
var guardedComms = map[string]bool{
	"veronicad": true,
	"veronica":  true,
	"init":      true,
	"systemd":   true,
	"sshd":      true,
}

// PolicyStore is the in-memory policy lifecycle manager. The audit-first
// invariant is structural: Apply only ever creates ModeAudit policies, and
// SetMode is the single path to ModeEnforce.
type PolicyStore struct {
	mu     sync.Mutex
	seq    atomic.Uint64
	policy map[string]Policy

	// now is overridable in tests; defaults to time.Now.
	now func() time.Time
}

// NewPolicyStore returns an empty PolicyStore.
func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		policy: make(map[string]Policy),
		now:    time.Now,
	}
}

// Apply validates the params, runs the guard-list check, and stores a new
// audit-mode policy. It rejects any mode other than ModeAudit: a fresh policy
// cannot start enforcing; that requires a later SetMode.
func (s *PolicyStore) Apply(primitiveID string, params map[string]any, app AppRef, mode Mode) (Policy, error) {
	if mode != ModeAudit {
		return Policy{}, fmt.Errorf("new policies must start in audit mode, got %q", mode)
	}
	if err := ValidateParams(primitiveID, params); err != nil {
		return Policy{}, err
	}
	if name := guardedTarget(app); name != "" {
		return Policy{}, fmt.Errorf("refusing to target protected app %q (self-protection guard list)", name)
	}

	p := Policy{
		ID:          "pol-" + strconv.FormatUint(s.seq.Add(1), 10),
		PrimitiveID: primitiveID,
		Params:      params,
		Mode:        ModeAudit,
		App:         app,
		CreatedAt:   s.now(),
	}

	s.mu.Lock()
	s.policy[p.ID] = p
	s.mu.Unlock()
	return p, nil
}

// SetMode transitions an existing policy between audit and enforce. It is the
// only path to ModeEnforce.
func (s *PolicyStore) SetMode(id string, mode Mode) (Policy, error) {
	if mode != ModeAudit && mode != ModeEnforce {
		return Policy{}, fmt.Errorf("invalid mode %q", mode)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.policy[id]
	if !ok {
		return Policy{}, fmt.Errorf("unknown policy %q", id)
	}
	p.Mode = mode
	s.policy[id] = p
	return p, nil
}

// List returns all current policies.
func (s *PolicyStore) List() []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Policy, 0, len(s.policy))
	for _, p := range s.policy {
		out = append(out, p)
	}
	return out
}

// Revert removes a policy, detaching its enforcement.
func (s *PolicyStore) Revert(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policy[id]; !ok {
		return fmt.Errorf("unknown policy %q", id)
	}
	delete(s.policy, id)
	return nil
}

// KillSwitch reverts every policy and returns the number removed. Fail-open:
// after this, nothing is enforced.
func (s *PolicyStore) KillSwitch() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.policy)
	s.policy = make(map[string]Policy)
	return n
}

// guardedTarget returns the guarded name an app resolves to, or "" if the app
// is safe to target. PID 1 is guarded regardless of name.
func guardedTarget(app AppRef) string {
	if guardedComms[app.Name] {
		return app.Name
	}
	for _, pid := range app.PIDs {
		if pid == 1 {
			return "pid 1"
		}
	}
	return ""
}
