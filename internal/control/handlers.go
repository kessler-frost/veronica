package control

import (
	"context"
	"fmt"
	"sync"
	"time"

	json "github.com/goccy/go-json"
)

// ProcSource supplies the live process list the resolver matches against. The
// host-testable handler injects a fake; the VM-gated linux build (Task 10)
// reads /proc + cgroup. Keeping it an interface is what makes resolve_app
// testable on darwin without /proc.
type ProcSource interface {
	Procs() ([]ProcInfo, error)
}

// OK is the result of revert_policy / kill_switch. Reverted carries the count
// removed by the kill switch.
type OK struct {
	Ok       bool `json:"ok"`
	Reverted int  `json:"reverted,omitempty"`
}

// Handlers binds the Phase-1 core (PolicyStore, Aggregator, resolver) to the
// eight daemon↔warden contract functions. It owns one Aggregator per observed
// app (the event source — eBPF in the VM, fakes in tests — feeds these via
// Aggregator(app).Add). Handlers is safe for concurrent use.
type Handlers struct {
	store *PolicyStore
	procs ProcSource

	mu   sync.Mutex
	aggs map[string]*Aggregator
}

// NewHandlers returns Handlers wired to a fresh PolicyStore and the given
// proc-source.
func NewHandlers(procs ProcSource) *Handlers {
	return &Handlers{
		store: NewPolicyStore(),
		procs: procs,
		aggs:  make(map[string]*Aggregator),
	}
}

// Aggregator returns the per-app event aggregator, creating it on first use, so
// the daemon's event source can route eBPF events into the right app's buffer.
func (h *Handlers) Aggregator(app string) *Aggregator { return h.aggregatorFor(app) }

func (h *Handlers) aggregatorFor(app string) *Aggregator {
	h.mu.Lock()
	defer h.mu.Unlock()
	agg, ok := h.aggs[app]
	if !ok {
		agg = NewAggregator(app)
		h.aggs[app] = agg
	}
	return agg
}

// ResolveApp implements resolve_app(name) -> AppRef. It reads the live process
// list from the proc-source and matches by name via the pure resolver.
func (h *Handlers) ResolveApp(_ context.Context, input map[string]any) (any, error) {
	req, err := decode[struct {
		Name string `json:"name"`
	}](input)
	if err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	procs, err := h.procs.Procs()
	if err != nil {
		return nil, fmt.Errorf("read processes: %w", err)
	}
	return MatchApp(req.Name, procs)
}

// Observe implements observe(app, window_secs) -> Activity by snapshotting the
// app's aggregator over the requested window.
func (h *Handlers) Observe(_ context.Context, input map[string]any) (any, error) {
	req, err := decode[struct {
		App        string `json:"app"`
		WindowSecs int    `json:"window_secs"`
	}](input)
	if err != nil {
		return nil, err
	}
	if req.App == "" {
		return nil, fmt.Errorf("app is required")
	}
	window := time.Duration(req.WindowSecs) * time.Second
	return h.aggregatorFor(req.App).Snapshot(window), nil
}

// ListPrimitives implements list_primitives() -> []Primitive over the vetted
// catalog.
func (h *Handlers) ListPrimitives(_ context.Context, _ map[string]any) (any, error) {
	cat := Catalog()
	out := make([]Primitive, 0, len(cat))
	for _, p := range cat {
		out = append(out, p)
	}
	return out, nil
}

// ApplyPolicy implements apply_policy(primitive_id, params, mode) -> Policy. The
// PolicyStore enforces audit-first (new policies must be ModeAudit) and the
// self-protection guard list.
func (h *Handlers) ApplyPolicy(_ context.Context, input map[string]any) (any, error) {
	req, err := decode[struct {
		PrimitiveID string         `json:"primitive_id"`
		Params      map[string]any `json:"params"`
		Mode        Mode           `json:"mode"`
		App         AppRef         `json:"app"`
	}](input)
	if err != nil {
		return nil, err
	}
	return h.store.Apply(req.PrimitiveID, req.Params, req.App, req.Mode)
}

// SetPolicyMode implements set_policy_mode(policy_id, mode) -> Policy, the only
// path from audit to enforce.
func (h *Handlers) SetPolicyMode(_ context.Context, input map[string]any) (any, error) {
	req, err := decode[struct {
		PolicyID string `json:"policy_id"`
		Mode     Mode   `json:"mode"`
	}](input)
	if err != nil {
		return nil, err
	}
	return h.store.SetMode(req.PolicyID, req.Mode)
}

// ListPolicies implements list_policies() -> []Policy.
func (h *Handlers) ListPolicies(_ context.Context, _ map[string]any) (any, error) {
	return h.store.List(), nil
}

// RevertPolicy implements revert_policy(policy_id) -> {ok}.
func (h *Handlers) RevertPolicy(_ context.Context, input map[string]any) (any, error) {
	req, err := decode[struct {
		PolicyID string `json:"policy_id"`
	}](input)
	if err != nil {
		return nil, err
	}
	if err := h.store.Revert(req.PolicyID); err != nil {
		return nil, err
	}
	return OK{Ok: true}, nil
}

// KillSwitch implements kill_switch() -> {ok} by reverting every policy.
func (h *Handlers) KillSwitch(_ context.Context, _ map[string]any) (any, error) {
	return OK{Ok: true, Reverted: h.store.KillSwitch()}, nil
}

// decode round-trips the Agentfield JSON input map into a typed request,
// matching the af package's parseInput idiom (so JSON number/array shapes are
// handled identically across the daemon).
func decode[T any](input map[string]any) (T, error) {
	var req T
	data, err := json.Marshal(input)
	if err != nil {
		return req, fmt.Errorf("bad request: %w", err)
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, fmt.Errorf("bad request: %w", err)
	}
	return req, nil
}
