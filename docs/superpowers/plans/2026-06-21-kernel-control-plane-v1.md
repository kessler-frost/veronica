# Kernel Control Plane v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build veronica's app-aware kernel control plane v1 — point it at an app in its Lima VM to observe what it's doing and enforce natural-language policies via a vetted catalog of eBPF-LSM primitives, audit-first.

**Architecture:** Go daemon (in the VM) owns the primitive catalog, observation aggregators, policy lifecycle, and Agentfield function registration. A Python "warden" agent (host) translates NL → a schema-validated `{primitive_id, params}`, owns the audit→confirm→enforce lifecycle, and summarizes observation. CLI fronts the warden.

**Tech Stack:** Go 1.26 (cilium/ebpf, Agentfield Go SDK), Python 3.12 (typer, msgspec/pydantic, jsonschema), eBPF C (CO-RE/LSM). uv for Python, never pip.

## Global Constraints

- **Branch:** all work on `develop`, push to `origin/develop`, never `main`.
- **Permissive licenses only** (Apache/MIT/BSD/MPL); no new BUSL/copyleft deps.
- **Host vs VM split:** the daemon `go build ./...` + all pure-Go logic and all Python is host-testable on darwin/arm64. eBPF *program loading*, `/proc`+cgroup reads, and the enforce demo are **VM-gated** — write them, test via scripts run inside Lima, never fake a host pass.
- **Code style:** Python uses `pathlib.Path`, minimal if/else and try/except, flat flow; Go uses table-driven tests, match surrounding idioms.
- **TDD:** failing test → run-fail → implement → run-pass → commit. Commit trailers on every commit:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_012mXAz8yRQAznJqUYkCGgE8`.
- **Disk:** clean `.venv`/caches/`go clean -testcache` after each phase; report `du -sh`.

---

## The daemon↔warden contract (shared, defined once)

All tasks depend on these. The daemon registers these Agentfield functions; the warden calls them through a `DaemonClient` interface it can mock.

**Go types** (`internal/control/types.go`):
```go
type Mode string // "audit" | "enforce"
const (ModeAudit Mode = "audit"; ModeEnforce Mode = "enforce")

type AppRef struct { Name string; CgroupPath string; PIDs []int }

type Primitive struct {
    ID     string          // e.g. "block-mount"
    Desc   string
    Params map[string]any  // JSON Schema for params
    Hooks  []string        // LSM hook names
}

type Policy struct {
    ID, PrimitiveID string
    Params          map[string]any
    Mode            Mode
    App             AppRef
    AuditCount      int       // would-block events seen in audit
    CreatedAt       time.Time
}

type Activity struct {
    App    string
    Window int                 // seconds
    Files  []FileEvent
    Net    []NetEvent
    Execs  []ExecEvent
    Mounts []MountEvent
}
```

**Agentfield functions** (daemon registers; warden calls):
`resolve_app(name) -> AppRef` · `observe(app, window_secs) -> Activity` · `list_primitives() -> []Primitive` · `apply_policy(primitive_id, params, mode) -> Policy` · `set_policy_mode(policy_id, mode) -> Policy` · `list_policies() -> []Policy` · `revert_policy(policy_id) -> {ok}` · `kill_switch() -> {ok}`

---

## Phase 1 — Go daemon host-testable core (no kernel needed)

### Task 1: Primitive catalog + schema validation
**Files:** Create `internal/control/catalog.go`, `internal/control/types.go`; Test `internal/control/catalog_test.go`.
**Interfaces:** Produces `Catalog() map[string]Primitive` (the 5 v1 primitives) and `ValidateParams(primitiveID string, params map[string]any) error` (validates params against the primitive's JSON Schema; returns error for unknown id or schema-invalid params).

- [ ] **Step 1 — failing test:** table-driven `TestValidateParams`: valid `block-mount{path_prefix:"/var/lib/docker/volumes"}` → nil; unknown primitive id → error; `block-egress` missing required `allow_cidrs` → error; wrong-type param → error.
- [ ] **Step 2:** run `go test ./internal/control/ -run TestValidateParams -v` → FAIL (undefined).
- [ ] **Step 3 — implement:** define the 5 primitives (`block-path-write`, `block-mount`, `block-egress`, `block-exec`, `drop-capability`) with JSON Schemas per the spec table; implement `ValidateParams` using a permissive JSON-schema lib (e.g. `github.com/santhosh-tekuri/jsonschema` — Apache/BSD; confirm license) or a hand-rolled validator if simpler.
- [ ] **Step 4:** run tests → PASS.
- [ ] **Step 5 — also test `Catalog()`** returns exactly 5 primitives each with non-empty Hooks; commit.

### Task 2: Policy lifecycle state machine
**Files:** Create `internal/control/lifecycle.go`; Test `internal/control/lifecycle_test.go`.
**Interfaces:** Produces `type PolicyStore` with `Apply(primitiveID string, params map[string]any, app AppRef, mode Mode) (Policy, error)`, `SetMode(id string, mode Mode) (Policy, error)`, `List() []Policy`, `Revert(id string) error`, `KillSwitch() int` (reverts all, returns count). Consumes Task 1's `ValidateParams`.

- [ ] **Step 1 — failing tests:** `Apply` rejects invalid params (via ValidateParams) and the **guard list** (refuse any policy whose `app` resolves to the daemon, PID 1/`init`, or `sshd`); a fresh policy created with `mode=enforce` is rejected unless it has passed audit (enforce requires a prior audit policy + explicit `SetMode`); `KillSwitch` reverts all and returns the count; `Revert` on unknown id errors.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3 — implement** the store (in-memory map + mutex), the audit-first invariant (`Apply` only accepts `ModeAudit` for new policies; `SetMode(id, ModeEnforce)` is the only path to enforce), the guard-list check, kill-switch.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit.

### Task 3: App-resolver pure core (host-testable parsing)
**Files:** Create `internal/control/resolve.go` (pure: cgroup-path + pid matching from provided data); the Linux `/proc`+cgroup reading shell goes in Task 8 (VM-gated). Test `internal/control/resolve_test.go`.
**Interfaces:** Produces `MatchApp(name string, procs []ProcInfo) (AppRef, error)` where `ProcInfo{PID int, Comm string, CgroupPath string}` is supplied by the caller (real data comes from `/proc` in the VM). Returns the cgroup + all matching PIDs, error if none.

- [ ] **Step 1 — failing tests:** fixture `[]ProcInfo` for "docker" (daemon + child procs sharing a cgroup prefix) → `MatchApp("docker", …)` returns the common cgroup path + all docker PIDs; name with no match → error; partial/substring name matching rules (start-anchored, per project classifier convention).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement matching. **Step 4:** PASS. **Step 5:** commit.

### Task 4: Observation aggregation core (host-testable)
**Files:** Create `internal/control/aggregate.go`; Test `internal/control/aggregate_test.go`. (Event structs live in `types.go`.)
**Interfaces:** Produces `type Aggregator` with `Add(ev Event)` and `Snapshot(window time.Duration) Activity` (groups events in the window by kind into the `Activity` struct, dedups/counts repeats). The eBPF event *source* is VM-gated (Task 9); this is the pure rolling-buffer + grouping logic.

- [ ] **Step 1 — failing tests:** add a mix of file/net/exec/mount events across timestamps → `Snapshot(30s)` includes only in-window events, grouped by kind, with repeat-counts; events older than the window are dropped.
- [ ] **Step 2:** FAIL. **Step 3:** implement ring buffer + windowed grouping. **Step 4:** PASS. **Step 5:** commit.

### Phase 1 gate
`go build ./... && go vet ./... && go test ./internal/control/ -race -v` all green. Commit + push develop. `go clean -testcache`.

---

## Phase 2 — Python warden + CLI (host-testable against the contract)

### Task 5: DaemonClient interface + fake
**Files:** Create `src/veronica/control/client.py` (Protocol/ABC), `src/veronica/control/fake_client.py` (in-memory fake implementing the contract for tests). Test `tests/control/test_fake_client.py`.
**Interfaces:** Produces `DaemonClient` with methods mirroring the Agentfield functions (`resolve_app`, `observe`, `list_primitives`, `apply_policy`, `set_policy_mode`, `list_policies`, `revert_policy`, `kill_switch`) and a `FakeDaemonClient` honoring the same audit-first + guard-list invariants as Task 2 (so warden tests are realistic).

- [ ] Steps: failing test that the fake enforces audit-first + guard list and round-trips policies → FAIL → implement → PASS → commit.

### Task 6: NL → primitive translation (schema-validated)
**Files:** Create `src/veronica/control/translate.py`; Test `tests/control/test_translate.py`.
**Interfaces:** Produces `translate(nl: str, primitives: list[dict], llm: LLM) -> tuple[str, dict]` returning `(primitive_id, params)`; validates against the primitive's JSON Schema (`jsonschema`, MIT); raises `TranslationError` if the LLM picks an unknown id or params fail validation. `LLM` is a small Protocol (mockable).
**Consumes:** catalog shape from `list_primitives()`.

- [ ] **Step 1 — failing tests** with a **mock LLM**: "don't let docker create volumes" → mock returns `{"primitive_id":"block-mount","params":{"path_prefix":"/var/lib/docker/volumes"}}` → translate returns that tuple; mock returning an unknown id → `TranslationError`; mock returning schema-invalid params → `TranslationError`.
- [ ] Steps 2-5: FAIL → implement (LLM structured output + jsonschema validation, no free-form path) → PASS → commit.

### Task 7: Audit→confirm→enforce lifecycle + summarize
**Files:** Create `src/veronica/control/warden.py`; Test `tests/control/test_warden.py`.
**Interfaces:** Produces `Warden(client: DaemonClient, llm: LLM)` with `enforce(nl) -> AuditReport` (translate → `apply_policy(mode=audit)` → returns policy id + would-block summary), `confirm(policy_id) -> Policy` (`set_policy_mode(enforce)`), `ask(app, question) -> str` (`observe` → LLM summary), `panic() -> int` (kill_switch).
**Consumes:** Tasks 5, 6.

- [ ] Failing tests (using `FakeDaemonClient` + mock LLM): `enforce` leaves the policy in `audit` and surfaces the would-block count; `confirm` flips to `enforce`; `enforce` then `panic` clears it; `ask` returns the mocked summary over the fake's activity. FAIL → implement → PASS → commit.

### Task 8: CLI verbs
**Files:** Modify `src/veronica/cli/main.py` (add `watch`, `ask`, `enforce`, `policies`, `audit`, `revert`, `panic`); Test `tests/cli/test_control_commands.py`.
**Interfaces:** Consumes `Warden`. Each verb constructs a Warden (real client in prod, injected fake in tests) and calls the matching method; `enforce` prints the audit summary and the confirm hint.

- [ ] Failing tests via typer's `CliRunner` with an injected `FakeDaemonClient`+mock LLM: `enforce "…"` exits 0 and prints the would-block summary; `policies` lists; `panic` clears. FAIL → implement → PASS → commit.

### Phase 2 gate
`uv run pytest tests/control tests/cli -v` green; `uv run ruff check` clean. Commit + push develop. Remove `.venv` + caches.

---

## Phase 3 — Daemon integration wiring (Go; mix of host-testable + VM-gated)

### Task 9: Agentfield function registration
**Files:** Create `internal/control/handlers.go` (handlers calling Tasks 1-4 + the resolver/aggregator); Modify `cmd/veronicad/main.go` to register the 8 functions. Test `internal/control/handlers_test.go` (handlers driven with fake resolver/aggregator — host-testable; the Agentfield transport is exercised in the VM).
**Interfaces:** Consumes Tasks 1-4; wires `PolicyStore`, `Aggregator`, resolver behind the 8 Agentfield function names from the contract.

- [ ] Failing handler tests (inject fakes for proc-source + event-source): `apply_policy` handler enforces audit-first + guard list; `kill_switch` handler reverts all; `observe` handler returns a Snapshot. FAIL → implement → PASS → commit.

### Task 10 (VM-gated): Linux proc/cgroup reader for the resolver
**Files:** Create `internal/control/resolve_linux.go` (build-tag `linux`): read `/proc/*/comm` + `/proc/*/cgroup`, feed `MatchApp`. Test: `scripts/vm/test_resolve.sh` (run in Lima).
- [ ] Implement behind `//go:build linux`; provide a VM script that starts a known process and asserts `resolve_app` finds its cgroup+pids. **Documented VM-gated** — do not run on host. Commit.

### Phase 3 gate
`go build ./... && go vet ./... && go test ./internal/control/ -race` green on host (linux-tagged file compiles via cross or is excluded on darwin — verify `GOOS=linux go build ./...` compiles). Commit + push.

---

## Phase 4 — eBPF/LSM programs + VM enforce demo (VM-gated; written, verified in Lima)

### Task 11: cgroup-filtered observation programs
**Files:** Modify `internal/ebpf/programs/{process_exec,file_open,net_connect}.c` to filter by target cgroup id; add `mount.c`. Regenerate Go bindings. Test: `scripts/vm/test_observe.sh`.
- [ ] Add cgroup-id filter param; emit events only for the target cgroup; VM script asserts `observe docker` returns docker's events and not others. VM-gated. Commit.

### Task 12: Enforcement LSM primitives (the catalog's kernel side)
**Files:** Create `internal/ebpf/programs/lsm/{block_path_write,block_mount,block_egress,block_exec,drop_capability}.c`; loader in `internal/ebpf/lsm_loader.go`. Test: `scripts/vm/test_enforce.sh`.
**Interfaces:** Each program: cgroup-scoped, audit mode (log-only via a map flag) vs enforce mode (return `-EPERM`); parameterized by the primitive's params via BPF maps.
- [ ] Implement the 5 LSM programs + loader honoring audit/enforce + cgroup scope + self-protection. VM script = the **acceptance demo**: `veronica watch docker`; `veronica enforce "don't let docker create volumes"` (audit → confirm → enforce); `docker volume create x` fails with EPERM; other docker ops work; `veronica panic` removes it. VM-gated. Commit.

### Task 13: `veronica setup` kernel preconditions
**Files:** Modify the setup flow + `lima/veronica.yaml`: ensure `CONFIG_BPF_LSM` + `lsm=…,bpf` boot param; daemon startup check disables enforcement with a clear message if absent. Test: `scripts/vm/test_preconditions.sh`.
- [ ] Implement precondition check + Lima boot-param config. VM-gated. Commit.

### Phase 4 gate (in VM)
Run all `scripts/vm/*.sh` in Lima; the enforce demo passes end-to-end. Document results in `docs/superpowers/` as the VM-verified acceptance record.

---

## Self-review notes
- **Spec coverage:** §2 components → Tasks 1 (catalog), 2 (lifecycle), 3+10 (resolver), 4+11 (observation), 5-8 (warden+CLI), 9 (Agentfield), 12 (enforcement), 13 (preconditions). §4 safety → audit-first (T2/T5/T7), catalog-bound (T1/T6), cgroup-scope (T11/T12), kill-switch (T2/T7/T12), guard list (T2), preconditions (T13). §5 testing split honored (host vs VM gates per task).
- **Host-testable now:** Tasks 1-9 (Phases 1-3). **VM-gated:** Tasks 10-13 (Phase 4 + the linux resolver/observe).
- **Contract consistency:** the 8 function names + types are defined once above and reused verbatim in Tasks 5, 7, 9.
