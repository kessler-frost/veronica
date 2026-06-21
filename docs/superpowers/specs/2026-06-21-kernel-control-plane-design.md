# Veronica — App-Aware Kernel Control Plane (v1 design)

**Date:** 2026-06-21
**Status:** Approved design, pending implementation plan
**Supersedes the README's "reactive behaviors" framing** for veronica's primary direction.

## 1. Goal

Point veronica at an application running inside its Lima VM and:
1. **Observe** — answer *"what is `<app>` doing?"* from real kernel-sourced activity.
2. **Control** — enforce natural-language policies on that app via a *vetted catalog* of eBPF-LSM primitives, **audit-first**.

Everything is scoped to apps running inside veronica's managed Lima Ubuntu VM (eBPF shares that kernel). Targeting a remote Linux host or native macOS apps is explicitly out of scope.

### Acceptance demo (runs in the VM)
- `veronica watch docker` → *"what's docker doing?"* returns a real summary of docker's recent file / network / exec / mount activity.
- `veronica enforce "don't let docker create volumes"` → compiles to the `block-mount` primitive scoped to docker's cgroup → loads in **audit** mode (logs the would-block) → user confirms → flips to **enforce** → `docker volume create x` fails with `EPERM`; docker's other operations are unaffected. `veronica panic` removes all enforcement instantly.

## 2. Architecture (Approach A: daemon catalog + warden agent)

Reuses the existing split — **Go daemon = eBPF runtime in the VM; Python = reasoning; Agentfield = control plane.**

```
 User ── CLI ──► Warden agent (Python, host) ──Agentfield──► Daemon (Go, VM root)
                   - NL → {primitive, params}                  - App resolver
                     (LLM structured output,                   - Observation aggregators (eBPF)
                      schema-validated)                        - Enforcement primitive catalog (eBPF-LSM)
                   - audit→confirm→enforce lifecycle           - Policy lifecycle manager
                   - observation → NL summary                  - kill-switch
                                                                       │
                                                              eBPF programs (kernel, VM)
```

### Components (each an independently testable unit)

1. **App resolver** (daemon/Go) — `resolve_app(name) → {cgroup_v2_path, live_pids}`. Tracks the app's process tree as it changes. The shared targeting primitive for both observation and enforcement.

2. **Observation aggregators** (daemon/Go + eBPF) — the existing `process_exec` / `file_open` / `net_connect` programs, now **cgroup-filtered in-kernel**, plus mount coverage. Events land in a rolling per-app activity buffer queryable by time window.

3. **Enforcement primitive catalog** (daemon/Go + eBPF-LSM) — a **fixed, vetted** set of parameterized LSM programs. Each entry declares: `id`, a JSON params schema, the LSM hook(s) it attaches, and supports `audit` (log-only) and `enforce` (`-EPERM`) modes. Always cgroup-scoped. **v1 set:**

   | id | params | LSM hook(s) | covers |
   |---|---|---|---|
   | `block-path-write` | `path_prefix` | `path_mkdir`, `inode_create`, `file_open`(write) | writes under a path |
   | `block-mount` | `path_prefix?` | `sb_mount` / `move_mount` | **"docker volume create"** |
   | `block-egress` | `allow_cidrs[]` | `socket_connect` | outbound to non-allowed addrs |
   | `block-exec` | `binaries[]` | `bprm_check_security` | exec of named binaries |
   | `drop-capability` | `caps[]` | `capable` / `security_capable` | dropping capabilities |

4. **Policy lifecycle manager** (daemon/Go) — `apply_policy` / `set_policy_mode` / `list_policies` / `revert_policy`, per-policy `audit|enforce` mode, and a global **kill-switch** that detaches all enforcement.

5. **Warden control agent** (Python/host) — the only reasoning component:
   - NL intent → `{primitive_id, params}` via **LLM structured output validated against the catalog JSON schema**. Anything that fails validation is rejected and never loaded — no free-form kernel code path exists.
   - Owns the **audit → confirm → enforce** lifecycle.
   - Summarizes observation buffers into natural-language answers.

6. **CLI** (`uv run veronica`) — new verbs: `watch <app>`, `ask "…"`, `enforce "…"`, `policies`, `audit <policy>`, `revert <policy>`, `panic`.

### Agentfield functions exposed by the daemon
`resolve_app(name)`, `observe(app, window_secs)`, `list_primitives()`, `apply_policy(primitive_id, params, mode)`, `set_policy_mode(policy_id, mode)`, `list_policies()`, `revert_policy(policy_id)`, `kill_switch()`.

## 3. Data flow

- **Observe:** kernel event → in-eBPF cgroup filter → ring buffer → per-app aggregator → `observe(app,window)` → warden → LLM summary → user.
- **Enforce:** NL → warden → LLM picks primitive+params (schema-validated) → `apply_policy(…, audit)` → daemon loads cgroup-scoped LSM program in audit → reports would-block events → warden: *"would have blocked N ops, e.g. …; confirm to enforce?"* → user confirms → `apply_policy(…, enforce)` → kernel denies. `panic`/`revert` detaches.

## 4. Safety & error handling (critical)

- **Audit-first is structural** — a policy cannot transition to `enforce` without passing through `audit` + an explicit user confirm. Enforced in the lifecycle state machine, not by convention.
- **Catalog-bounded** — the LLM can only emit a validated `{primitive_id, params}`. No mechanism exists to load arbitrary eBPF from NL.
- **Cgroup-scoped** — every LSM denial is predicated on the resolved target cgroup (`bpf_current_task_under_cgroup` / cgroup-id match). It cannot deny system-wide.
- **Fail-open** — `veronica panic` detaches everything; and if the daemon process dies, the kernel closes the BPF links, so all denials vanish. A crash can never wedge the VM into a locked-down state.
- **Self-protection guard list** — refuse any policy that resolves to denying the veronica daemon, `init`/PID 1, or `sshd`.
- **Kernel precondition check** — the daemon verifies `CONFIG_BPF_LSM=y` and `bpf` in the active LSM list at startup; if absent, enforcement is disabled with a clear message. `veronica setup` configures the Lima image's `lsm=` boot parameter so enforcement is available.

## 5. Testing strategy

- **Host-testable (Go unit, on macOS — extends the Wave-1 host suite):** app-resolver logic, catalog schema validation, the policy lifecycle state machine (audit→enforce transitions, kill-switch, guard list), warden NL→primitive translation against a **mock LLM** (assert schema-valid output and that invalid LLM output is rejected), and the CLI.
- **VM integration (gated, scripted in Lima):** real eBPF load/attach, cgroup-filtered observation correctness, and the enforce demo — `docker volume create` → `EPERM`, audit-mode logs-but-does-not-block, `panic` detaches. Documented as kernel-gated; run in the VM.
- **Acceptance:** the docker observe + block-volume demo, scripted and reproducible in the VM.

## 6. Out of scope for v1 (YAGNI)

Ephemeral per-app observation subscriptions (Approach C — a later scaling optimization), loading `sched_enforce` / `xdp_filter`, cross-policy conflict resolution beyond last-writer-wins + `revert`, and remote-host or macOS-native targeting.
