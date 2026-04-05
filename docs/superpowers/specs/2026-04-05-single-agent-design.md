# Single Agent Architecture

**Date:** 2026-04-05
**Status:** Approved
**Supersedes:** Multi-agent architecture (multiple DynamicAgent instances per NATS KV entry)

## Problem

The current multi-agent architecture has two structural problems:

1. **Agent collision** — multiple agents react to the same eBPF event. A scaffolder and an SSH hardener both fire on `ssh-keygen`, competing and undoing each other's work.
2. **Filter quality** — the LLM generates agent configs with overly broad or narrow filters. Tested across 4 models (Qwen local, mercury-2, kimi-k2.5, gpt-5.4-nano) — filter generation is consistently unreliable.

## Solution

Replace N independent agents with a single agent that accumulates behaviors from `veronica add`. No per-agent filters, no creator prompt, no JSON config generation.

## CLI Changes

```
veronica add "scaffold projects based on directory creation"
veronica add "revert dangerous permission changes on sensitive files"
veronica list
veronica rm "scaffold projects"
veronica start / stop / status / logs
```

The `agent` subcommand is removed entirely. `add` appends raw text to a behaviors list. `rm` removes a behavior by text match. `list` shows all behaviors.

## NATS KV Schema

Single key `veronica` in the `agents` bucket:

```json
{
  "behaviors": [
    "scaffold projects based on directory creation",
    "revert dangerous permission changes on sensitive files",
    "validate config files in /etc/ and reload services"
  ],
  "subscriptions": ["process_exec", "file_open"]
}
```

No per-agent names, filters, status fields, or context strings.

## Event Subscription Management

When a behavior is added or removed, a one-time LLM call determines which event types the agent needs based on all current behaviors. The result is stored in `subscriptions` and the agent subscribes to exactly those NATS subjects.

The agent also has a runtime `subscribe` tool it can call to update its own subscriptions if it realizes it's missing events:

```python
async def subscribe(event_types: list[str]) -> str:
    """Set which eBPF event types you receive.
    Valid: process_exec, process_exit, file_open, net_connect.
    Replaces the current subscription list entirely."""
```

When called, `subscriptions` is updated in KV and NATS subscriptions are hot-swapped without restart.

## System Prompt Construction

Each batch, the system prompt is built from:

```
BASE_SYSTEM_PROMPT

Your behaviors:
- scaffold projects based on directory creation
- revert dangerous permission changes on sensitive files
- validate config files in /etc/ and reload services

[rules about tool use, final_answer, etc.]
```

The behaviors list is read from KV at prompt construction time. No per-agent context — one prompt covers everything.

## Event Flow

1. eBPF probes capture kernel events (unchanged)
2. Go daemon classifies and publishes to NATS (unchanged)
3. Single Python agent receives events on subscribed subjects
4. Debounce + batch (2s window, cap 20 events, 5 unique per batch — unchanged)
5. System prompt built with all behaviors
6. LLM processes batch, calls tools, calls `final_answer`
7. Tasks marked done in KV

## Tools

Same 9 tools as before, plus `subscribe`:

1. `exec_command` — run shell commands in VM
2. `enforce` — chmod/iptables enforcement
3. `transform` — iptables NAT/redirect
4. `schedule` — renice process priority
5. `measure` — perf stat, ss, /proc metrics
6. `kv_get` / `kv_put` / `kv_keys` — shared state
7. `final_answer` — signal completion
8. `subscribe` — update event subscriptions (new)

## What Gets Deleted

- `src/veronica/agents/creator.py` — no more LLM-generated agent configs
- `src/veronica/agents/runner.py` — replaced by simpler single-agent launcher
- `DynamicAgent` class — gone
- `BaseAgent._matches_filter()` — gone (classifier handles noise, no per-agent filters)
- `agent` CLI subcommand (`agent add`, `agent list`, `agent stop`, `agent rm`) — replaced by top-level `add` / `rm` / `list`
- `CREATOR_PROMPT` and all JSON config parsing logic

## What Stays

- `BaseAgent` core (debounce, batch, semantic key, tool wrappers, LLM loop)
- Go daemon, classifier, publisher, tool responders — all unchanged
- NATS infrastructure — unchanged
- `veronica start` / `stop` / `status` / `logs` / `build` / `setup` / `run` / `vm *` — unchanged

## Migration

On first `veronica add`, if old per-agent entries exist in the `agents` KV bucket, they are ignored. The new schema uses the single key `veronica`. Old entries can be cleaned up with `veronica rm` or by purging the bucket.
