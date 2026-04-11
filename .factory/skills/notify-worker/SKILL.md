---
name: notify-worker
description: Implements the notify skill for veronicad — Go daemon handlers, event enrichment, and Python integration
---

# Notify Worker

NOTE: Startup and cleanup are handled by `worker-base`. This skill defines the WORK PROCEDURE.

## When to Use This Skill

Features that add or modify:
- Go daemon skill handlers in `internal/af/skills.go`
- Event parsing/enrichment in `internal/ebpf/manager.go`
- Python agent integration in `src/veronica/agent.py`
- Associated unit tests

## Required Skills

None.

## Work Procedure

### 1. Read the feature description and identify affected files

Read the feature's `description`, `expectedBehavior`, and `verificationSteps`. Identify which source files need changes. Always read the full current version of each file before editing.

Key source files:
- `internal/af/skills.go` — skill handlers, request types, registration
- `internal/ebpf/manager.go` — event parsing, /proc helpers
- `src/veronica/agent.py` — DAEMON_SKILLS, agent creation

### 2. Write tests FIRST (TDD red phase)

Before any implementation:
- For Go: create test files (`internal/af/skills_test.go` or `internal/af/notify_test.go`). Follow the pattern in `internal/classifier/classifier_test.go` for test structure.
- For Python: create test files in `tests/` (e.g., `tests/test_agent.py`).
- Tests must cover: happy path, error cases (invalid PID, empty message), and edge cases from the feature's `expectedBehavior`.
- Run tests to confirm they FAIL: `go test ./internal/af/ -v -run TestNotify` or `uv run pytest tests/ -v -k notify`.

### 3. Implement the feature (TDD green phase)

Write the minimum code to make tests pass. Follow existing patterns exactly:
- Go handlers: use `parseInput[T]`, `okResult`/`errResult`, `log.Printf("SKILL <name>: ...")`
- Request structs: add `json` tags
- Registration: add to `RegisterSkills()` with `ag.RegisterReasoner()`
- Python: add to `DAEMON_SKILLS` list in logical position (with action skills, not at the end)

**CRITICAL for /proc operations:** macOS has no `/proc` filesystem. In Go tests, you must either:
- Use an interface/function variable for file I/O that can be swapped in tests (e.g., `var openFile = os.OpenFile` then override in tests)
- Use temp files/pipes as stand-ins for `/proc/<pid>/fd/1`
- Do NOT skip tests because macOS lacks /proc — mock it

### 4. Run tests (TDD verify)

**CRITICAL: Always set Go env vars before any Go command:**
```bash
export GONOSUMCHECK='github.com/Agent-Field/*'
export GONOSUMDB='github.com/Agent-Field/*'
export GOPRIVATE='github.com/Agent-Field/*'
```

```bash
# Go tests
go test ./internal/af/ -v -count=1
go test ./internal/classifier/ -v -count=1

# Python tests
uv run pytest -v

# Go vet
go vet ./internal/...
```

All tests must pass. Fix any failures before proceeding.

### 5. Verify manually

For Go features:
- Inspect the generated JSON output format in test logs
- Verify that the handler follows the exact same pattern as other handlers (compare with `handleExec`, `handleSchedule`)
- Check that `RegisterSkills` has the new registration

For Python features:
- Run: `uv run python -c "from veronica.agent import DAEMON_SKILLS; print(DAEMON_SKILLS)"`
- Verify "notify" appears in the output

### 6. Run full test suite

```bash
go test ./internal/af/ ./internal/classifier/ -v -count=1
uv run pytest -v
go vet ./internal/...
```

All must pass.

## Example Handoff

```json
{
  "salientSummary": "Added notify skill handler to skills.go: NotifyRequest struct, handleNotify that opens /proc/<pid>/fd/1 and writes '[veronica] <message>\\n', registered with Agentfield. Tests cover happy path, invalid PID, empty message, and concurrent writes using pipes. All 8 tests pass.",
  "whatWasImplemented": "NotifyRequest struct with pid/message fields, handleNotify closure that validates inputs, opens /proc/<pid>/fd/1, writes formatted message, closes fd. Registered in RegisterSkills() with description. Added 8 test cases in notify_test.go.",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {"command": "go test ./internal/af/ -v -count=1", "exitCode": 0, "observation": "8 tests passed including TestNotifyHappyPath, TestNotifyInvalidPID, TestNotifyEmptyMessage, TestNotifyConcurrent"},
      {"command": "go vet ./internal/...", "exitCode": 0, "observation": "no issues"},
      {"command": "uv run pytest -v", "exitCode": 0, "observation": "all existing tests pass"}
    ],
    "interactiveChecks": [
      {"action": "Compared handleNotify with handleExec pattern", "observed": "Same structure: parseInput, validate, log, execute, return result"}
    ]
  },
  "tests": {
    "added": [
      {
        "file": "internal/af/notify_test.go",
        "cases": [
          {"name": "TestNotifyHappyPath", "verifies": "writes [veronica] message\\n to pipe"},
          {"name": "TestNotifyInvalidPID", "verifies": "returns error for PID 99999999"},
          {"name": "TestNotifyEmptyMessage", "verifies": "returns error for empty string"},
          {"name": "TestNotifyConcurrent", "verifies": "two concurrent writes produce clean lines"}
        ]
      }
    ]
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- `go mod tidy` fails to resolve Agentfield SDK dependency
- Cannot find a way to mock /proc operations for macOS testing
- The existing `parseInput` generic function doesn't work with the new request struct
- Test infrastructure (pytest, go test) is broken
- Feature depends on changes from another feature that hasn't been implemented yet
