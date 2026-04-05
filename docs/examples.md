# Veronica: Intelligence Scenarios

Real-world examples of how Veronica adds value to daily workflows. Each scenario shows what the user does, what eBPF observes, and what the agent autonomously decides to do.

## 1. Project Scaffolding

**Trigger:** `mkdir my-fastapi-app`
**eBPF hook:** `sched_process_exec` tracepoint catches `mkdir`
**Intelligence:** Agent infers the intended stack from the directory name — "fastapi" means Python + FastAPI. Decides to run `uv init`, install FastAPI + uvicorn, and generate a `main.py` with a hello world route. User walks into a ready-to-go project.

## 2. Git Clone → Auto-Setup

**Trigger:** `git clone https://github.com/someone/cool-project.git`
**eBPF hook:** `sched_process_exec` tracepoint catches `git`
**Intelligence:** Agent inspects the cloned repo to detect the language/framework — `pyproject.toml` means Python (run `uv sync`), `package.json` means JS (run `npm install`), `go.mod` means Go (run `go mod download`). Adapts to whatever it finds.

## 3. Crash Recovery

**Trigger:** nginx exits with code 1
**eBPF hook:** `sched_process_exit` tracepoint catches nginx exit
**Intelligence:** Agent doesn't blindly restart — it checks logs first to understand why the crash happened. Validates the config with `nginx -t` before restarting. If config is broken, it diagnoses the issue rather than restart-looping.

## 4. Dangerous Command Interception

**Trigger:** `chmod 777 /etc/shadow`
**eBPF hook:** `sched_process_exec` tracepoint catches `chmod`
**Intelligence:** Agent recognizes that `777` on a sensitive system file is dangerous. Knows the correct permissions for shadow files (`640`) and reverts immediately. Doesn't just block — it fixes.

## 5. Smart curl → Auto-Extract

**Trigger:** `curl -O https://example.com/dataset.tar.gz`
**eBPF hook:** `sched_process_exec` tracepoint catches `curl`
**Intelligence:** Agent detects the downloaded file is an archive from the filename extension. Extracts it to the same directory where the download happened, then cleans up the archive. Handles .tar.gz, .zip, .tgz.

## 6. Docker Run → Resource Guardrails

**Trigger:** `docker run -d postgres`
**eBPF hook:** `sched_process_exec` tracepoint catches `docker`
**Intelligence:** Agent detects a container started without resource limits. Applies sensible defaults (memory cap, CPU quota) and sets up a health check. Prevents runaway containers from eating the host.

## 7. SSH Key Generation → Security Hardening

**Trigger:** `ssh-keygen -t rsa`
**eBPF hook:** `sched_process_exec` tracepoint catches `ssh-keygen`
**Intelligence:** Agent recognizes RSA is outdated. Deletes the RSA key, regenerates as ed25519 (more secure, faster). Sets proper permissions — 600 on private key, 644 on public. Doesn't just warn, it fixes.

## 8. Repeated Command → Suggest Alias

**Trigger:** User runs `docker compose up -d` 12 times in one day
**eBPF hook:** `sched_process_exec` tracepoint catches repeated patterns
**Intelligence:** Agent detects temporal patterns — same command run frequently. Creates a shell alias or Makefile target and adds it to the user's config. Requires pattern memory across events.

## 9. File Editing → Auto-Validate

**Trigger:** User edits `/etc/nginx/nginx.conf`
**eBPF hook:** `kprobe/do_sys_openat2` catches write to `/etc/` path
**Intelligence:** Agent detects a config file was modified (write-only file open, not reads). Knows which service owns which config — runs `nginx -t` for nginx configs. If valid, reloads the service. If broken, logs the validation error.

## 10. Package Install → Security Scan

**Trigger:** `pip install reqeusts`
**eBPF hook:** `sched_process_exec` tracepoint catches `pip`
**Intelligence:** Agent compares the package name against known packages and detects "reqeusts" is a likely typosquat of "requests" (transposed letters). Attempts to kill the install and warns. Doesn't need a database — the LLM recognizes the pattern.

## 11. Spec File → Auto-Scaffold

**Trigger:** User writes `todo_project.md` describing a project
**eBPF hook:** `kprobe/do_sys_openat2` catches write to `*_project.md`
**Intelligence:** Agent reads the spec file, understands the described project structure, and scaffolds it in the same directory. A Python todo CLI spec produces `main.py` with add/list/done commands, `pyproject.toml`, and a JSON data file. A Go API spec produces `main.go` with HTTP handlers and `go.mod`. Adapts to whatever the spec describes.

---

## Implementation Status

| # | Scenario | Status |
|---|---|---|
| 1 | Project scaffolding | Tested — FastAPI, Go scaffold correctly |
| 2 | Git clone auto-setup | Partial — detected event, behavior text needs refinement |
| 3 | Crash recovery | Tested — validated config, confirmed nginx restarted |
| 4 | Dangerous chmod | Tested — detected chmod 777, reverted to 640 |
| 5 | curl auto-extract | Partial — detected event, tool executor timeout in VM |
| 6 | Docker guardrails | Not tested — no docker in VM |
| 7 | SSH key hardening | Tested — replaced RSA with ed25519 |
| 8 | Repeated command alias | Not tested — needs temporal pattern detection |
| 9 | Config auto-validate | Tested — nginx -t + systemctl restart |
| 10 | Package security scan | Tested — detected typosquat "reqeusts" |
| 11 | Spec file scaffold | Tested — todo CLI, Go API, weather dashboard all scaffolded correctly |

Single agent with accumulated behaviors via `veronica add`. Comm filter prevents noise. LLM: LM Studio (default) or OpenRouter.
