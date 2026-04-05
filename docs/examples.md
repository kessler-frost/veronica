# Veronica: Intelligence Scenarios

Real-world examples of how Veronica adds value to daily workflows. Each scenario shows what the user does, what eBPF observes, and what Veronica autonomously decides to do.

## 1. Project Scaffolding

**Trigger:** `mkdir my-fastapi-app`
**eBPF hook:** `sched_process_exec` tracepoint catches `mkdir`
**What Veronica does:**
- Infers the intended stack from the directory name — "fastapi" means Python + FastAPI
- Runs `uv init`, installs FastAPI + uvicorn
- Generates `main.py` with a hello world route
- User walks into a ready-to-go project

## 2. Git Clone → Auto-Setup

**Trigger:** `git clone https://github.com/someone/cool-project.git`
**eBPF hook:** `sched_process_exec` tracepoint catches `git`
**What Veronica does:**
- Inspects the cloned repo to detect the language/framework
- `pyproject.toml` → runs `uv sync`
- `package.json` → runs `npm install`
- `go.mod` → runs `go mod download`
- Adapts to whatever it finds

## 3. Crash Recovery

**Trigger:** nginx exits with code 1
**eBPF hook:** `sched_process_exit` tracepoint catches nginx exit
**What Veronica does:**
- Doesn't blindly restart — checks logs first to understand why the crash happened
- Validates the config with `nginx -t` before restarting
- If config is broken, diagnoses the issue rather than restart-looping

## 4. Dangerous Command Interception

**Trigger:** `chmod 777 /etc/shadow`
**eBPF hook:** `sched_process_exec` tracepoint catches `chmod`
**What Veronica does:**
- Recognizes that `777` on a sensitive system file is dangerous
- Knows the correct permissions for shadow files (`640`)
- Reverts immediately — doesn't just block, it fixes

## 5. Smart curl → Auto-Extract

**Trigger:** `curl -O https://example.com/dataset.tar.gz`
**eBPF hook:** `sched_process_exec` tracepoint catches `curl`
**What Veronica does:**
- Detects the downloaded file is an archive from the filename extension
- Extracts to the same directory where the download happened
- Cleans up the archive — handles .tar.gz, .zip, .tgz

## 6. Docker Run → Resource Guardrails

**Trigger:** `docker run -d postgres`
**eBPF hook:** `sched_process_exec` tracepoint catches `docker`
**What Veronica does:**
- Detects a container started without resource limits
- Applies sensible defaults (memory cap, CPU quota)
- Sets up a health check — prevents runaway containers from eating the host

## 7. SSH Key Generation → Security Hardening

**Trigger:** `ssh-keygen -t rsa`
**eBPF hook:** `sched_process_exec` tracepoint catches `ssh-keygen`
**What Veronica does:**
- Recognizes RSA is outdated
- Deletes the RSA key, regenerates as ed25519 (more secure, faster)
- Sets proper permissions — 600 on private key, 644 on public
- Doesn't just warn, it fixes

## 8. Repeated Command → Suggest Alias

**Trigger:** User runs `docker compose up -d` 12 times in one day
**eBPF hook:** `sched_process_exec` tracepoint catches repeated patterns
**What Veronica does:**
- Detects temporal patterns — same command run frequently
- Creates a shell alias or Makefile target
- Adds it to the user's config — requires pattern memory across events

## 9. File Editing → Auto-Validate

**Trigger:** User edits `/etc/nginx/nginx.conf`
**eBPF hook:** `kprobe/do_sys_openat2` catches write to `/etc/` path
**What Veronica does:**
- Detects a config file was modified (write-only file open, not reads)
- Knows which service owns which config — runs `nginx -t` for nginx configs
- If valid, reloads the service
- If broken, logs the validation error

## 10. Package Install → Security Scan

**Trigger:** `pip install reqeusts`
**eBPF hook:** `sched_process_exec` tracepoint catches `pip`
**What Veronica does:**
- Compares the package name against known packages
- Detects "reqeusts" is a likely typosquat of "requests" (transposed letters)
- Attempts to kill the install and warns
- Doesn't need a database — the LLM recognizes the pattern

## 11. Spec File → Auto-Scaffold

**Trigger:** User writes `todo_project.md` describing a project
**eBPF hook:** `kprobe/do_sys_openat2` catches write to `*_project.md`
**What Veronica does:**
- Reads the spec file and understands the described project structure
- Scaffolds in the same directory as the spec file
- A Python todo CLI spec → `main.py` with add/list/done commands, `pyproject.toml`, JSON data file
- A Go API spec → `main.go` with HTTP handlers, `go.mod`
- Adapts to whatever the spec describes

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

Veronica uses a single agent with accumulated behaviors via `veronica add`. Comm filter prevents noise. LLM: LM Studio (default) or OpenRouter.
