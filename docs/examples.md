# Veronica: Intelligence Scenarios

Real-world examples of how Veronica adds value to daily workflows. Each scenario describes what the user does, what Veronica observes via eBPF, and what action it takes autonomously.

## 1. Project Scaffolding

**Trigger:** `mkdir my-flask-api`
**Category:** Proactive
**What Veronica does:**
- Detects "flask" + "api" in the directory name
- Enters the directory
- Runs `uv init`, `uv add flask`
- Creates `app.py` with a hello world route
- Creates a `Dockerfile`
- User walks into a ready-to-go project

## 2. Git Clone → Auto-Setup

**Trigger:** `git clone https://github.com/someone/cool-project.git`
**Category:** Proactive
**What Veronica does:**
- Waits for clone to complete (watches process_exit for git)
- Inspects the cloned repo
- Detects `pyproject.toml` → runs `uv sync`
- Detects `package.json` → runs `bun install`
- Detects `go.mod` → runs `go mod download`
- Detects `.env.example` → copies to `.env`

## 3. Crash Recovery

**Trigger:** nginx exits with code 1
**Category:** Immediate (process_exit, non-zero exit code, known service)
**What Veronica does:**
- Reads the nginx error log
- Diagnoses the issue (e.g., bad config syntax on line 42)
- Fixes the config
- Restarts nginx
- Verifies it's healthy

## 4. Dangerous Command Interception

**Trigger:** `chmod 777 /etc/shadow`
**Category:** Immediate (sensitive file)
**What Veronica does:**
- Detects permission change on a sensitive file
- Reverts permissions to 640
- Logs the incident

## 5. Smart curl → Auto-Extract

**Trigger:** `curl -O https://example.com/dataset.tar.gz`
**Category:** Proactive
**What Veronica does:**
- Monitors the download (watches file_write events)
- Once complete, extracts to a directory
- Cleans up the archive

## 6. Docker Run → Resource Guardrails

**Trigger:** `docker run -d postgres`
**Category:** Proactive
**What Veronica does:**
- Detects container started without resource limits
- Sets memory/CPU limits on the container
- Sets up a health check
- Logs the configuration

## 7. SSH Key Generation → Security Hardening

**Trigger:** `ssh-keygen -t rsa`
**Category:** Proactive
**What Veronica does:**
- Detects RSA key generation
- Generates an ed25519 key instead (more secure, faster)
- Checks if `~/.ssh/config` exists
- Sets proper permissions on the key files

## 8. Repeated Command → Suggest Alias

**Trigger:** User runs `docker compose up -d` 12 times in one day
**Category:** Digest (pattern detection)
**What Veronica does:**
- Digest agent notices the repetition pattern
- Creates a shell alias or Makefile target
- Adds it to the user's shell config

## 9. File Editing → Auto-Validate

**Trigger:** User edits `/etc/nginx/nginx.conf` (vim, nano, etc.)
**Category:** Immediate (file_write on config file)
**What Veronica does:**
- Detects the config file was modified
- Runs `nginx -t` to validate
- If valid: auto-reloads nginx
- If broken: reverts to the backup, alerts via log

## 10. Package Install → Security Scan

**Trigger:** `uv add some-random-package`
**Category:** Proactive
**What Veronica does:**
- Checks if the package name looks suspicious (typosquatting)
- Verifies the package has a reasonable download count / age
- Warns in the log if it looks risky

---

## Implementation Status

| # | Scenario | Classifier | Action Executor | Prompt | Status |
|---|---|---|---|---|---|
| 1 | Project scaffolding | Proactive (mkdir) | Needs real executor | Needs tuning | Not tested |
| 2 | Git clone auto-setup | Proactive (git) | Needs real executor | Needs tuning | Not tested |
| 3 | Crash recovery | Needs: process_exit + non-zero → Immediate | Needs real executor | Needs tuning | Not tested |
| 4 | Dangerous chmod | Immediate (sensitive file) | Needs real executor | Needs tuning | Not tested |
| 5 | curl auto-extract | Proactive (curl) | Needs real executor | Needs tuning | Not tested |
| 6 | Docker guardrails | Proactive (docker) | Needs real executor | Needs tuning | Not tested |
| 7 | SSH key hardening | Needs: ssh-keygen → Proactive | Needs real executor | Needs tuning | Not tested |
| 8 | Repeated command alias | Digest (pattern detection) | Needs real executor | Needs tuning | Not tested |
| 9 | Config auto-validate | Needs: file_write on configs → Immediate | Needs real executor | Needs tuning | Not tested |
| 10 | Package security scan | Proactive (uv) | Needs real executor | Needs tuning | Not tested |

## Common requirements across all scenarios

1. **Real action executor** — currently stubbed, needs to actually run shell commands
2. **Classifier updates** — some commands need to move between categories
3. **Prompt tuning** — each scenario needs specific instructions in the system prompt
4. **Notification** — actions are silent (just do it), observable via `veronica logs` or future TUI
