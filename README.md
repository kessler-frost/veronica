# Veronica

> Proactive agents at the kernel level, powered by eBPF

| User did | Agent did |
|---|---|
| `mkdir my-fastapi-app` | Scaffolded full project — `main.py`, `requirements.txt`, tests |
| `mkdir my-go-server` | `go mod init`, created `main.go`, `Makefile` |
| `git clone flask.git` | Detected `pyproject.toml`, installed uv, ran `uv sync` |
| `chmod 777 /etc/shadow` | Reverted to `640` immediately |
| `ssh-keygen -t rsa` | Replaced with `ed25519`, fixed permissions |
| `pip install reqeusts` | Caught typosquat, killed install |
| nginx crashed | Diagnosed via logs, restarted service |
| Edited `nginx.conf` | Validated with `nginx -t`, reloaded service |

## Quick Start

```bash
# Install
git clone https://github.com/kessler-frost/veronica.git
cd veronica
uv sync

# Create and setup VM (one-time)
uv run veronica vm start
uv run veronica setup

# Add an agent
uv run veronica agent add "scaffold projects automatically based on directory creation"

# Start (blocks — Ctrl+C to stop)
uv run veronica start
```

Requires: macOS (Apple Silicon) or Linux, [uv](https://docs.astral.sh/uv/), [Lima](https://lima-vm.io/), and [LM Studio](https://lmstudio.ai/) for local inference. For cloud models, set `VERONICA_LLM_PROVIDER=openrouter` and `OPENROUTER_API_KEY`.
