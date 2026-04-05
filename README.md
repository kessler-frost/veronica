# Veronica

> Proactive agents at the kernel level, powered by eBPF

| User did | Agent did |
|---|---|
| `mkdir my-fastapi-app` | Scaffolded full project — `uv init`, FastAPI, routes, tests |
| `mkdir my-go-server` | `go mod init`, created `cmd/`, `Makefile`, `Dockerfile` |
| `git clone flask.git` | Detected `pyproject.toml`, ran `uv sync` |
| `chmod 777 /etc/shadow` | Reverted to `640` immediately |
| `ssh-keygen -t rsa` | Replaced with `ed25519`, fixed permissions |
| `pip install reqeusts` | Caught typosquat, killed install |
| nginx crashed | Diagnosed via logs, confirmed restart |
| Edited `nginx.conf` | Validated with `nginx -t`, reloaded service |
