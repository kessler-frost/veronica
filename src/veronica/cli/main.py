"""Veronica CLI — manage daemon, VM, and behaviors."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

import typer

from veronica.config import VeronicaConfig
from veronica.mcp_server import run_mcp_server
from veronica.opencode import OpenCodeClient
from veronica.watcher import EventWatcher

app = typer.Typer(help="Control the Veronica eBPF intelligence layer.")
vm_app = typer.Typer(help="Manage the Lima VM lifecycle.")
app.add_typer(vm_app, name="vm")

cfg = VeronicaConfig()

MAIN_AGENT_PROMPT = """You are the Veronica orchestrator. You manage subagents that handle eBPF kernel events on a Linux VM.

When asked to add a behavior:
1. Determine which eBPF event types the subagent needs (process_exec, process_exit, file_open, net_connect)
2. Determine which command names (comms) are relevant — be strict, only exact commands that trigger the behavior
3. Write an agent markdown file using the write tool
4. Spawn the subagent

When asked to remove a behavior, kill the corresponding subagent.

When asked to list behaviors, describe the current subagents and their configurations.

Pay attention to paths in events. When acting on a file or directory, work in the same location.
If a tool or dependency is missing, install it and continue.
You run as root in the VM.
"""


def _vm_running() -> bool:
    result = subprocess.run(["limactl", "list", "--json"], capture_output=True, text=True)
    for line in result.stdout.strip().splitlines():
        inst = json.loads(line)
        if inst.get("name") == cfg.vm_name:
            return inst.get("status") == "Running"
    return False


def _vm_shell(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["limactl", "shell", cfg.vm_name, "--", *args], check=check)


def _sync_to_vm():
    """Copy project source files into the VM."""
    host_root = Path(__file__).resolve().parents[3]
    vm_path = cfg.vm_project_path
    _vm_shell("mkdir", "-p", vm_path)
    subprocess.run(["limactl", "cp", "-r", f"{host_root}/cmd", f"{cfg.vm_name}:{vm_path}/cmd"], check=True)
    subprocess.run(["limactl", "cp", "-r", f"{host_root}/internal", f"{cfg.vm_name}:{vm_path}/internal"], check=True)
    for f in ["go.mod", "go.sum"]:
        src = host_root / f
        if src.exists():
            subprocess.run(["limactl", "cp", str(src), f"{cfg.vm_name}:{vm_path}/{f}"], check=True)
    service = host_root / "lima" / "veronica.service"
    if service.exists():
        _vm_shell("mkdir", "-p", f"{vm_path}/lima")
        subprocess.run(["limactl", "cp", str(service), f"{cfg.vm_name}:{vm_path}/lima/veronica.service"], check=True)


def _load_behaviors() -> dict:
    if cfg.behaviors_file.exists():
        return json.loads(cfg.behaviors_file.read_text())
    return {"behaviors": [], "subagents": {}, "session_id": None}


def _save_behaviors(data: dict) -> None:
    cfg.veronica_dir.mkdir(parents=True, exist_ok=True)
    cfg.behaviors_file.write_text(json.dumps(data, indent=2))


def _veronica_already_running() -> bool:
    our_pid = os.getpid()
    result = subprocess.run(["pgrep", "-f", "veronica start"], capture_output=True, text=True)
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            return True
    return False


def _setup_opencode_config():
    """Create ~/.veronica/.opencode/ with MCP config and main agent."""
    oc_dir = cfg.opencode_config_dir
    agents_dir = oc_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)

    # opencode.json — MCP + provider config
    oc_config = {
        "provider": {
            "openrouter": {
                "api_key": os.environ.get("OPENROUTER_API_KEY", ""),
            }
        },
        "mcp": {
            "veronica": {
                "type": "remote",
                "url": f"http://localhost:{cfg.mcp_port}/mcp",
            }
        },
    }
    (oc_dir / "opencode.json").write_text(json.dumps(oc_config, indent=2))

    # Main agent
    main_agent = f"""---
description: Veronica orchestrator — spawns and manages subagents for eBPF behaviors
mode: primary
---

{MAIN_AGENT_PROMPT}
"""
    (agents_dir / "main.md").write_text(main_agent)


# --- Top-level commands ---

@app.command()
def start():
    """Start VM, daemon, MCP server, OpenCode, and event watcher."""
    if _veronica_already_running():
        typer.echo("Another veronica process is already running. Run `veronica stop` first.", err=True)
        raise typer.Exit(1)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not _vm_running():
        typer.echo(f"Starting Lima VM {cfg.vm_name!r}...")
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)
    else:
        typer.echo(f"Lima VM {cfg.vm_name!r} already running.")

    typer.echo("Starting daemon...")
    _vm_shell("sudo", "systemctl", "start", "veronica")

    # Setup OpenCode config
    _setup_opencode_config()

    # Start MCP server in background thread
    typer.echo(f"Starting MCP server on port {cfg.mcp_port}...")
    mcp_thread = threading.Thread(target=run_mcp_server, args=(cfg.mcp_port, cfg.nats_url), daemon=True)
    mcp_thread.start()

    # Start OpenCode headless
    typer.echo("Starting OpenCode server...")
    env = os.environ.copy()
    env["OPENCODE_DIR"] = str(cfg.opencode_config_dir)
    oc_proc = subprocess.Popen(
        ["opencode", "serve", "--port", str(cfg.opencode_port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(3)  # Wait for OpenCode server to start

    async def _run():
        client = OpenCodeClient(base_url=cfg.opencode_url)

        # Create main session
        data = _load_behaviors()
        session = await client.create_session()
        data["session_id"] = session["id"]
        _save_behaviors(data)

        typer.echo(f"OpenCode session: {session['id']}")

        # Send initial system prompt
        await client.send_message(
            session["id"], MAIN_AGENT_PROMPT,
            provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
        )

        # Replay stored behaviors
        for behavior in data.get("behaviors", []):
            typer.echo(f"Replaying: {behavior}")
            await client.send_message(
                session["id"],
                f"Create and spawn a new subagent for this behavior: {behavior}",
                provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
            )

        # Start event watcher
        watcher = EventWatcher(
            nats_url=cfg.nats_url, opencode=client,
            provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
        )
        watcher.set_routing(data.get("subagents", {}))
        await watcher.start()

        typer.echo("Veronica running (Ctrl+C to stop)...")
        stop = asyncio.Event()
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await watcher.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        typer.echo("Shutting down...")
    finally:
        oc_proc.terminate()


@app.command()
def stop():
    """Stop Veronica and daemon service."""
    result = subprocess.run(["pgrep", "-f", "veronica start"], capture_output=True, text=True)
    our_pid = os.getpid()
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            os.kill(pid, 9)
            typer.echo(f"Stopped Veronica (pid {pid})")
    # Kill OpenCode server
    subprocess.run(["pkill", "-f", "opencode serve"], capture_output=True)
    typer.echo("Stopping daemon...")
    _vm_shell("sudo", "systemctl", "stop", "veronica")


@app.command()
def status():
    """Show VM and daemon status."""
    typer.echo("=== Lima VM ===")
    subprocess.run(["limactl", "list", cfg.vm_name])
    typer.echo("\n=== Daemon ===")
    _vm_shell("sudo", "systemctl", "status", "veronica", check=False)


@app.command()
def logs():
    """Stream daemon logs."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name, "--", "sudo", "journalctl", "-u", "veronica", "-f"])


@app.command()
def build():
    """Sync source to VM, build daemon, and restart."""
    typer.echo("Syncing source to VM...")
    _sync_to_vm()
    typer.echo("Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.vm_project_path} && sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")
    typer.echo("Restarting service...")
    _vm_shell("sudo", "systemctl", "restart", "veronica", check=False)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(ctx: typer.Context):
    """Run a command inside the VM as root."""
    _vm_shell("sudo", *ctx.args, check=False)


@app.command()
def setup():
    """Full setup: sync source, eBPF compile, build, install service."""
    if not _vm_running():
        typer.echo("VM not running — run `veronica vm start` first", err=True)
        raise typer.Exit(1)
    typer.echo("1/6 Syncing source to VM...")
    _sync_to_vm()
    ebpf_dir = f"{cfg.vm_project_path}/internal/ebpf/programs"
    typer.echo("2/6 Generating vmlinux.h...")
    _vm_shell("bash", "-c", f"cd {ebpf_dir} && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h")
    typer.echo("3/6 Compiling eBPF programs...")
    for prog in ["process_exec", "file_open", "net_connect", "process_exit"]:
        _vm_shell("bash", "-c", f"cd {ebpf_dir} && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c {prog}.c -o {prog}.o")
        typer.echo(f"   {prog}.o OK")
    typer.echo("4/6 Generating Go bindings...")
    _vm_shell("bash", "-c", f"cd {cfg.vm_project_path} && go generate ./internal/ebpf/bpf/")
    typer.echo("5/6 Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.vm_project_path} && sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")
    typer.echo("6/6 Installing systemd service...")
    _vm_shell("sudo", "cp", f"{cfg.vm_project_path}/lima/veronica.service", "/etc/systemd/system/veronica.service")
    _vm_shell("sudo", "systemctl", "daemon-reload")
    _vm_shell("sudo", "systemctl", "enable", "veronica")
    typer.echo("Setup complete. Run `veronica start`.")


# --- VM subcommands ---

@vm_app.command("start")
def vm_start():
    """Start the Lima VM."""
    result = subprocess.run(["limactl", "list", "--json"], capture_output=True, text=True)
    exists = any(
        json.loads(line).get("name") == cfg.vm_name
        for line in result.stdout.strip().splitlines()
        if line.strip()
    )
    if exists:
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)
    else:
        yaml_path = Path(__file__).resolve().parents[3] / cfg.lima_config
        subprocess.run(["limactl", "create", f"--name={cfg.vm_name}", str(yaml_path)], check=True)
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)


@vm_app.command("stop")
def vm_stop():
    """Stop the Lima VM."""
    subprocess.run(["limactl", "stop", cfg.vm_name], check=True)


@vm_app.command("ssh")
def vm_ssh():
    """Open interactive shell in VM."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name])


# --- Behavior commands ---

@app.command()
def add(description: str = typer.Argument(help="Natural language behavior description")):
    """Add a behavior to Veronica."""
    data = _load_behaviors()
    data["behaviors"].append(description)
    _save_behaviors(data)

    session_id = data.get("session_id")
    if session_id:
        async def _add():
            client = OpenCodeClient(base_url=cfg.opencode_url)
            await client.send_message(
                session_id,
                f"Create and spawn a new subagent for this behavior: {description}",
                provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
            )
        asyncio.run(_add())
        typer.echo(f"Added and spawned: {description}")
    else:
        typer.echo(f"Added: {description} (will spawn on next `veronica start`)")


@app.command("list")
def list_behaviors():
    """List all behaviors."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", [])
    subagents = data.get("subagents", {})

    if not behaviors:
        typer.echo("No behaviors configured. Run `veronica add \"...\"` to add one.")
        return

    typer.echo(f"Behaviors ({len(behaviors)}):")
    for i, b in enumerate(behaviors, 1):
        typer.echo(f"  {i}. {b}")

    if subagents:
        typer.echo(f"\nSubagents ({len(subagents)}):")
        for name, config in subagents.items():
            subs = config.get("subscriptions", [])
            comms = config.get("comm_filter", [])
            typer.echo(f"  {name}: events={subs} comms={comms}")


@app.command()
def rm(description: str = typer.Argument(help="Behavior text to remove (partial match)")):
    """Remove a behavior."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", [])
    matches = [b for b in behaviors if description.lower() in b.lower()]

    if not matches:
        typer.echo(f"No behavior matching '{description}'")
        return

    for m in matches:
        behaviors.remove(m)
        typer.echo(f"Removed: {m}")

    data["behaviors"] = behaviors
    _save_behaviors(data)

    session_id = data.get("session_id")
    if session_id:
        async def _rm():
            client = OpenCodeClient(base_url=cfg.opencode_url)
            for m in matches:
                await client.send_message(
                    session_id,
                    f"Kill the subagent that handles this behavior: {m}",
                    provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
                )
        asyncio.run(_rm())
