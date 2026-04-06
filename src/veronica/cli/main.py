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
from veronica.mcp_server import run_mcp_server, set_watcher
from veronica.opencode import OpenCodeClient
from veronica.watcher import EventWatcher

app = typer.Typer(help="Control the Veronica eBPF intelligence layer.")
vm_app = typer.Typer(help="Manage the Lima VM lifecycle.")
app.add_typer(vm_app, name="vm")

cfg = VeronicaConfig()


# --- Helpers ---

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
    return {"behaviors": [], "subagents": {}}


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
    """Create ~/.veronica/.opencode/opencode.json with MCP config."""
    oc_dir = cfg.opencode_config_dir
    oc_dir.mkdir(parents=True, exist_ok=True)
    oc_config = {
        "mcp": {
            "veronica": {
                "type": "remote",
                "url": f"http://localhost:{cfg.mcp_port}/mcp",
            }
        },
    }
    (oc_dir / "opencode.json").write_text(json.dumps(oc_config, indent=2))


# --- Core commands ---

@app.command()
def start():
    """Start everything: VM, daemon, MCP server, OpenCode, and event watcher."""
    if _veronica_already_running():
        typer.echo("Veronica is already running. Run `veronica stop` first.", err=True)
        raise typer.Exit(1)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # 1. VM
    if not _vm_running():
        typer.echo("Starting VM...")
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)

    # 2. Daemon
    typer.echo("Starting daemon...")
    _vm_shell("sudo", "systemctl", "start", "veronica")

    # 3. OpenCode config
    _setup_opencode_config()

    # 4. MCP server (background thread)
    typer.echo("Starting MCP server...")
    mcp_thread = threading.Thread(target=run_mcp_server, args=(cfg.mcp_port, cfg.nats_url), daemon=True)
    mcp_thread.start()

    # 5. OpenCode (background process)
    typer.echo("Starting OpenCode...")
    cfg.veronica_dir.mkdir(parents=True, exist_ok=True)
    oc_proc = subprocess.Popen(
        ["opencode", "serve", "--port", str(cfg.opencode_port)],
        cwd=str(cfg.veronica_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)

    # 6. Create sessions and start watcher
    async def _run():
        client = OpenCodeClient(base_url=cfg.opencode_url)
        data = _load_behaviors()

        # Watcher (created early so MCP subscribe tool can update routing)
        watcher = EventWatcher(
            nats_url=cfg.nats_url, opencode=client,
            provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
        )
        watcher.set_routing(data.get("subagents", {}))
        set_watcher(watcher, cfg.behaviors_file)

        # Create a session per behavior (skip if already exists)
        for behavior in data.get("behaviors", []):
            existing = [n for n, sa in data.get("subagents", {}).items() if sa.get("behavior") == behavior]
            if existing:
                typer.echo(f"  Active: {existing[0]}")
                continue

            name = behavior.lower().replace(" ", "-")[:30]
            session = await client.create_session()
            data.setdefault("subagents", {})[name] = {
                "name": name,
                "session_id": session["id"],
                "behavior": behavior,
                "subscriptions": [],
                "comm_filter": [],
            }
            _save_behaviors(data)
            typer.echo(f"  New: {name}")

            await client.send_message(
                session["id"],
                f"You are a Veronica eBPF agent. Your behavior: {behavior}\n\n"
                "First, call list_subscriptions to see available eBPF event types. "
                "Then call subscribe with your agent name and the event types + comm filters relevant to your behavior. "
                f"Your agent name is: {name}\n\n"
                "After subscribing, wait for events. When you receive events, act on them using the tools available to you.",
                provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
            )

        await watcher.start()
        n = len(data.get("subagents", {}))
        typer.echo(f"\nVeronica running with {n} agent{'s' if n != 1 else ''} (Ctrl+C to stop)")

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
        typer.echo("\nShutting down...")
    finally:
        oc_proc.terminate()


@app.command()
def stop():
    """Stop everything: Veronica, OpenCode, and daemon."""
    # Stop Veronica process
    result = subprocess.run(["pgrep", "-f", "veronica start"], capture_output=True, text=True)
    our_pid = os.getpid()
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            os.kill(pid, 9)
            typer.echo(f"Stopped Veronica (pid {pid})")

    # Stop OpenCode
    subprocess.run(["pkill", "-f", "opencode serve"], capture_output=True)
    typer.echo("Stopped OpenCode")

    # Stop daemon
    typer.echo("Stopping daemon...")
    _vm_shell("sudo", "systemctl", "stop", "veronica")


@app.command()
def status():
    """Show status of all components."""
    # VM
    if _vm_running():
        typer.echo("VM:      running")
    else:
        typer.echo("VM:      stopped")

    # Daemon
    result = subprocess.run(
        ["limactl", "shell", cfg.vm_name, "--", "sudo", "systemctl", "is-active", "veronica"],
        capture_output=True, text=True,
    )
    daemon_status = result.stdout.strip() if result.returncode == 0 else "stopped"
    typer.echo(f"Daemon:  {daemon_status}")

    # OpenCode
    result = subprocess.run(["pgrep", "-f", "opencode serve"], capture_output=True, text=True)
    typer.echo(f"OpenCode: {'running' if result.stdout.strip() else 'stopped'}")

    # Behaviors
    data = _load_behaviors()
    behaviors = data.get("behaviors", [])
    subagents = data.get("subagents", {})
    typer.echo(f"\nBehaviors: {len(behaviors)}")
    for i, b in enumerate(behaviors, 1):
        name = next((n for n, sa in subagents.items() if sa.get("behavior") == b), None)
        subs = subagents.get(name, {}).get("subscriptions", []) if name else []
        typer.echo(f"  {i}. {b}")
        if subs:
            typer.echo(f"     → {name} listening on {subs}")


@app.command()
def logs():
    """Stream daemon logs."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name, "--", "sudo", "journalctl", "-u", "veronica", "-f"])


# --- Build commands ---

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
    """Full first-time setup: sync source, compile eBPF, build daemon, install service."""
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


# --- VM commands ---

@vm_app.command("start")
def vm_start():
    """Create and start the Lima VM."""
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
    typer.echo(f"Added: {description}")
    typer.echo("Run `veronica start` to activate.")


@app.command("list")
def list_behaviors():
    """List all behaviors and their status."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", [])
    subagents = data.get("subagents", {})

    if not behaviors:
        typer.echo("No behaviors. Run `veronica add \"...\"` to add one.")
        return

    for i, b in enumerate(behaviors, 1):
        name = next((n for n, sa in subagents.items() if sa.get("behavior") == b), None)
        if name:
            subs = subagents[name].get("subscriptions", [])
            comms = subagents[name].get("comm_filter", [])
            status = f"→ {name} [{', '.join(subs)}]"
            if comms:
                status += f" comms={comms}"
        else:
            status = "(pending)"
        typer.echo(f"  {i}. {b} {status}")


@app.command()
def rm(description: str = typer.Argument(help="Behavior text to remove (partial match)")):
    """Remove a behavior."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", [])
    matches = [b for b in behaviors if description.lower() in b.lower()]

    if not matches:
        typer.echo(f"No behavior matching '{description}'")
        return

    subagents = data.get("subagents", {})
    for m in matches:
        behaviors.remove(m)
        typer.echo(f"Removed: {m}")
        for name, sa in list(subagents.items()):
            if sa.get("behavior") == m:
                del subagents[name]

    data["behaviors"] = behaviors
    _save_behaviors(data)
