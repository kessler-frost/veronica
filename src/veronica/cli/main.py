"""Veronica CLI — manage daemon, VM, and behaviors."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
import uuid
from pathlib import Path

import typer

from veronica.config import VeronicaConfig

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
    """Load behaviors.json. Format:
    {"behaviors": {"<uuid>": {"description": "...", "config": null | {...}}}}
    """
    if cfg.behaviors_file.exists():
        return json.loads(cfg.behaviors_file.read_text())
    return {"behaviors": {}}


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


# --- Core commands ---

@app.command()
def start():
    """Start everything: VM, daemon, Agentfield control plane, and behavior agents."""
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

    # 3. Agentfield control plane (background process)
    typer.echo("Starting Agentfield control plane...")
    af_proc = subprocess.Popen(
        ["af", "server"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    # 4. Start behavior agents
    data = _load_behaviors()
    behaviors = data.get("behaviors", {})

    async def _run():
        from veronica.agent import create_behavior_agent

        agents = []
        for agent_id, info in behaviors.items():
            desc = info["description"]
            existing_config = info.get("config")
            configured = "configured" if existing_config else "will self-configure"
            typer.echo(f"  Starting agent {agent_id}... ({configured})")
            agent = create_behavior_agent(
                agent_id=agent_id,
                behavior=desc,
                agentfield_url=cfg.agentfield_url,
                llm_url=cfg.llm_url,
                llm_model=cfg.llm_model,
                behaviors_file=cfg.behaviors_file,
                existing_config=existing_config,
                llm_api_key=cfg.llm_api_key,
            )
            agents.append(agent)

        n = len(agents)
        typer.echo(f"\nVeronica running with {n} behavior agent{'s' if n != 1 else ''} (Ctrl+C to stop)")

        # Start serving all agents, then boot (self-configure + subscribe)
        serve_tasks = [asyncio.create_task(a.serve()) for a in agents]
        # Give agents a moment to register with control plane before booting
        await asyncio.sleep(1)
        for a in agents:
            if hasattr(a, "_boot"):
                await a._boot()

        try:
            await asyncio.gather(*serve_tasks)
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        typer.echo("\nShutting down...")
    finally:
        af_proc.terminate()


@app.command()
def stop():
    """Stop everything: behavior agents, control plane, and daemon."""
    # Stop Veronica process
    result = subprocess.run(["pgrep", "-f", "veronica start"], capture_output=True, text=True)
    our_pid = os.getpid()
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            os.kill(pid, 9)
            typer.echo(f"Stopped Veronica (pid {pid})")

    # Stop Agentfield control plane
    subprocess.run(["pkill", "-f", "af server"], capture_output=True)
    typer.echo("Stopped Agentfield control plane")

    # Stop daemon
    typer.echo("Stopping daemon...")
    _vm_shell("sudo", "systemctl", "stop", "veronica")


@app.command()
def status():
    """Show status of all components."""
    # VM
    if _vm_running():
        typer.echo("VM:             running")
    else:
        typer.echo("VM:             stopped")

    # Daemon
    result = subprocess.run(
        ["limactl", "shell", cfg.vm_name, "--", "sudo", "systemctl", "is-active", "veronica"],
        capture_output=True, text=True,
    )
    daemon_status = result.stdout.strip() if result.returncode == 0 else "stopped"
    typer.echo(f"Daemon:         {daemon_status}")

    # Agentfield
    result = subprocess.run(["pgrep", "-f", "af server"], capture_output=True, text=True)
    typer.echo(f"Control Plane:  {'running' if result.stdout.strip() else 'stopped'}")

    # Behaviors
    data = _load_behaviors()
    behaviors = data.get("behaviors", {})
    typer.echo(f"\nBehaviors: {len(behaviors)}")
    for agent_id, info in behaviors.items():
        desc = info["description"]
        config = info.get("config")
        typer.echo(f"  {agent_id}  {desc}")
        if config:
            subs = config.get("subscriptions", [])
            comms = config.get("comm_filter", [])
            typer.echo(f"           events={subs} comm_filter={comms}")
        else:
            typer.echo(f"           (will self-configure on first boot)")


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
    agent_id = uuid.uuid4().hex[:8]
    data.setdefault("behaviors", {})[agent_id] = {
        "description": description,
        "config": None,
    }
    _save_behaviors(data)
    typer.echo(f"Added [{agent_id}]: {description}")
    typer.echo("Run `veronica start` to activate. Agent will self-configure on first boot.")


@app.command("list")
def list_behaviors():
    """List all behaviors and their configuration."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", {})

    if not behaviors:
        typer.echo("No behaviors. Run `veronica add \"...\"` to add one.")
        return

    for agent_id, info in behaviors.items():
        desc = info["description"]
        config = info.get("config")
        typer.echo(f"  {agent_id}  {desc}")
        if config:
            subs = config.get("subscriptions", [])
            comms = config.get("comm_filter", [])
            typer.echo(f"           events={subs} comm_filter={comms}")
        else:
            typer.echo(f"           (will self-configure on first boot)")


@app.command()
def rm(description: str = typer.Argument(help="Behavior text or UUID prefix to remove")):
    """Remove a behavior by description (partial match) or UUID prefix."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", {})

    # Try UUID prefix match first, then description match
    to_remove = []
    for agent_id, info in behaviors.items():
        if agent_id.startswith(description) or description.lower() in info["description"].lower():
            to_remove.append(agent_id)

    if not to_remove:
        typer.echo(f"No behavior matching '{description}'")
        return

    for agent_id in to_remove:
        desc = behaviors.pop(agent_id)["description"]
        typer.echo(f"Removed [{agent_id}]: {desc}")

    _save_behaviors(data)
