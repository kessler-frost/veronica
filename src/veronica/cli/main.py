"""Veronica CLI — manage daemon, VM, and agents."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path

import msgspec
import nats as nats_client
import typer

from veronica.agents.creator import create_agent_config
from veronica.agents.runner import AgentRunner
from veronica.config import VeronicaConfig

app = typer.Typer(help="Control the Veronica eBPF intelligence layer.")
vm_app = typer.Typer(help="Manage the Lima VM lifecycle.")
agent_app = typer.Typer(help="Manage agents.")
app.add_typer(vm_app, name="vm")
app.add_typer(agent_app, name="agent")

cfg = VeronicaConfig()


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
    # Copy Go source, eBPF programs, configs — exclude .git, __pycache__, etc.
    subprocess.run([
        "limactl", "cp", "-r",
        f"{host_root}/cmd", f"{cfg.vm_name}:{vm_path}/cmd",
    ], check=True)
    subprocess.run([
        "limactl", "cp", "-r",
        f"{host_root}/internal", f"{cfg.vm_name}:{vm_path}/internal",
    ], check=True)
    for f in ["go.mod", "go.sum"]:
        src = host_root / f
        if src.exists():
            subprocess.run([
                "limactl", "cp", str(src), f"{cfg.vm_name}:{vm_path}/{f}",
            ], check=True)
    # Copy lima service file
    service = host_root / "lima" / "veronica.service"
    if service.exists():
        _vm_shell("mkdir", "-p", f"{vm_path}/lima")
        subprocess.run([
            "limactl", "cp", str(service), f"{cfg.vm_name}:{vm_path}/lima/veronica.service",
        ], check=True)


# --- Top-level commands ---

def _veronica_already_running() -> bool:
    """Check if another veronica start process is already running."""
    our_pid = os.getpid()
    result = subprocess.run(
        ["pgrep", "-f", "veronica start"],
        capture_output=True, text=True,
    )
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            return True
    return False


@app.command()
def start():
    """Start VM, daemon, and agent runner. Idempotent."""
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

    typer.echo("Starting agent runner (Ctrl+C to stop)...")
    runner = AgentRunner(cfg)
    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        typer.echo("Shutting down...")


@app.command()
def stop():
    """Stop agent runner and daemon service."""
    # Kill any running veronica start processes (agent runners)
    result = subprocess.run(["pgrep", "-f", "veronica start"], capture_output=True, text=True)
    our_pid = os.getpid()
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            os.kill(pid, 9)
            typer.echo(f"Killed agent runner (pid {pid})")
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
    """Run a command inside the VM."""
    _vm_shell(*ctx.args, check=False)


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
    """Start the Lima VM. Creates from lima config if it doesn't exist."""
    # Check if instance exists
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


# --- Agent subcommands ---

@agent_app.command("add")
def agent_add(description: str = typer.Argument(help="Natural language description")):
    """Create an agent from natural language."""

    async def _add():
        config = await create_agent_config(
            description,
            llm_provider=cfg.llm_provider,
            llm_base_url=cfg.llm_base_url,
            llm_model=cfg.llm_model,
            openrouter_model=cfg.openrouter_model,
        )

        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        agent_data = {
            "events": config["events"],
            "filter": config.get("filter", {}),
            "context": config["context"],
            "status": "active",
            "description": description,
        }
        await kv.put(config["name"], msgspec.json.encode(agent_data))
        await nc.close()

        typer.echo(f"Created agent '{config['name']}'")
        typer.echo(f"  Subscribed to: {', '.join(config['events'])}")
        typer.echo(f"  Filter: {config.get('filter', {})}")
        typer.echo(f"  Context: {config['context']}")

    asyncio.run(_add())


@agent_app.command("list")
def agent_list():
    """List all registered agents."""

    async def _list():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        try:
            keys = await kv.keys()
        except Exception:
            typer.echo("No agents registered.")
            await nc.close()
            return

        for key in keys:
            entry = await kv.get(key)
            config = msgspec.json.decode(entry.value, type=dict)
            status = config.get("status", "unknown")
            desc = config.get("description", config.get("context", ""))
            events = ", ".join(config.get("events", []))
            typer.echo(f"  {key:20s} {status:10s} events=[{events}]  {desc[:60]}")

        await nc.close()

    asyncio.run(_list())


@agent_app.command("stop")
def agent_stop(name: str = typer.Argument(help="Agent name")):
    """Stop a specific agent."""

    async def _stop():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        entry = await kv.get(name)
        config = msgspec.json.decode(entry.value, type=dict)
        config["status"] = "stopped"
        await kv.put(name, msgspec.json.encode(config))
        await nc.close()
        typer.echo(f"Stopped agent '{name}'")

    asyncio.run(_stop())


@agent_app.command("rm")
def agent_rm(name: str = typer.Argument(help="Agent name")):
    """Remove an agent."""

    async def _rm():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")
        await kv.delete(name)
        await nc.close()
        typer.echo(f"Removed agent '{name}'")

    asyncio.run(_rm())
