"""Veronica CLI — manage daemon, VM, and agents."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess

import typer

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


# --- Top-level commands ---

@app.command()
def start():
    """Start VM, daemon, and agent runner. Idempotent."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not _vm_running():
        typer.echo(f"Starting Lima VM {cfg.vm_name!r}...")
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)
    else:
        typer.echo(f"Lima VM {cfg.vm_name!r} already running.")

    typer.echo("Starting daemon...")
    _vm_shell("sudo", "systemctl", "start", "veronica")

    typer.echo("Starting agent runner (Ctrl+C to stop)...")
    from veronica.agents.runner import AgentRunner
    runner = AgentRunner(cfg)
    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        typer.echo("Shutting down...")


@app.command()
def stop():
    """Stop daemon service."""
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
    """Build daemon in VM and restart."""
    typer.echo("Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.project_path} && GOTOOLCHAIN=auto sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")
    typer.echo("Restarting service...")
    _vm_shell("sudo", "systemctl", "restart", "veronica")


@app.command()
def setup():
    """Full setup: eBPF compile, build, install service."""
    if not _vm_running():
        typer.echo("VM not running — run `veronica vm start` first", err=True)
        raise typer.Exit(1)
    ebpf_dir = f"{cfg.project_path}/internal/ebpf/programs"
    typer.echo("1/5 Generating vmlinux.h...")
    _vm_shell("bash", "-c", f"cd {ebpf_dir} && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h")
    typer.echo("2/5 Compiling eBPF programs...")
    for prog in ["process_exec", "file_open", "net_connect", "process_exit"]:
        _vm_shell("bash", "-c", f"cd {ebpf_dir} && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c {prog}.c -o {prog}.o")
        typer.echo(f"   {prog}.o OK")
    typer.echo("3/5 Generating Go bindings...")
    _vm_shell("bash", "-c", f"cd {cfg.project_path} && GOTOOLCHAIN=auto go generate ./internal/ebpf/bpf/")
    typer.echo("4/5 Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.project_path} && GOTOOLCHAIN=auto sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")
    typer.echo("5/5 Installing systemd service...")
    _vm_shell("sudo", "cp", f"{cfg.project_path}/lima/veronica.service", "/etc/systemd/system/veronica.service")
    _vm_shell("sudo", "systemctl", "daemon-reload")
    _vm_shell("sudo", "systemctl", "enable", "veronica")
    typer.echo("Setup complete. Run `veronica start`.")


# --- VM subcommands ---

@vm_app.command("start")
def vm_start():
    """Start the Lima VM."""
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


# --- Agent subcommands (Phase 2 stubs) ---

@agent_app.command("list")
def agent_list():
    """List all registered agents."""
    typer.echo("Agent management coming in Phase 2. Use NATS KV directly for now.")


@agent_app.command("add")
def agent_add(description: str = typer.Argument(help="Natural language description")):
    """Create an agent from natural language. (Phase 2)"""
    typer.echo(f"Agent creation coming in Phase 2. Description: {description}")


@agent_app.command("stop")
def agent_stop(name: str = typer.Argument(help="Agent name")):
    """Stop a specific agent. (Phase 2)"""
    typer.echo(f"Agent stop coming in Phase 2. Name: {name}")


@agent_app.command("rm")
def agent_rm(name: str = typer.Argument(help="Agent name")):
    """Remove an agent. (Phase 2)"""
    typer.echo(f"Agent remove coming in Phase 2. Name: {name}")
