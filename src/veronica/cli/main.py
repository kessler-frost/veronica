"""Veronica CLI — manage daemon, VM, and behaviors."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import typer

from veronica.config import VeronicaConfig

app = typer.Typer(help="Control the Veronica eBPF intelligence layer.")
vm_app = typer.Typer(help="Manage the Lima VM lifecycle.")
app.add_typer(vm_app, name="vm")

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
    """Start VM, daemon, and agent. Idempotent."""
    typer.echo("Not yet implemented — pending OpenCode integration.")
    raise typer.Exit(1)


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


# --- Behavior commands (stubs — pending OpenCode integration) ---

@app.command()
def add(description: str = typer.Argument(help="Natural language behavior description")):
    """Add a behavior to Veronica."""
    typer.echo("Not yet implemented — pending OpenCode integration.")
    raise typer.Exit(1)


@app.command("list")
def list_behaviors():
    """List all behaviors."""
    typer.echo("Not yet implemented — pending OpenCode integration.")
    raise typer.Exit(1)


@app.command()
def rm(description: str = typer.Argument(help="Behavior text to remove (partial match)")):
    """Remove a behavior."""
    typer.echo("Not yet implemented — pending OpenCode integration.")
    raise typer.Exit(1)
