"""Veronica CLI — manage daemon and VM lifecycle."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import typer

from veronica.config import VeronicaConfig

app = typer.Typer(help="Control the Veronica daemon running inside the Lima VM.")
vm_app = typer.Typer(help="Manage the Lima VM lifecycle.")
app.add_typer(vm_app, name="vm")

cfg = VeronicaConfig()


def _vm_running() -> bool:
    result = subprocess.run(
        ["limactl", "list", "--json"],
        capture_output=True, text=True,
    )
    for line in result.stdout.strip().splitlines():
        inst = json.loads(line)
        if inst.get("name") == cfg.vm_name:
            return inst.get("status") == "Running"
    return False


def _vm_shell(*args: str, check: bool = True, stream: bool = True) -> subprocess.CompletedProcess:
    cmd = ["limactl", "shell", cfg.vm_name, "--", *args]
    if stream:
        return subprocess.run(cmd, check=check)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _exec_vm_shell(*args: str) -> None:
    """Replace current process with limactl shell (for interactive use)."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name, "--", *args])


@app.command()
def start():
    """Ensure the Lima VM is running and start the Veronica systemd service."""
    if not _vm_running():
        typer.echo(f"Starting Lima VM {cfg.vm_name!r}...")
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)
    else:
        typer.echo(f"Lima VM {cfg.vm_name!r} is already running.")
    typer.echo("Starting systemd service veronica...")
    _vm_shell("sudo", "systemctl", "start", "veronica")


@app.command()
def stop():
    """Stop the Veronica systemd service."""
    typer.echo("Stopping systemd service veronica...")
    _vm_shell("sudo", "systemctl", "stop", "veronica")


@app.command()
def status():
    """Show VM status and daemon service status."""
    typer.echo("=== Lima VM status ===")
    subprocess.run(["limactl", "list", cfg.vm_name])
    typer.echo("\n=== Systemd service status ===")
    _vm_shell("sudo", "systemctl", "status", "veronica", check=False)


@app.command()
def logs():
    """Stream journalctl logs for the Veronica service (Ctrl+C to stop)."""
    _exec_vm_shell("sudo", "journalctl", "-u", "veronica", "-f")


@app.command()
def build():
    """Build the daemon in the VM, install it, and restart the service."""
    typer.echo("Building daemon inside VM...")
    _vm_shell(
        "bash", "-c",
        f"cd {cfg.project_path} && GOTOOLCHAIN=auto sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}",
    )
    typer.echo("Restarting service...")
    _vm_shell("sudo", "systemctl", "restart", "veronica")


@app.command()
def setup():
    """Full setup: vmlinux.h, compile eBPF, generate Go bindings, build daemon, install service."""
    if not _vm_running():
        typer.echo("VM is not running — run `veronica vm start` first", err=True)
        raise typer.Exit(1)

    ebpf_dir = f"{cfg.project_path}/internal/ebpf/programs"

    typer.echo("1/5 Generating vmlinux.h...")
    _vm_shell("bash", "-c", f"cd {ebpf_dir} && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h")

    typer.echo("2/5 Compiling eBPF programs...")
    for prog in ["process_exec", "file_open", "net_connect", "process_exit"]:
        _vm_shell("bash", "-c", f"cd {ebpf_dir} && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c {prog}.c -o {prog}.o")
        typer.echo(f"   {prog}.o OK")

    typer.echo("3/5 Generating Go bindings (bpf2go)...")
    _vm_shell("bash", "-c", f"cd {cfg.project_path} && GOTOOLCHAIN=auto go generate ./internal/ebpf/bpf/")

    typer.echo("4/5 Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.project_path} && GOTOOLCHAIN=auto sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")

    typer.echo("5/5 Installing systemd service...")
    _vm_shell("sudo", "cp", f"{cfg.project_path}/lima/veronica.service", "/etc/systemd/system/veronica.service")
    _vm_shell("sudo", "systemctl", "daemon-reload")
    _vm_shell("sudo", "systemctl", "enable", "veronica")

    typer.echo("Setup complete. Run `veronica start` to start the daemon.")


@app.command()
def run(args: list[str] = typer.Argument(help="Command to run inside the VM")):
    """Run a command inside the VM."""
    _vm_shell(*args)


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
    """Open an interactive shell in the Lima VM."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name])
