"""Veronica CLI — manage daemon, VM, and behaviors."""

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
from agno.agent import Agent

from veronica.agents.agent import VeronicaAgent
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

    typer.echo("Starting agent (Ctrl+C to stop)...")
    agent = VeronicaAgent(cfg=cfg, nats_url=cfg.nats_url)
    try:
        asyncio.run(agent.run())
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


# --- Behavior commands ---

VALID_EVENTS = frozenset({"process_exec", "process_exit", "net_connect", "file_open"})

SUBSCRIPTION_PROMPT = """Given a list of behaviors for an eBPF kernel agent on Ubuntu Linux, return a JSON object with:
- "events": array of eBPF event types to subscribe to. Valid: process_exec, process_exit, file_open, net_connect
- "comms": array of ONLY the command names directly relevant to these behaviors. Be minimal — only include commands the agent must see to act. Do NOT include every possible variant or package manager on other distros.

Example for "scaffold projects based on directory creation":
{"events": ["process_exec"], "comms": ["mkdir", "git", "npm", "uv", "go"]}

Example for "revert dangerous permission changes":
{"events": ["process_exec"], "comms": ["chmod", "chown"]}

Example for "watch for service crashes and restart them":
{"events": ["process_exit"], "comms": ["nginx", "postgres", "node", "python3"]}

Return ONLY the JSON object, no other text."""


async def _resolve_subscriptions(behaviors: list[str]) -> tuple[list[str], list[str]]:
    """Ask LLM which events and comms the behaviors need. Returns (events, comms)."""
    model = cfg.build_model()
    sub_agent = Agent(
        model=model,
        instructions=SUBSCRIPTION_PROMPT,
        markdown=False,
    )
    behaviors_text = "\n".join(f"- {b}" for b in behaviors)
    response = await sub_agent.arun(f"Behaviors:\n{behaviors_text}")
    content = response.content.strip() if response else "{}"

    json_start = content.find("{")
    json_end = content.rfind("}") + 1
    if json_start >= 0 and json_end > 0:
        result = msgspec.json.decode(content[json_start:json_end].encode(), type=dict)
        events = [e for e in result.get("events", []) if e in VALID_EVENTS]
        comms = result.get("comms", [])
        return events, comms

    return [], []


@app.command()
def add(description: str = typer.Argument(help="Natural language behavior description")):
    """Add a behavior to Veronica."""

    async def _add():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        try:
            entry = await kv.get("veronica")
            config = msgspec.json.decode(entry.value, type=dict)
        except Exception:
            config = {"behaviors": [], "subscriptions": [], "comm_filter": []}

        config["behaviors"].append(description)

        events, comms = await _resolve_subscriptions(config["behaviors"])
        config["subscriptions"] = events
        config["comm_filter"] = comms

        await kv.put("veronica", msgspec.json.encode(config))
        await nc.close()

        typer.echo(f"Added: {description}")
        typer.echo(f"  Subscriptions: {config['subscriptions']}")
        typer.echo(f"  Watching: {config['comm_filter']}")
        typer.echo(f"  Total behaviors: {len(config['behaviors'])}")

    asyncio.run(_add())


@app.command("list")
def list_behaviors():
    """List all behaviors."""

    async def _list():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        try:
            entry = await kv.get("veronica")
            config = msgspec.json.decode(entry.value, type=dict)
        except Exception:
            typer.echo("No behaviors configured. Run `veronica add \"...\"` to add one.")
            await nc.close()
            return

        typer.echo(f"Subscriptions: {config.get('subscriptions', [])}")
        typer.echo(f"Watching: {config.get('comm_filter', [])}")
        typer.echo(f"Behaviors ({len(config.get('behaviors', []))}):")
        for i, b in enumerate(config.get("behaviors", []), 1):
            typer.echo(f"  {i}. {b}")

        await nc.close()

    asyncio.run(_list())


@app.command()
def rm(description: str = typer.Argument(help="Behavior text to remove (partial match)")):
    """Remove a behavior."""

    async def _rm():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        try:
            entry = await kv.get("veronica")
            config = msgspec.json.decode(entry.value, type=dict)
        except Exception:
            typer.echo("No behaviors configured.")
            await nc.close()
            return

        behaviors = config.get("behaviors", [])
        matches = [b for b in behaviors if description.lower() in b.lower()]

        if not matches:
            typer.echo(f"No behavior matching '{description}'")
            await nc.close()
            return

        for m in matches:
            behaviors.remove(m)
            typer.echo(f"Removed: {m}")

        config["behaviors"] = behaviors

        if behaviors:
            events, comms = await _resolve_subscriptions(behaviors)
            config["subscriptions"] = events
            config["comm_filter"] = comms
        else:
            config["subscriptions"] = []
            config["comm_filter"] = []

        await kv.put("veronica", msgspec.json.encode(config))
        await nc.close()

        typer.echo(f"  Subscriptions: {config['subscriptions']}")
        typer.echo(f"  Watching: {config.get('comm_filter', [])}")
        typer.echo(f"  Remaining behaviors: {len(behaviors)}")

    asyncio.run(_rm())
