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

MAIN_AGENT_PROMPT = """You are the Veronica orchestrator. You spawn and manage OpenCode subagents that handle eBPF kernel events.

IMPORTANT: Do NOT run veronica CLI commands. You manage subagents by writing markdown files and using @mentions.

When asked to add a behavior, do exactly this:
1. Pick a short kebab-case name (e.g. "scaffolder", "perm-guard")
2. Decide which eBPF events it needs: process_exec, process_exit, file_open, net_connect
3. Decide which command names (comms) trigger it — be strict, only exact process names
4. Write a file at .opencode/agents/<name>.md with this format:

---
description: <one line description>
mode: subagent
---

<system prompt for the subagent explaining what it should do when it receives events>

5. After writing the file, invoke the subagent with: @<name> "You are now active. Wait for events."

When asked to remove a behavior, delete the .opencode/agents/<name>.md file.

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
    return {"behaviors": [], "subagents": {}}





def _parse_veronica_config(messages: list) -> dict | None:
    """Extract VERONICA_CONFIG JSON from OpenCode message history."""
    for msg in messages:
        for part in msg.get("parts", []):
            text = part.get("text", "")
            if "VERONICA_CONFIG:" in text:
                for line in text.split("\n"):
                    line = line.strip()
                    if line.startswith("VERONICA_CONFIG:"):
                        payload = line[len("VERONICA_CONFIG:"):]
                        return json.loads(payload)
    return None


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
    """Create ~/.veronica/.opencode/ with MCP config and agents dir."""
    oc_dir = cfg.opencode_config_dir
    agents_dir = oc_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)

    # opencode.json — MCP config only (auth handled by OpenCode's auth system)
    oc_config = {
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

    # Start OpenCode headless from ~/.veronica
    typer.echo("Starting OpenCode server...")
    oc_proc = subprocess.Popen(
        ["opencode", "serve", "--port", str(cfg.opencode_port)],
        cwd=str(cfg.veronica_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(3)  # Wait for OpenCode server to start

    async def _run():
        client = OpenCodeClient(base_url=cfg.opencode_url)
        data = _load_behaviors()

        # Create watcher early so MCP subscribe_events tool can update routing
        watcher = EventWatcher(
            nats_url=cfg.nats_url, opencode=client,
            provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
        )
        watcher.set_routing(data.get("subagents", {}))
        set_watcher(watcher, cfg.behaviors_file)

        # For each behavior that doesn't have a subagent session yet, create one
        for behavior in data.get("behaviors", []):
            # Check if we already have a subagent for this behavior
            matching = [
                name for name, sa in data.get("subagents", {}).items()
                if sa.get("behavior") == behavior
            ]
            if matching:
                typer.echo(f"Subagent already exists: {matching[0]}")
                continue

            # Snapshot existing agent files
            agents_dir = cfg.opencode_config_dir / "agents"
            agents_dir.mkdir(parents=True, exist_ok=True)
            existing_agents = {f.stem for f in agents_dir.glob("*.md")}

            # Use creator session to write the .md file
            typer.echo(f"Creating agent for: {behavior}")
            creator_session = await client.create_session()
            await client.send_message_and_wait(
                creator_session["id"],
                f"{MAIN_AGENT_PROMPT}\n\nCreate a subagent for this behavior: {behavior}",
                provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
            )

            # Find the new .md file the creator wrote
            new_agents = {f.stem for f in agents_dir.glob("*.md")} - existing_agents
            if new_agents:
                name = new_agents.pop()
                subagent_session = await client.create_session()
                config = {
                    "name": name,
                    "session_id": subagent_session["id"],
                    "behavior": behavior,
                    "subscriptions": [],
                    "comm_filter": [],
                }
                data.setdefault("subagents", {})[name] = config
                _save_behaviors(data)
                typer.echo(f"  Agent: {name} → session {subagent_session['id']}")

                # Tell the subagent to discover and subscribe to events
                typer.echo(f"  Asking {name} to subscribe...")
                await client.send_message(
                    subagent_session["id"],
                    "You are now active. First, call list_subscriptions to see all available eBPF event types and filtering options. "
                    "Then call subscribe with your agent name and the event types + comm filters relevant to your behavior. "
                    f"Your agent name is: {name}",
                    agent=name,
                    provider_id=cfg.opencode_provider, model_id=cfg.opencode_model,
                )
            else:
                typer.echo(f"  WARNING: No agent file created for: {behavior}")

        # Start event watcher (already created above, routing may have been updated by subscribe_events)
        await watcher.start()

        typer.echo(f"Veronica running with {len(data.get('subagents', {}))} subagents (Ctrl+C to stop)...")
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
    typer.echo(f"Added: {description} (will create agent on next `veronica start`)")


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

    # Remove associated subagents and their .md files
    subagents = data.get("subagents", {})
    for name, sa in list(subagents.items()):
        if sa.get("behavior") in matches:
            agent_file = cfg.opencode_config_dir / "agents" / f"{name}.md"
            if agent_file.exists():
                agent_file.unlink()
            del subagents[name]
            typer.echo(f"  Deleted subagent: {name}")

    data["behaviors"] = behaviors
    _save_behaviors(data)
