"""DaemonClient — the host-side contract for the Go control-plane daemon.

Mirrors the eight Agentfield functions the daemon registers (see the
kernel-control-plane design's daemon-warden contract). The warden talks to the
daemon only through this Protocol, so tests can drop in a `FakeDaemonClient`.

Types mirror the Go contract (`internal/control/types.go`) one-to-one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol

Mode = Literal["audit", "enforce"]


@dataclass(frozen=True)
class AppRef:
    """A resolved application: its name, cgroup, and live PIDs."""

    name: str
    cgroup_path: str = ""
    pids: tuple[int, ...] = ()


@dataclass(frozen=True)
class Primitive:
    """A vetted enforcement primitive from the daemon's catalog."""

    id: str
    desc: str
    params: dict[str, Any]  # JSON Schema for the params
    hooks: tuple[str, ...]  # LSM hook names


@dataclass(frozen=True)
class Policy:
    """A policy instance: a primitive bound to params, an app, and a mode."""

    id: str
    primitive_id: str
    params: dict[str, Any]
    mode: Mode
    app: AppRef
    audit_count: int = 0


@dataclass(frozen=True)
class FileEvent:
    path: str
    op: str
    count: int = 1


@dataclass(frozen=True)
class NetEvent:
    daddr: str
    dport: int
    count: int = 1


@dataclass(frozen=True)
class ExecEvent:
    comm: str
    filename: str
    count: int = 1


@dataclass(frozen=True)
class MountEvent:
    source: str
    target: str
    count: int = 1


@dataclass(frozen=True)
class Activity:
    """A windowed snapshot of one app's kernel-sourced activity."""

    app: str
    window: int  # seconds
    files: tuple[FileEvent, ...] = ()
    net: tuple[NetEvent, ...] = ()
    execs: tuple[ExecEvent, ...] = ()
    mounts: tuple[MountEvent, ...] = ()


class DaemonClient(Protocol):
    """The eight Agentfield functions the daemon exposes to the warden."""

    def resolve_app(self, name: str) -> AppRef: ...

    def observe(self, app: str, window_secs: int) -> Activity: ...

    def list_primitives(self) -> list[Primitive]: ...

    def apply_policy(
        self, primitive_id: str, params: dict[str, Any], mode: Mode
    ) -> Policy: ...

    def set_policy_mode(self, policy_id: str, mode: Mode) -> Policy: ...

    def list_policies(self) -> list[Policy]: ...

    def revert_policy(self, policy_id: str) -> dict[str, Any]: ...

    def kill_switch(self) -> dict[str, Any]: ...
