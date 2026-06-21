"""AgentfieldDaemonClient — the production DaemonClient.

Adapts the daemon's eight Agentfield functions (registered in Phase 3) to the
synchronous `DaemonClient` contract by driving the async `app.call(...)` and
deserializing the JSON responses into the contract dataclasses. Tests inject a
FakeDaemonClient instead, so this is not exercised on the host CI path.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agentfield import Agent

from veronica.control.client import (
    Activity,
    AppRef,
    ExecEvent,
    FileEvent,
    Mode,
    MountEvent,
    NetEvent,
    Policy,
    Primitive,
)


class AgentfieldDaemonClient:
    def __init__(self, agentfield_url: str, node_id: str = "veronicad") -> None:
        self.app = Agent(node_id="veronica-warden", agentfield_server=agentfield_url)
        self.node = node_id

    def resolve_app(self, name: str) -> AppRef:
        return _app_ref(self._call("resolve_app", name=name))

    def observe(self, app: str, window_secs: int) -> Activity:
        return _activity(self._call("observe", app=app, window_secs=window_secs))

    def list_primitives(self) -> list[Primitive]:
        return [_primitive(p) for p in self._call("list_primitives")]

    def apply_policy(
        self, primitive_id: str, params: dict[str, Any], mode: Mode
    ) -> Policy:
        return _policy(
            self._call(
                "apply_policy", primitive_id=primitive_id, params=params, mode=mode
            )
        )

    def set_policy_mode(self, policy_id: str, mode: Mode) -> Policy:
        return _policy(self._call("set_policy_mode", policy_id=policy_id, mode=mode))

    def list_policies(self) -> list[Policy]:
        return [_policy(p) for p in self._call("list_policies")]

    def revert_policy(self, policy_id: str) -> dict[str, Any]:
        return self._call("revert_policy", policy_id=policy_id)

    def kill_switch(self) -> dict[str, Any]:
        return self._call("kill_switch")

    def _call(self, fn: str, **kwargs: Any) -> Any:
        return asyncio.run(self.app.call(f"{self.node}.{fn}", **kwargs))


def _app_ref(d: dict[str, Any]) -> AppRef:
    return AppRef(
        name=d["name"],
        cgroup_path=d.get("cgroup_path", ""),
        pids=tuple(d.get("pids", ())),
    )


def _primitive(d: dict[str, Any]) -> Primitive:
    return Primitive(
        id=d["id"],
        desc=d.get("desc", ""),
        params=d["params"],
        hooks=tuple(d.get("hooks", ())),
    )


def _policy(d: dict[str, Any]) -> Policy:
    return Policy(
        id=d["id"],
        primitive_id=d["primitive_id"],
        params=d.get("params", {}),
        mode=d["mode"],
        app=_app_ref(d["app"]),
        audit_count=d.get("audit_count", 0),
    )


def _activity(d: dict[str, Any]) -> Activity:
    return Activity(
        app=d["app"],
        window=d.get("window", 0),
        files=tuple(FileEvent(**e) for e in d.get("files", ())),
        net=tuple(NetEvent(**e) for e in d.get("net", ())),
        execs=tuple(ExecEvent(**e) for e in d.get("execs", ())),
        mounts=tuple(MountEvent(**e) for e in d.get("mounts", ())),
    )
