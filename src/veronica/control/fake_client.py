"""FakeDaemonClient — an in-memory DaemonClient for warden/CLI tests.

It honors the SAME invariants the Go daemon enforces (Task 2 lifecycle):
  * audit-first: `apply_policy` only accepts ``mode="audit"``; the only path to
    enforce is `set_policy_mode(id, "enforce")`.
  * guard list: refuse any policy whose app is the daemon, init/PID 1, or sshd.
  * params validated against the primitive's JSON Schema (catalog-bounded).
  * kill_switch reverts every policy and reports the count.

Tests drive it via the `add_app` / `set_activity` / `simulate_would_block`
seeding helpers, none of which exist on the real daemon.
"""

from __future__ import annotations

import itertools
from dataclasses import replace
from typing import Any

import jsonschema

from veronica.control.catalog import PRIMITIVES, PRIMITIVES_BY_ID
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

GUARDED_NAMES = frozenset({"veronicad", "init", "sshd"})
GUARDED_PIDS = frozenset({1})


class GuardListError(Exception):
    """Raised when a policy would target a self-protected app."""


class LifecycleError(Exception):
    """Raised when audit-first is violated (e.g. applying directly in enforce)."""


class UnknownPolicyError(KeyError):
    """Raised when a policy id is not found."""


class ParamValidationError(Exception):
    """Raised when params fail the primitive's JSON Schema (or id is unknown)."""


class FakeDaemonClient:
    def __init__(self) -> None:
        self._apps: dict[str, AppRef] = {}
        self._activity: dict[str, Activity] = {}
        self._policies: dict[str, Policy] = {}
        self._ids = (f"pol-{n}" for n in itertools.count(1))

    # --- test seeding helpers (not part of the DaemonClient contract) ---

    def add_app(
        self, name: str, cgroup_path: str = "", pids: tuple[int, ...] = ()
    ) -> AppRef:
        ref = AppRef(name=name, cgroup_path=cgroup_path, pids=tuple(pids))
        self._apps[name] = ref
        return ref

    def set_activity(
        self,
        app: str,
        files: tuple[FileEvent, ...] = (),
        net: tuple[NetEvent, ...] = (),
        execs: tuple[ExecEvent, ...] = (),
        mounts: tuple[MountEvent, ...] = (),
    ) -> None:
        self._activity[app] = Activity(
            app=app, window=0, files=files, net=net, execs=execs, mounts=mounts
        )

    def simulate_would_block(self, policy_id: str, count: int) -> None:
        pol = self._require_policy(policy_id)
        self._policies[policy_id] = replace(pol, audit_count=pol.audit_count + count)

    # --- DaemonClient contract ---

    def resolve_app(self, name: str) -> AppRef:
        return self._apps[name]

    def observe(self, app: str, window_secs: int) -> Activity:
        seeded = self._activity.get(app, Activity(app=app, window=0))
        return replace(seeded, window=window_secs)

    def list_primitives(self) -> list[Primitive]:
        return list(PRIMITIVES)

    def apply_policy(
        self, primitive_id: str, params: dict[str, Any], mode: Mode
    ) -> Policy:
        if mode != "audit":
            raise LifecycleError(
                "new policies must start in audit; use set_policy_mode to enforce"
            )
        self._validate(primitive_id, params)
        app = self._target_app()
        _guard(app)
        pol = Policy(
            id=next(self._ids),
            primitive_id=primitive_id,
            params=params,
            mode="audit",
            app=app,
        )
        self._policies[pol.id] = pol
        return pol

    def set_policy_mode(self, policy_id: str, mode: Mode) -> Policy:
        pol = replace(self._require_policy(policy_id), mode=mode)
        self._policies[policy_id] = pol
        return pol

    def list_policies(self) -> list[Policy]:
        return list(self._policies.values())

    def revert_policy(self, policy_id: str) -> dict[str, Any]:
        self._require_policy(policy_id)
        del self._policies[policy_id]
        return {"ok": True}

    def kill_switch(self) -> dict[str, Any]:
        count = len(self._policies)
        self._policies.clear()
        return {"ok": True, "reverted": count}

    # --- internals ---

    def _validate(self, primitive_id: str, params: dict[str, Any]) -> None:
        prim = PRIMITIVES_BY_ID.get(primitive_id)
        if prim is None:
            raise ParamValidationError(f"unknown primitive id: {primitive_id}")
        jsonschema.validate(params, prim.params)

    def _require_policy(self, policy_id: str) -> Policy:
        pol = self._policies.get(policy_id)
        if pol is None:
            raise UnknownPolicyError(policy_id)
        return pol

    def _target_app(self) -> AppRef:
        """The real daemon resolves the watched app itself; tests seed exactly
        one app, so the fake binds new policies to that sole target."""
        if not self._apps:
            raise KeyError("no app resolved; call add_app(...) first")
        return next(iter(self._apps.values()))


def _guard(app: AppRef) -> None:
    if app.name in GUARDED_NAMES or GUARDED_PIDS & set(app.pids):
        raise GuardListError(f"refusing to target protected app: {app.name}")
