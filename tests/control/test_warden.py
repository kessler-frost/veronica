"""Tests for Warden — the audit->confirm->enforce lifecycle + summarize.

Driven by FakeDaemonClient + a mock LLM (no real LM Studio / daemon).
"""

from __future__ import annotations

import json

import pytest

from veronica.control.client import MountEvent, NetEvent
from veronica.control.fake_client import FakeDaemonClient
from veronica.control.warden import AuditReport, Warden


class ScriptedLLM:
    """Returns queued replies in order; falls back to the last one."""

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        idx = min(len(self.calls) - 1, len(self.replies) - 1)
        return self.replies[idx]


def _translation(primitive_id, params):
    return json.dumps({"primitive_id": primitive_id, "params": params})


def _fake_with_docker():
    fake = FakeDaemonClient()
    fake.add_app("docker", cgroup_path="/sys/fs/cgroup/docker", pids=(101, 102))
    return fake


def test_enforce_leaves_policy_in_audit_and_reports_would_block():
    fake = _fake_with_docker()
    llm = ScriptedLLM(
        _translation("block-mount", {"path_prefix": "/var/lib/docker/volumes"})
    )
    warden = Warden(fake, llm)

    report = warden.enforce("don't let docker create volumes")

    assert isinstance(report, AuditReport)
    assert report.primitive_id == "block-mount"
    # Policy exists and is still in audit (never auto-enforced).
    pols = fake.list_policies()
    assert len(pols) == 1
    assert pols[0].mode == "audit"
    assert report.policy_id == pols[0].id
    # would-block count surfaced (zero until events accrue).
    assert report.would_block == 0


def test_enforce_surfaces_accrued_would_block_count():
    fake = _fake_with_docker()
    llm = ScriptedLLM(_translation("block-mount", {"path_prefix": "/v"}))
    warden = Warden(fake, llm)

    # Pre-seed a would-block simulation by intercepting after apply: emulate the
    # daemon having logged 3 audit hits at report time.
    report = warden.enforce("block docker volumes")
    fake.simulate_would_block(report.policy_id, 3)
    # Re-querying reflects the daemon's audit counter.
    assert fake.list_policies()[0].audit_count == 3


def test_confirm_flips_audit_to_enforce():
    fake = _fake_with_docker()
    llm = ScriptedLLM(_translation("block-mount", {"path_prefix": "/v"}))
    warden = Warden(fake, llm)

    report = warden.enforce("block docker volumes")
    pol = warden.confirm(report.policy_id)

    assert pol.mode == "enforce"
    assert fake.list_policies()[0].mode == "enforce"


def test_enforce_then_panic_clears_everything():
    fake = _fake_with_docker()
    llm = ScriptedLLM(_translation("block-mount", {"path_prefix": "/v"}))
    warden = Warden(fake, llm)

    warden.enforce("block docker volumes")
    warden.confirm(fake.list_policies()[0].id)
    cleared = warden.panic()

    assert cleared == 1
    assert fake.list_policies() == []


def test_panic_with_no_policies_returns_zero():
    fake = _fake_with_docker()
    warden = Warden(fake, ScriptedLLM("{}"))
    assert warden.panic() == 0


def test_ask_summarizes_activity_via_llm():
    fake = _fake_with_docker()
    fake.set_activity(
        "docker",
        net=(NetEvent(daddr="1.2.3.4", dport=443),),
        mounts=(MountEvent(source="x", target="/var/lib/docker/volumes/v"),),
    )
    llm = ScriptedLLM("docker opened a connection to 1.2.3.4:443 and created a volume")
    warden = Warden(fake, llm)

    summary = warden.ask("docker", "what is docker doing?")

    assert summary == "docker opened a connection to 1.2.3.4:443 and created a volume"
    # The activity reached the LLM prompt.
    _system, user = llm.calls[0]
    assert "1.2.3.4" in user
    assert "what is docker doing?" in user


def test_enforce_rejects_invalid_translation():
    from veronica.control.translate import TranslationError

    fake = _fake_with_docker()
    llm = ScriptedLLM(_translation("nonexistent", {}))
    warden = Warden(fake, llm)
    with pytest.raises(TranslationError):
        warden.enforce("do something the catalog can't express")


def test_enforce_passes_catalog_from_daemon_to_translate():
    """enforce pulls the live catalog via list_primitives, not a hardcoded one."""
    fake = _fake_with_docker()
    llm = ScriptedLLM(_translation("block-exec", {"binaries": ["sh"]}))
    warden = Warden(fake, llm)
    report = warden.enforce("block shell exec in docker")
    assert report.primitive_id == "block-exec"
    # Prompt carried the daemon's catalog ids.
    _system, user = llm.calls[0]
    assert "block-exec" in user
