"""Tests for the control-plane CLI verbs via typer's CliRunner.

Each verb builds a Warden; we monkeypatch the factory to inject a Warden backed
by a FakeDaemonClient + scripted mock LLM, so nothing touches the real daemon
or LM Studio.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from veronica.cli import main as cli
from veronica.control.client import MountEvent, NetEvent
from veronica.control.fake_client import FakeDaemonClient
from veronica.control.warden import Warden

runner = CliRunner()


class ScriptedLLM:
    def __init__(self, *replies: str) -> None:
        self.replies = list(replies) or ["{}"]
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        idx = min(self.calls, len(self.replies) - 1)
        self.calls += 1
        return self.replies[idx]


def _translation(primitive_id, params):
    return json.dumps({"primitive_id": primitive_id, "params": params})


@pytest.fixture
def inject(monkeypatch):
    """Install a Warden built from a caller-supplied fake + LLM."""

    def _install(fake: FakeDaemonClient, llm: ScriptedLLM) -> Warden:
        warden = Warden(fake, llm)
        monkeypatch.setattr(cli, "_make_warden", lambda: warden)
        return warden

    return _install


def _docker_fake():
    fake = FakeDaemonClient()
    fake.add_app("docker", cgroup_path="/sys/fs/cgroup/docker", pids=(101, 102))
    return fake


def test_enforce_exits_zero_and_prints_summary_and_confirm_hint(inject):
    fake = _docker_fake()
    llm = ScriptedLLM(_translation("block-mount", {"path_prefix": "/var/lib/docker/volumes"}))
    inject(fake, llm)

    result = runner.invoke(cli.app, ["enforce", "don't let docker create volumes"])

    assert result.exit_code == 0, result.output
    assert "block-mount" in result.output
    assert "audit" in result.output.lower()
    # would-block summary + a confirm hint referencing the policy id.
    pol_id = fake.list_policies()[0].id
    assert pol_id in result.output
    assert "confirm" in result.output.lower()
    # Policy is in audit, NOT enforced.
    assert fake.list_policies()[0].mode == "audit"


def test_policies_lists_active_policies(inject):
    fake = _docker_fake()
    fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    inject(fake, ScriptedLLM())

    result = runner.invoke(cli.app, ["policies"])

    assert result.exit_code == 0, result.output
    pol = fake.list_policies()[0]
    assert pol.id in result.output
    assert "block-mount" in result.output
    assert "audit" in result.output


def test_policies_empty_message(inject):
    inject(_docker_fake(), ScriptedLLM())
    result = runner.invoke(cli.app, ["policies"])
    assert result.exit_code == 0
    assert "no policies" in result.output.lower()


def test_audit_confirm_flips_to_enforce(inject):
    fake = _docker_fake()
    pol = fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    inject(fake, ScriptedLLM())

    result = runner.invoke(cli.app, ["audit", pol.id, "--confirm"])

    assert result.exit_code == 0, result.output
    assert fake.list_policies()[0].mode == "enforce"
    assert "enforce" in result.output.lower()


def test_audit_without_confirm_shows_status(inject):
    fake = _docker_fake()
    pol = fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    fake.simulate_would_block(pol.id, 4)
    inject(fake, ScriptedLLM())

    result = runner.invoke(cli.app, ["audit", pol.id])

    assert result.exit_code == 0, result.output
    # Still audit; shows the would-block count.
    assert fake.list_policies()[0].mode == "audit"
    assert "4" in result.output


def test_revert_removes_policy(inject):
    fake = _docker_fake()
    pol = fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    inject(fake, ScriptedLLM())

    result = runner.invoke(cli.app, ["revert", pol.id])

    assert result.exit_code == 0, result.output
    assert fake.list_policies() == []


def test_panic_clears_all_policies(inject):
    fake = _docker_fake()
    fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    fake.apply_policy("block-exec", {"binaries": ["sh"]}, "audit")
    inject(fake, ScriptedLLM())

    result = runner.invoke(cli.app, ["panic"])

    assert result.exit_code == 0, result.output
    assert fake.list_policies() == []
    assert "2" in result.output


def test_watch_prints_activity_summary(inject):
    fake = _docker_fake()
    fake.set_activity(
        "docker",
        net=(NetEvent(daddr="1.2.3.4", dport=443),),
        mounts=(MountEvent(source="x", target="/vol"),),
    )
    inject(fake, ScriptedLLM("docker is talking to 1.2.3.4 and mounting /vol"))

    result = runner.invoke(cli.app, ["watch", "docker"])

    assert result.exit_code == 0, result.output
    assert "1.2.3.4" in result.output


def test_ask_prints_llm_answer(inject):
    fake = _docker_fake()
    fake.set_activity("docker", net=(NetEvent(daddr="9.9.9.9", dport=53),))
    inject(fake, ScriptedLLM("docker made a DNS query to 9.9.9.9"))

    result = runner.invoke(cli.app, ["ask", "docker", "is docker doing dns?"])

    assert result.exit_code == 0, result.output
    assert "9.9.9.9" in result.output


def test_enforce_invalid_translation_exits_nonzero(inject):
    fake = _docker_fake()
    inject(fake, ScriptedLLM(_translation("does-not-exist", {})))

    result = runner.invoke(cli.app, ["enforce", "something impossible"])

    assert result.exit_code != 0
    assert fake.list_policies() == []
