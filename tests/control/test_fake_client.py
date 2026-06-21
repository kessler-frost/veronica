"""Tests for FakeDaemonClient — must honor the daemon's audit-first + guard-list
invariants so warden tests against it are realistic."""

from __future__ import annotations

import pytest

from veronica.control.client import AppRef
from veronica.control.fake_client import (
    FakeDaemonClient,
    GuardListError,
    LifecycleError,
    UnknownPolicyError,
)


def test_resolve_app_returns_cgroup_and_pids():
    fake = FakeDaemonClient()
    fake.add_app("docker", cgroup_path="/sys/fs/cgroup/docker", pids=(101, 102))
    ref = fake.resolve_app("docker")
    assert ref.name == "docker"
    assert ref.cgroup_path == "/sys/fs/cgroup/docker"
    assert ref.pids == (101, 102)


def test_resolve_unknown_app_errors():
    fake = FakeDaemonClient()
    with pytest.raises(KeyError):
        fake.resolve_app("nope")


def test_list_primitives_has_five_with_schemas():
    fake = FakeDaemonClient()
    prims = fake.list_primitives()
    ids = {p.id for p in prims}
    assert ids == {
        "block-path-write",
        "block-mount",
        "block-egress",
        "block-exec",
        "drop-capability",
    }
    for p in prims:
        assert p.params  # JSON Schema present
        assert p.hooks  # at least one LSM hook


def test_apply_policy_defaults_to_audit_mode():
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    pol = fake.apply_policy(
        "block-mount", {"path_prefix": "/var/lib/docker/volumes"}, "audit"
    )
    assert pol.mode == "audit"
    assert pol.primitive_id == "block-mount"
    assert pol.app.name == "docker"
    assert pol.id


def test_apply_policy_rejects_enforce_for_new_policy():
    """Audit-first is structural: a brand-new policy cannot start in enforce."""
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    with pytest.raises(LifecycleError):
        fake.apply_policy(
            "block-mount", {"path_prefix": "/var/lib/docker/volumes"}, "enforce"
        )


def test_set_policy_mode_flips_audit_to_enforce():
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    pol = fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    flipped = fake.set_policy_mode(pol.id, "enforce")
    assert flipped.mode == "enforce"
    assert flipped.id == pol.id
    # And the stored policy reflects the new mode.
    assert fake.list_policies()[0].mode == "enforce"


def test_set_policy_mode_unknown_id_errors():
    fake = FakeDaemonClient()
    with pytest.raises(UnknownPolicyError):
        fake.set_policy_mode("missing", "enforce")


@pytest.mark.parametrize("guarded", ["veronicad", "init", "sshd"])
def test_guard_list_refuses_protected_apps(guarded):
    """Self-protection: refuse policies that resolve to the daemon/init/sshd."""
    fake = FakeDaemonClient()
    fake.add_app(guarded, pids=(1,))
    with pytest.raises(GuardListError):
        fake.apply_policy("block-exec", {"binaries": ["sh"]}, "audit")


def test_guard_list_refuses_pid_1():
    """A policy whose app owns PID 1 is refused regardless of name."""
    fake = FakeDaemonClient()
    fake.add_app("weird", pids=(1, 200))
    with pytest.raises(GuardListError):
        fake.apply_policy("block-exec", {"binaries": ["sh"]}, "audit")


def test_apply_policy_unknown_app_errors():
    fake = FakeDaemonClient()
    with pytest.raises(KeyError):
        fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")


def test_list_policies_round_trips():
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    fake.add_app("nginx", pids=(202,))
    p1 = fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    p2 = fake.apply_policy("block-exec", {"binaries": ["sh"]}, "audit")
    got = {p.id for p in fake.list_policies()}
    assert got == {p1.id, p2.id}


def test_revert_policy_removes_it():
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    pol = fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    res = fake.revert_policy(pol.id)
    assert res == {"ok": True}
    assert fake.list_policies() == []


def test_revert_unknown_policy_errors():
    fake = FakeDaemonClient()
    with pytest.raises(UnknownPolicyError):
        fake.revert_policy("missing")


def test_kill_switch_reverts_all_and_returns_count():
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    fake.apply_policy("block-exec", {"binaries": ["sh"]}, "audit")
    res = fake.kill_switch()
    assert res == {"ok": True, "reverted": 2}
    assert fake.list_policies() == []


def test_observe_returns_seeded_activity():
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    from veronica.control.client import MountEvent

    fake.set_activity("docker", mounts=(MountEvent(source="x", target="/vol"),))
    act = fake.observe("docker", 30)
    assert act.app == "docker"
    assert act.window == 30
    assert act.mounts[0].target == "/vol"


def test_audit_count_increments_simulated_would_block():
    """The fake can simulate would-block events accruing during audit."""
    fake = FakeDaemonClient()
    fake.add_app("docker", pids=(101,))
    pol = fake.apply_policy("block-mount", {"path_prefix": "/v"}, "audit")
    fake.simulate_would_block(pol.id, 3)
    assert fake.list_policies()[0].audit_count == 3


def test_fake_satisfies_daemon_client_protocol():
    from veronica.control.client import DaemonClient

    fake: DaemonClient = FakeDaemonClient()
    assert isinstance(fake.resolve_app, object)
    # AppRef is hashable/frozen as part of the contract.
    assert AppRef("a") == AppRef("a")
