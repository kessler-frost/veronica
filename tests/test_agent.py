"""tests/test_agent.py — Tests for agent discovery and EVENT_SCHEMA."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

from veronica.agent import EVENT_SCHEMA, discover_daemon_skills


def test_ppid_in_event_schema():
    """EVENT_SCHEMA['process_exec']['data_fields'] must include 'ppid'."""
    assert "ppid" in EVENT_SCHEMA["process_exec"]["data_fields"]
    assert EVENT_SCHEMA["process_exec"]["data_fields"]["ppid"] == "parent process ID (shell PID for terminal notification)"


def test_discover_daemon_skills():
    """discover_daemon_skills extracts reasoner IDs from the control plane."""

    @dataclass
    class FakeReasoner:
        id: str

    @dataclass
    class FakeCapability:
        reasoners: list

    @dataclass
    class FakeDiscoveryJSON:
        capabilities: list

    @dataclass
    class FakeResult:
        json: FakeDiscoveryJSON

    fake_result = FakeResult(
        json=FakeDiscoveryJSON(
            capabilities=[
                FakeCapability(reasoners=[
                    FakeReasoner(id="subscribe"),
                    FakeReasoner(id="exec"),
                    FakeReasoner(id="notify"),
                ]),
            ]
        )
    )

    app = MagicMock()
    app.client.discover_capabilities.return_value = fake_result

    skills = discover_daemon_skills(app)

    app.client.discover_capabilities.assert_called_once_with(node_id="veronicad", reasoner="*")
    assert skills == ["subscribe", "exec", "notify"]


def test_discover_daemon_skills_empty():
    """discover_daemon_skills returns empty list when no capabilities found."""

    @dataclass
    class FakeResult:
        json: None = None

    app = MagicMock()
    app.client.discover_capabilities.return_value = FakeResult()

    skills = discover_daemon_skills(app)
    assert skills == []
