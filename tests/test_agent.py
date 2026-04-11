"""tests/test_agent.py — Tests for DAEMON_SKILLS and EVENT_SCHEMA in agent.py."""

from pathlib import Path

from veronica.agent import DAEMON_SKILLS, EVENT_SCHEMA, create_behavior_agent


def test_notify_in_daemon_skills():
    """'notify' must be present in the DAEMON_SKILLS list."""
    assert "notify" in DAEMON_SKILLS


def test_daemon_skills_ordering():
    """'notify' must come after 'measure' and before 'map_read' in DAEMON_SKILLS."""
    measure_idx = DAEMON_SKILLS.index("measure")
    notify_idx = DAEMON_SKILLS.index("notify")
    map_read_idx = DAEMON_SKILLS.index("map_read")
    assert measure_idx < notify_idx < map_read_idx, (
        f"Expected measure ({measure_idx}) < notify ({notify_idx}) < map_read ({map_read_idx})"
    )


def test_ppid_in_event_schema():
    """EVENT_SCHEMA['process_exec']['data_fields'] must include 'ppid'."""
    assert "ppid" in EVENT_SCHEMA["process_exec"]["data_fields"]
    assert EVENT_SCHEMA["process_exec"]["data_fields"]["ppid"] == "parent process ID (shell PID for terminal notification)"


def test_notify_in_system_prompt():
    """The system prompt built by create_behavior_agent must contain 'notify'."""
    agent = create_behavior_agent(
        agent_id="test",
        behavior="test behavior",
        agentfield_url="http://localhost:8090",
        lm_studio_url="http://localhost:1234",
        lm_studio_model="test-model",
        behaviors_file=Path("/dev/null"),
    )
    # The system prompt is built from DAEMON_SKILLS via ', '.join(DAEMON_SKILLS)
    skills_str = ", ".join(DAEMON_SKILLS)
    assert "notify" in skills_str
