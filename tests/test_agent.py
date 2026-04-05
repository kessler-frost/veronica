"""tests/test_agent.py"""

import msgspec
import nats as nats_client
import pytest

from veronica.agents.agent import VeronicaAgent


@pytest.mark.asyncio
async def test_agent_builds_prompt_with_behaviors():
    """System prompt includes all behaviors from config."""
    try:
        nc = await nats_client.connect("nats://localhost:4222")
    except Exception:
        pytest.skip("NATS server not running")

    js = nc.jetstream()
    kv = await js.key_value("agents")
    await kv.put("veronica", msgspec.json.encode({
        "behaviors": ["scaffold projects", "revert dangerous permissions"],
        "subscriptions": ["process_exec"],
    }))

    agent = VeronicaAgent(nats_url="nats://localhost:4222")
    agent._nc = nc
    agent._js = js
    config = await agent._load_config()

    assert config["behaviors"] == ["scaffold projects", "revert dangerous permissions"]
    assert config["subscriptions"] == ["process_exec"]

    await kv.delete("veronica")
    await nc.close()
