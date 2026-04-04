"""tests/test_config.py"""

from veronica.config import VeronicaConfig


def test_defaults():
    cfg = VeronicaConfig()
    assert cfg.nats_url == "nats://localhost:4222"
    assert cfg.vm_name == "veronica"
    assert cfg.llm_base_url == "http://localhost:1234"
    assert cfg.llm_max_turns == 10
