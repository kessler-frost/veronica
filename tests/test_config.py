"""tests/test_config.py"""

from pathlib import Path

from veronica.config import VeronicaConfig


def test_defaults():
    cfg = VeronicaConfig()
    assert cfg.nats_url == "nats://localhost:4222"
    assert cfg.vm_name == "veronica"
    assert cfg.opencode_port == 4096
    assert cfg.mcp_port == 4097
    assert cfg.veronica_dir == Path.home() / ".veronica"


def test_opencode_url():
    cfg = VeronicaConfig()
    assert cfg.opencode_url == "http://localhost:4096"
