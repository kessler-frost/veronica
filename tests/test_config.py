"""tests/test_config.py"""

from pathlib import Path

from veronica.config import VeronicaConfig


def test_defaults():
    cfg = VeronicaConfig()
    assert cfg.agentfield_url == "http://localhost:8090"
    assert cfg.lm_studio_url == "http://localhost:1234"
    assert cfg.vm_name == "veronica"
    assert cfg.veronica_dir == Path.home() / ".veronica"


def test_lm_api_key_defaults_to_none():
    cfg = VeronicaConfig()
    assert cfg.lm_api_key is None


def test_behaviors_file():
    cfg = VeronicaConfig()
    assert cfg.behaviors_file == Path.home() / ".veronica" / "behaviors.json"
