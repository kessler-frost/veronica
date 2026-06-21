"""tests/test_config.py"""

from pathlib import Path

import pytest

from veronica.config import VeronicaConfig


def test_defaults():
    cfg = VeronicaConfig()
    assert cfg.agentfield_url == "http://localhost:8090"
    assert cfg.llm_url == "http://localhost:1234"
    assert cfg.vm_name == "veronica"
    assert cfg.veronica_dir == Path.home() / ".veronica"


def test_llm_api_key_defaults_to_none():
    cfg = VeronicaConfig()
    assert cfg.llm_api_key is None


def test_behaviors_file():
    cfg = VeronicaConfig()
    assert cfg.behaviors_file == Path.home() / ".veronica" / "behaviors.json"


def test_env_override_simple(monkeypatch):
    monkeypatch.setenv("VERONICA_VM_NAME", "test-vm")
    monkeypatch.setenv("VERONICA_AGENTFIELD_URL", "http://example.com:9000")
    cfg = VeronicaConfig()
    assert cfg.vm_name == "test-vm"
    assert cfg.agentfield_url == "http://example.com:9000"


def test_env_override_api_key(monkeypatch):
    monkeypatch.setenv("VERONICA_LLM_API_KEY", "secret-key")
    cfg = VeronicaConfig()
    assert cfg.llm_api_key == "secret-key"


def test_env_override_home_dir_propagates_to_derived_paths(monkeypatch, tmp_path):
    monkeypatch.setenv("VERONICA_HOME_DIR", str(tmp_path))
    cfg = VeronicaConfig()
    assert cfg.home_dir == tmp_path
    assert cfg.veronica_dir == tmp_path / ".veronica"
    assert cfg.behaviors_file == tmp_path / ".veronica" / "behaviors.json"


@pytest.mark.parametrize("field", ["agentfield_url", "llm_url", "llm_model", "vm_name"])
def test_string_fields_are_str(field):
    cfg = VeronicaConfig()
    assert isinstance(getattr(cfg, field), str)


def test_home_dir_is_path():
    cfg = VeronicaConfig()
    assert isinstance(cfg.home_dir, Path)
