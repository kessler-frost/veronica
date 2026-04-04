"""tests/test_config.py"""
from veronica.config import VeronicaConfig

def test_defaults():
    cfg = VeronicaConfig()
    assert cfg.daemon_ws_url == "ws://localhost:9090/ws"
    assert cfg.vm_name == "veronica"
    assert cfg.session_timeout == 60
