"""Veronica configuration. No env var overrides for now."""

from pydantic_settings import BaseSettings


class VeronicaConfig(BaseSettings):
    model_config = {"env_prefix": "VERONICA_", "env_nested_delimiter": "__"}

    daemon_ws_url: str = "ws://localhost:9090/ws"
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_build_path: str = "/tmp/veronica"
    daemon_pkg: str = "./cmd/veronicad/"
    daemon_install_path: str = "/usr/local/bin/veronicad"
    session_timeout: int = 60
    project_path: str = "/Users/fimbulwinter/dev/veronica"
