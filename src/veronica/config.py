"""Veronica configuration."""

from pydantic_settings import BaseSettings


class VeronicaConfig(BaseSettings):
    model_config = {"env_prefix": "VERONICA_", "env_nested_delimiter": "__"}

    nats_url: str = "nats://localhost:4222"
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_build_path: str = "/tmp/veronica"
    daemon_pkg: str = "./cmd/veronicad/"
    daemon_install_path: str = "/usr/local/bin/veronicad"
    project_path: str = "/Users/fimbulwinter/dev/veronica"
    llm_base_url: str = "http://localhost:1234"
    llm_model: str = ""
