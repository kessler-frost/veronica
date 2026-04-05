"""Veronica configuration."""

from pathlib import Path

from pydantic_settings import BaseSettings


class VeronicaConfig(BaseSettings):
    model_config = {"env_prefix": "VERONICA_", "env_nested_delimiter": "__"}

    nats_url: str = "nats://localhost:4222"
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_pkg: str = "./cmd/veronicad/"
    daemon_install_path: str = "/usr/local/bin/veronicad"
    vm_project_path: str = "/home/fimbulwinter.linux/veronica"
    opencode_port: int = 4096
    mcp_port: int = 4097
    opencode_provider: str = "openrouter"
    opencode_model: str = "openai/gpt-5.4-nano"
    home_dir: Path = Path.home()

    @property
    def veronica_dir(self) -> Path:
        return self.home_dir / ".veronica"

    @property
    def opencode_url(self) -> str:
        return f"http://localhost:{self.opencode_port}"

    @property
    def opencode_config_dir(self) -> Path:
        return self.veronica_dir / ".opencode"

    @property
    def behaviors_file(self) -> Path:
        return self.veronica_dir / "behaviors.json"
