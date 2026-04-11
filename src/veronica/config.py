"""Veronica configuration."""

from pathlib import Path

from pydantic_settings import BaseSettings


class VeronicaConfig(BaseSettings):
    model_config = {"env_prefix": "VERONICA_", "env_nested_delimiter": "__"}

    agentfield_url: str = "http://localhost:8090"
    lm_studio_url: str = "http://localhost:1234"
    lm_studio_model: str = "mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled"
    lm_api_key: str | None = None
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_pkg: str = "./cmd/veronicad/"
    daemon_install_path: str = "/usr/local/bin/veronicad"
    vm_project_path: str = "/home/fimbulwinter.linux/veronica"
    home_dir: Path = Path.home()

    @property
    def veronica_dir(self) -> Path:
        return self.home_dir / ".veronica"

    @property
    def behaviors_file(self) -> Path:
        return self.veronica_dir / "behaviors.json"
