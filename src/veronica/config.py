"""Veronica configuration."""

from agno.models.lmstudio import LMStudio
from agno.models.openrouter import OpenRouter
from pydantic_settings import BaseSettings

PROVIDERS = {
    "openrouter": lambda cfg: OpenRouter(id=cfg.openrouter_model, temperature=0.0),
    "lmstudio": lambda cfg: LMStudio(id=cfg.llm_model, base_url=cfg.llm_base_url, temperature=0.0),
}


class VeronicaConfig(BaseSettings):
    model_config = {"env_prefix": "VERONICA_", "env_nested_delimiter": "__"}

    nats_url: str = "nats://localhost:4222"
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_pkg: str = "./cmd/veronicad/"
    daemon_install_path: str = "/usr/local/bin/veronicad"
    vm_project_path: str = "/home/fimbulwinter.linux/veronica"
    llm_provider: str = "openrouter"  # "lmstudio" or "openrouter"
    llm_base_url: str = "http://localhost:1234/v1"
    llm_model: str = "mlx-qwen3.5-35b-a3b-claude-4.6-opus-reasoning-distilled"
    openrouter_model: str = "inception/mercury-2"
    max_concurrent_agents: int = 1

    def build_model(self):
        return PROVIDERS[self.llm_provider](self)
