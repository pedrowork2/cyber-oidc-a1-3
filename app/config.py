"""Configuração lida de variáveis de ambiente (.env). Nenhum segredo fica no código."""
import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "sim"}


def _list(name: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, "").split(",") if v.strip()]


@dataclass
class Config:
    client_id: str = field(default_factory=lambda: os.getenv("GOOGLE_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("GOOGLE_CLIENT_SECRET", ""))
    redirect_uri: str = field(default_factory=lambda: os.getenv("REDIRECT_URI", "https://localhost:8443/callback"))
    discovery_url: str = field(default_factory=lambda: os.getenv(
        "OIDC_DISCOVERY_URL", "https://accounts.google.com/.well-known/openid-configuration"))
    auto_provision: bool = field(default_factory=lambda: _bool("AUTO_PROVISION", True))
    admin_subs: list[str] = field(default_factory=lambda: _list("ADMIN_SUBS"))
    allowed_hd: str = field(default_factory=lambda: os.getenv("ALLOWED_HD", "").strip())
    clock_skew: int = field(default_factory=lambda: int(os.getenv("CLOCK_SKEW_SECONDS", "120")))
    idle_timeout_s: int = field(default_factory=lambda: int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "30")) * 60)
    absolute_timeout_s: int = field(default_factory=lambda: int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_HOURS", "8")) * 3600)
    demo_mode: bool = field(default_factory=lambda: _bool("DEMO_MODE", False))
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_PER_MINUTE", "10")))
    database_path: str = field(default_factory=lambda: os.getenv("DATABASE_PATH", "app.db"))
    # Timeout das chamadas HTTP ao provedor (4.6): (conexão, leitura)
    http_timeout: tuple = (5, 10)
    # Discovery do Google publica "https://accounts.google.com"; o Google documenta
    # que o iss também pode vir como "accounts.google.com" (enunciado, seção 3).
    extra_issuers: list[str] = field(default_factory=lambda: ["accounts.google.com"])
