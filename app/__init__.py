"""Fábrica da aplicação Flask (Cliente / Relying Party)."""
from __future__ import annotations

import logging
import os
import re
from logging.handlers import RotatingFileHandler

from flask import Flask, g, render_template

from .config import Config
from .db import Database
from .oidc import GoogleProvider
from .security import RateLimiter, SessionManager


class RedactSecretsFilter(logging.Filter):
    """O log de acesso do Werkzeug grava a URL completa; o code e o state do
    callback não devem ir para o log (mesmo sendo de uso único)."""
    PATTERN = re.compile(r"\b(code|state|code_verifier|access_token|id_token)=[^&\s\"]+")

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        redacted = self.PATTERN.sub(r"\1=[REDACTED]", msg)
        if redacted != msg:
            record.msg, record.args = redacted, None
        return True


def _setup_logging(log_dir: str = "logs") -> None:
    logging.getLogger("werkzeug").addFilter(RedactSecretsFilter())
    root = logging.getLogger()
    if any(getattr(h, "_oidc", False) for h in root.handlers):
        return
    os.makedirs(log_dir, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = RotatingFileHandler(os.path.join(log_dir, "app.log"), maxBytes=2_000_000,
                             backupCount=3, encoding="utf-8")
    sh = logging.StreamHandler()
    for h in (fh, sh):
        h.setFormatter(fmt)
        h._oidc = True
        root.addHandler(h)
    root.setLevel(logging.INFO)


ERROR_MESSAGES = {
    400: ("Requisição inválida", "A requisição não pôde ser processada."),
    401: ("Não autenticado", "Você precisa entrar para acessar esta página."),
    403: ("Acesso negado", "Seu perfil não tem permissão para acessar esta área."),
    404: ("Não encontrado", "A página solicitada não existe."),
    405: ("Método não permitido", "Use o método correto para esta rota."),
    429: ("Muitas tentativas", "Muitas tentativas em pouco tempo. Aguarde um minuto e tente de novo."),
    500: ("Erro interno", "Ocorreu um erro inesperado."),
}


def create_app(config: Config | None = None, provider=None, setup_logging: bool = True) -> Flask:
    config = config or Config()
    if setup_logging:
        _setup_logging()

    app = Flask(__name__)
    app.json.ensure_ascii = False  # acentos legíveis nos quadros JSON das demos
    # A sessão do Flask (cookie assinado) NÃO é usada; usamos sessão server-side própria.
    app.config.update(SECRET_KEY=os.urandom(32), SESSION_COOKIE_SECURE=True)

    db = Database(config.database_path)
    sessions = SessionManager(db, config)
    app.extensions.update(
        config=config,
        db=db,
        sessions=sessions,
        provider=provider or GoogleProvider(config),
        rate_limiter=RateLimiter(config.rate_limit_per_minute, 60),
    )

    @app.before_request
    def load_session():
        sessions.load()
        g.user = None
        if g.session_user_id is not None:
            # Role relido do banco a cada requisição (4.2, passo 12)
            g.user = db.get_user(g.session_user_id)
            if g.user is None:
                sessions.destroy()

    @app.after_request
    def security_headers(resp):
        sessions.apply_cookie(resp)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        # no-referrer: o code/state do callback não vaza para terceiros via Referer
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' https://*.googleusercontent.com; "
            "style-src 'self'; script-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'none'")
        return resp

    for code, (title, message) in ERROR_MESSAGES.items():
        def handler(err, code=code, title=title, message=message):
            return render_template("erro.html", title=title, message=message, code=code), code
        app.register_error_handler(code, handler)

    @app.context_processor
    def inject():
        return {"user": g.get("user"), "csrf_token": g.get("session_data", {}).get("csrf", ""),
                "demo_mode": config.demo_mode}

    from .routes import bp
    app.register_blueprint(bp)
    return app
