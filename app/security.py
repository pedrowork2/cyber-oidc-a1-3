"""Sessão local server-side (4.4), rate limiting e decoradores de autorização (4.5)."""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, g, request

from .oidc import random_token

# Prefixo __Host-: o navegador só aceita o cookie se Secure, Path=/ e sem Domain,
# o que impede que um subdomínio sobrescreva o cookie de sessão.
SESSION_COOKIE = "__Host-sid"
LOGIN_TX_TTL = 600  # transação de login (state/nonce/verifier) vale 10 min


class SessionManager:
    def __init__(self, db, config):
        self.db = db
        self.config = config

    # Chamado em before_request
    def load(self) -> None:
        g.sid, g.session_data, g.session_user_id = None, {}, None
        g.new_sid, g.clear_cookie = None, False
        sid = request.cookies.get(SESSION_COOKIE)
        if not sid:
            return
        row = self.db.get_session(sid)
        if row is None:
            g.clear_cookie = True
            return
        now = time.time()
        if now > row["absolute_expiry"] or now - row["last_seen"] > self.config.idle_timeout_s:
            self.db.delete_session(sid)
            self.db.audit("sessao_expirada", f"user_id={row['user_id']}")
            g.clear_cookie = True
            return
        self.db.update_session(sid)  # renova o relógio de inatividade
        g.sid, g.session_data, g.session_user_id = sid, json.loads(row["data"]), row["user_id"]

    def create(self, user_id: int | None, data: dict, ttl: int) -> str:
        """Cria SEMPRE um identificador novo (rotação no login)."""
        if g.get("sid"):
            self.db.delete_session(g.sid)
        sid = random_token(32)  # 256 bits gerados pelo servidor
        self.db.create_session(sid, user_id, data, ttl)
        g.sid, g.session_data, g.session_user_id = sid, data, user_id
        g.new_sid, g.clear_cookie = sid, False
        return sid

    def destroy(self) -> None:
        if g.get("sid"):
            self.db.delete_session(g.sid)
        g.sid, g.session_data, g.session_user_id = None, {}, None
        g.new_sid, g.clear_cookie = None, True

    def pop_login_transaction(self) -> dict | None:
        """Lê e destrói a transação de login: state/nonce/verifier são de uso único."""
        tx = g.session_data.get("tx") if g.get("sid") and g.session_user_id is None else None
        if g.get("sid") and g.session_user_id is None:
            self.destroy()
        if tx and time.time() - tx.get("created", 0) > LOGIN_TX_TTL:
            return None
        return tx

    # Chamado em after_request
    def apply_cookie(self, response):
        if g.get("new_sid"):
            response.set_cookie(SESSION_COOKIE, g.new_sid, httponly=True, secure=True,
                                samesite="Lax", path="/")
        elif g.get("clear_cookie"):
            response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True,
                                   samesite="Lax")
        return response


class RateLimiter:
    """Janela deslizante por IP, em memória (suficiente para uma instância)."""

    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


def rate_limited(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        limiter: RateLimiter = current_app.extensions["rate_limiter"]
        if not limiter.allow(request.remote_addr or "?"):
            current_app.extensions["db"].audit("rate_limit", f"ip={request.remote_addr} {request.path}")
            abort(429)
        return view(*args, **kwargs)
    return wrapper


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            abort(401)
        return view(*args, **kwargs)
    return wrapper


def role_required(role: str):
    """Autorização no SERVIDOR. O role é relido do banco a cada requisição
    (before_request), então rebaixar um usuário tem efeito imediato."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.get("user") is None:
                abort(401)
            if g.user["role"] != role:
                current_app.extensions["db"].audit(
                    "acesso_negado", f"user_id={g.user['id']} role={g.user['role']} {request.path}")
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def check_csrf() -> None:
    token = request.form.get("csrf_token", "")
    expected = g.session_data.get("csrf", "")
    import hmac
    if not expected or not hmac.compare_digest(token.encode(), expected.encode()):
        abort(400)
