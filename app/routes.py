"""Rotas da aplicação: implementa o passo a passo do item 4.2 do enunciado."""
from __future__ import annotations

import json
import logging
import time

from flask import (Blueprint, abort, current_app, g, jsonify, redirect, render_template,
                   request, url_for)

from .oidc import (ProviderError, TokenValidationError, ValidationReport, constant_time_equals,
                   pkce_pair, random_token, split_jwt, validate_id_token)
from .security import LOGIN_TX_TTL, check_csrf, login_required, rate_limited, role_required

bp = Blueprint("main", __name__)
log = logging.getLogger("app")

# Variações de redirect_uri para o teste negativo 11 (somente DEMO_MODE)
REDIRECT_TAMPER = {
    "redirect_barra": lambda u: u + "/",
    "redirect_param": lambda u: u + "?extra=1",
    "redirect_subcaminho": lambda u: u + "/sub",
}
DEMOS = {"verifier_errado", "reuso_code", "nonce_errado", *REDIRECT_TAMPER}


def _ext(name):
    return current_app.extensions[name]


def _fail(status: int, title: str, message: str, event: str, detail: str = "", **ctx):
    """Erro amigável para o usuário + detalhe técnico apenas no log/auditoria (4.6)."""
    log.warning("%s: %s", event, detail)
    _ext("db").audit(event, detail)
    return render_template("erro.html", title=title, message=message, code=status, **ctx), status


# ---------------------------------------------------------------------------
@bp.get("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Passos 1 e 2: gerar state, nonce e PKCE; redirecionar para o authorization_endpoint
# ---------------------------------------------------------------------------
@bp.get("/login")
@rate_limited
def login():
    cfg, provider, sessions = _ext("config"), _ext("provider"), _ext("sessions")
    demo = request.args.get("demo")
    if demo and (not cfg.demo_mode or demo not in DEMOS):
        abort(400)
    if g.user is not None and not demo:
        return redirect(url_for("main.perfil"))

    state, nonce = random_token(32), random_token(32)  # 256 bits cada
    code_verifier, code_challenge = pkce_pair()
    redirect_uri = REDIRECT_TAMPER[demo](cfg.redirect_uri) if demo in REDIRECT_TAMPER else cfg.redirect_uri

    # Os três valores ficam no SERVIDOR, ligados a uma sessão pré-login cujo id vai no cookie.
    sessions.create(None, {"tx": {
        "state": state, "nonce": nonce, "code_verifier": code_verifier,
        "redirect_uri": redirect_uri, "created": time.time(), "demo": demo,
    }}, LOGIN_TX_TTL)

    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if cfg.allowed_hd:
        params["hd"] = cfg.allowed_hd  # só uma dica de UI; a regra real é checada no callback
    try:
        url = provider.authorization_url(params)
    except ProviderError as exc:
        sessions.destroy()
        return _fail(502, "Provedor indisponível", "Não foi possível falar com o Google agora.",
                     "descoberta_falhou", str(exc))
    log.info("Início do fluxo: state=%s… nonce=%s… code_challenge=%s demo=%s",
             state[:8], nonce[:8], code_challenge, demo)
    return redirect(url, code=302)


# ---------------------------------------------------------------------------
# Passos 4 a 11: callback
# ---------------------------------------------------------------------------
@bp.get("/callback")
@rate_limited
def callback():
    cfg, provider, db, sessions = _ext("config"), _ext("provider"), _ext("db"), _ext("sessions")
    tx = sessions.pop_login_transaction()  # uso único: some da sessão já aqui
    demo = (tx or {}).get("demo")

    # 4.6 — o provedor devolveu erro (ex.: access_denied)
    if "error" in request.args:
        err = request.args.get("error", "")
        msg = ("Você cancelou o login." if err == "access_denied"
               else "O provedor de identidade não concluiu o login.")
        return _fail(400, "Login não concluído", msg, "callback_erro_provedor",
                     f"error={err} description={request.args.get('error_description', '')}")

    if tx is None:
        return _fail(400, "Sessão de login expirada", "Inicie o login novamente.",
                     "callback_sem_transacao", "sem transação de login válida no servidor")

    # Passo 5 — state (CSRF). Aborta ANTES de qualquer chamada ao token_endpoint.
    states = request.args.getlist("state")
    if len(states) != 1 or not constant_time_equals(states[0], tx["state"]):
        return _fail(400, "Requisição inválida", "Não foi possível validar o retorno do login.",
                     "state_invalido",
                     f"state ausente/divergente (recebidos={len(states)}) — possível CSRF; "
                     "fluxo abortado antes da troca do code")

    # RFC 9207: o Google devolve o emissor no callback; se vier, deve ser o esperado
    # (defesa contra o ataque de "mix-up" entre provedores).
    iss_param = request.args.getlist("iss")
    if len(iss_param) > 1 or (iss_param and iss_param[0] not in provider.issuers):
        return _fail(400, "Requisição inválida", "Não foi possível validar o retorno do login.",
                     "iss_callback_invalido", f"iss no callback={iss_param}")

    codes = request.args.getlist("code")
    if len(codes) != 1 or not codes[0]:
        return _fail(400, "Requisição inválida", "Retorno do login incompleto.",
                     "code_ausente", f"codes recebidos={len(codes)}")
    code = codes[0]

    # Passo 6 — troca do code (uma única vez; sem retry)
    verifier = tx["code_verifier"]
    if demo == "verifier_errado":
        verifier = pkce_pair()[0]
    try:
        tokens = provider.exchange_code(code, verifier, tx["redirect_uri"])
    except ProviderError as exc:
        detail = f"status={exc.status} error={exc.oauth_error} body={exc.body}"
        if demo:
            log.info("DEMO %s: token_endpoint recusou: %s", demo, detail)
            _ext("db").audit("demo_" + demo, detail)
            return render_template("demo_resultado.html", demo=demo, titulo="Troca do code recusada",
                                   resultado={"status_http": exc.status, "resposta": exc.body})
        return _fail(502, "Falha no login", "Não foi possível concluir o login agora.",
                     "token_endpoint_falhou", detail)

    demo_info = None
    if demo == "reuso_code":
        demo_info = _demo_reuse_code(provider, code, tx, tokens)

    id_token = tokens.get("id_token")
    if not id_token or str(tokens.get("token_type", "")).lower() != "bearer":
        return _fail(502, "Falha no login", "Resposta inesperada do provedor.",
                     "resposta_token_invalida", f"campos={sorted(tokens)}")

    # Passo 7 — decompor o ID Token e registrar as três partes no log
    try:
        decoded = split_jwt(id_token)
        log.info("ID Token decomposto (ainda NÃO validado):\n%s",
                 json.dumps(decoded.describe(), indent=2, ensure_ascii=False))
    except TokenValidationError as exc:
        return _fail(401, "Falha no login", "Token de identidade inválido.", "id_token_invalido",
                     str(exc))

    # Passo 8 — validar conforme o checklist 4.3
    report = ValidationReport()
    nonce = random_token() if demo == "nonce_errado" else tx["nonce"]
    try:
        claims = validate_id_token(
            id_token, key_resolver=provider.get_signing_key, issuers=provider.issuers,
            client_id=cfg.client_id, nonce=nonce, clock_skew=cfg.clock_skew, report=report)
    except TokenValidationError as exc:
        if demo:
            return render_template("demo_resultado.html", demo=demo, titulo="ID Token rejeitado",
                                   resultado={"erro": str(exc)}, checklist=report.as_list())
        return _fail(401, "Falha no login", "Não foi possível validar sua identidade.",
                     "id_token_rejeitado", str(exc))
    except ProviderError as exc:
        return _fail(502, "Falha no login", "Não foi possível concluir o login agora.",
                     "jwks_indisponivel", str(exc))

    # Extra (ponto adicional): restrição de domínio pelo claim hd — não pelo sufixo do e-mail
    if cfg.allowed_hd:
        ok = claims.get("hd") == cfg.allowed_hd
        report.add("extra", "hd (domínio)", ok, f"hd={claims.get('hd')!r} esperado={cfg.allowed_hd!r}")
        if not ok:
            return _fail(403, "Acesso negado", "Esta aplicação aceita apenas contas institucionais.",
                         "hd_recusado", f"hd={claims.get('hd')!r}")

    # Checklist 10 — /userinfo com o access token; sub deve ser o mesmo do ID Token
    try:
        info = provider.userinfo(tokens["access_token"])
    except (ProviderError, KeyError) as exc:
        return _fail(502, "Falha no login", "Não foi possível concluir o login agora.",
                     "userinfo_falhou", str(exc))
    if not constant_time_equals(info.get("sub"), claims["sub"]):
        report.add(10, "sub do /userinfo", False, "sub do /userinfo diferente do ID Token")
        return _fail(401, "Falha no login", "Não foi possível validar sua identidade.",
                     "userinfo_sub_divergente", f"id_token.sub={claims['sub']} userinfo.sub={info.get('sub')}")
    report.add(10, "sub do /userinfo", True, "sub do /userinfo idêntico ao do ID Token")

    # Os tokens do provedor não são guardados: depois deste ponto são descartados (4.4).
    tokens.clear()

    # Passos 9 e 10 — vínculo pelo par iss + sub (nunca pelo e-mail)
    iss = provider.issuers[0]  # forma canônica publicada na descoberta
    sub = claims["sub"]
    user = db.find_user_by_sub(iss, sub)
    if user is None:
        if not cfg.auto_provision:
            report.add(9, "sub → id interno", False, "sub não cadastrado e AUTO_PROVISION=false")
            return _fail(403, "Acesso negado", "Seu usuário não está cadastrado nesta aplicação.",
                         "usuario_nao_cadastrado", f"iss={iss} sub={sub}")
        if claims.get("email_verified") is not True or not claims.get("email"):
            report.add(9, "sub → id interno", False, "email_verified != true; registro não criado")
            return _fail(403, "Acesso negado", "Seu e-mail precisa estar verificado no provedor.",
                         "email_nao_verificado", f"sub={sub}")
        role = "admin" if sub in cfg.admin_subs else "user"
        user_id = db.create_user(iss=iss, sub=sub, user_name=claims["email"],
                                 full_name=claims.get("name"), role=role)
        db.audit("usuario_criado", f"id={user_id} sub={sub} role={role}")
        report.add(9, "sub → id interno", True, f"sub novo → registro criado com id={user_id}")
    else:
        user_id = user["id"]
        report.add(9, "sub → id interno", True, f"sub localizado → id interno {user_id}")
    db.touch_login(user_id, claims.get("name"))

    # Passo 11 — sessão local nova (sessionID rotacionado)
    sessions.create(user_id, {
        "csrf": random_token(32),
        "checklist": report.as_list(),
        "login_at": time.time(),
        "demo": demo_info,
    }, cfg.absolute_timeout_s)
    db.audit("login_ok", f"user_id={user_id}")
    log.info("Login concluído: user_id=%s sub=%s", user_id, sub)
    return redirect(url_for("main.perfil"))


def _demo_reuse_code(provider, code, tx, first_tokens):
    """Teste negativo 9 (DEMO_MODE): reapresenta o mesmo code e observa o provedor.

    O OIDC tolera reuso dentro de uma janela muito curta (consistência eventual
    no provedor), então tentamos de imediato e depois de alguns segundos.
    """
    result = {"tentativas_de_reuso": []}
    started = time.time()
    for delay in (0, 3, 10):
        time.sleep(max(0.0, started + delay - time.time()))
        attempt = {"apos_segundos": round(time.time() - started, 1)}
        try:
            provider.exchange_code(code, tx["code_verifier"], tx["redirect_uri"])
            attempt["resultado"] = "ACEITA pelo provedor"
        except ProviderError as exc:
            attempt["resultado"] = "RECUSADA"
            attempt["status_http"], attempt["resposta"] = exc.status, exc.body
        result["tentativas_de_reuso"].append(attempt)
        if attempt["resultado"] == "RECUSADA":
            break
    # O RFC 6749 §4.1.2 diz que o servidor DEVERIA revogar os tokens emitidos a partir do code.
    try:
        provider.userinfo(first_tokens["access_token"])
        result["access_token_original_apos_reuso"] = "ainda válido no /userinfo"
    except ProviderError as exc:
        result["access_token_original_apos_reuso"] = f"recusado (HTTP {exc.status}) — revogado"
    log.info("DEMO reuso do code: %s", result)
    return result


# ---------------------------------------------------------------------------
# Áreas protegidas (4.5)
# ---------------------------------------------------------------------------
@bp.get("/perfil")
@login_required
def perfil():
    checklist = sorted(g.session_data.get("checklist", []),
                       key=lambda c: c["numero"] if isinstance(c["numero"], int) else 99)
    return render_template("perfil.html", checklist=checklist,
                           demo_info=g.session_data.get("demo"))


@bp.get("/admin")
@role_required("admin")
def admin():
    return render_template("admin.html", users=_ext("db").list_users())


REALM = "app-oidc-33506"


def _bearer_error(status: int, error: str | None = None, description: str | None = None):
    """Resposta de erro do RFC 6750 §3: sempre com WWW-Authenticate: Bearer."""
    challenge = f'Bearer realm="{REALM}"'
    body = {}
    if error:
        challenge += f', error="{error}"'
        body["error"] = error
        if description:
            challenge += f', error_description="{description}"'
            body["error_description"] = description
    resp = jsonify(body)
    resp.status_code = status
    resp.headers["WWW-Authenticate"] = challenge
    return resp


@bp.get("/api/userinfo")
@rate_limited
def api_userinfo():
    """Servidor de recursos protegido por Bearer (RFC 6750) — teste negativo 14.

    Aceita o access token do Google apenas se ele foi emitido para ESTE client_id
    (evita aceitar token emitido para outra aplicação) e ainda está válido.
    """
    cfg, provider = _ext("config"), _ext("provider")
    auth = request.headers.get("Authorization", "")
    if not auth:
        return _bearer_error(401)  # RFC 6750 §3.1: sem token → sem código de erro
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip() or " " in token.strip():
        return _bearer_error(400, "invalid_request", "Authorization malformado")
    token = token.strip()
    try:
        info = provider.tokeninfo(token)
    except ProviderError as exc:
        if exc.status is None:  # falha de rede: não dá para afirmar que o token é inválido
            resp = jsonify({"error": "temporarily_unavailable"})
            resp.status_code = 503
            return resp
        return _bearer_error(401, "invalid_token", "token invalido ou expirado")
    if cfg.client_id not in (info.get("aud"), info.get("azp")):
        return _bearer_error(401, "invalid_token", "token emitido para outro cliente")
    try:
        expires_in = int(info.get("expires_in", 0))
    except (TypeError, ValueError):
        expires_in = 0
    if expires_in <= 0:
        return _bearer_error(401, "invalid_token", "token expirado")
    scopes = str(info.get("scope", "")).split()
    if not any(s in scopes for s in ("openid", "email", "profile",
                                     "https://www.googleapis.com/auth/userinfo.email")):
        return _bearer_error(403, "insufficient_scope", "escopo openid ausente")
    try:
        ui = provider.userinfo(token)
    except ProviderError:
        return _bearer_error(401, "invalid_token", "token recusado pelo provedor")
    return jsonify({"sub": ui.get("sub"), "name": ui.get("name"), "email": ui.get("email")})


@bp.get("/demo")
def demo():
    if not _ext("config").demo_mode:
        abort(404)
    return render_template("demo.html")


@bp.post("/logout")
def logout():
    if g.user is not None:
        check_csrf()
        _ext("db").audit("logout", f"user_id={g.session_user_id}")
    _ext("sessions").destroy()  # invalida no servidor e apaga o cookie
    return redirect(url_for("main.index"))
