"""Testes do fluxo completo na aplicação: callback, sessão, autorização (casos 8, 13, 15...)."""
from urllib.parse import parse_qs, urlparse

from conftest import HTTPS, full_login, start_login

SID = "__Host-sid"


def cookie_header(resp):
    return ";".join(resp.headers.getlist("Set-Cookie"))


# ------------------------------------------------------------ fluxo feliz
def test_login_completo_cria_sessao_e_vincula_por_sub(client, provider, app):
    q = start_login(client)
    # Passo 2: parâmetros da requisição de autorização
    assert q["response_type"] == ["code"]
    assert q["scope"] == ["openid profile email"]
    assert q["code_challenge_method"] == ["S256"]
    assert len(q["state"][0]) >= 22 and len(q["nonce"][0]) >= 22  # >= 128 bits
    r = client.get("/callback", query_string={"code": "code-valido", "state": q["state"][0]},
                   base_url=HTTPS)
    assert r.status_code == 302 and r.headers["Location"].endswith("/perfil")
    r = client.get("/perfil", base_url=HTTPS)
    assert r.status_code == 200
    assert "110169484474386276334" in r.get_data(as_text=True)
    user = app.extensions["db"].list_users()[0]
    assert user["oidc_sub"] == "110169484474386276334"
    assert user["oidc_iss"] == "https://accounts.google.com"
    assert user["user_name"] == "joao.silva@example.com"


def test_cookie_de_sessao_seguro(client):
    start = client.get("/login", base_url=HTTPS)
    c = cookie_header(start)
    assert SID in c and "HttpOnly" in c and "Secure" in c and "SameSite=Lax" in c and "Path=/" in c


def test_session_id_rotacionado_no_login(client):
    q = start_login(client)
    sid_pre = client.get_cookie(SID).value
    client.get("/callback", query_string={"code": "code-valido", "state": q["state"][0]},
               base_url=HTTPS)
    sid_pos = client.get_cookie(SID).value
    assert sid_pre != sid_pos
    assert len(sid_pos) >= 22


def test_sessao_no_banco_guarda_apenas_hash_do_sid(client, app):
    full_login(client)
    sid = client.get_cookie(SID).value
    import sqlite3
    conn = sqlite3.connect(app.extensions["config"].database_path)
    rows = [r[0] for r in conn.execute("SELECT sid_hash FROM sessions")]
    assert sid not in rows and len(rows) == 1


def test_mesmo_sub_com_email_diferente_e_o_mesmo_usuario(client, provider, app):
    full_login(client)
    provider.claims_override = {"email": "novo.email@example.com"}
    client2 = app.test_client()
    full_login(client2)
    assert len(app.extensions["db"].list_users()) == 1


def test_email_igual_com_sub_diferente_nao_reaproveita_conta(client, provider, app):
    full_login(client)
    provider.sub = "999999999999999999999"
    full_login(app.test_client())
    users = app.extensions["db"].list_users()
    assert len(users) == 2 and users[0]["id"] != users[1]["id"]


# ------------------------------------------------------- teste negativo 8
def test_08_state_divergente_aborta_antes_da_troca(client, provider):
    start_login(client)
    r = client.get("/callback", query_string={"code": "code-valido", "state": "forjado"},
                   base_url=HTTPS)
    assert r.status_code == 400
    assert provider.exchange_calls == []  # o token_endpoint nunca foi chamado
    assert client.get_cookie(SID) is None


def test_08_state_ausente_aborta_antes_da_troca(client, provider):
    start_login(client)
    r = client.get("/callback", query_string={"code": "code-valido"}, base_url=HTTPS)
    assert r.status_code == 400 and provider.exchange_calls == []


def test_08_state_repetido_aborta(client, provider):
    q = start_login(client)
    r = client.get(f"/callback?code=code-valido&state={q['state'][0]}&state=x", base_url=HTTPS)
    assert r.status_code == 400 and provider.exchange_calls == []


def test_iss_do_callback_rfc9207_de_outro_emissor_aborta(client, provider):
    q = start_login(client)
    r = client.get("/callback", query_string={"code": "code-valido", "state": q["state"][0],
                                              "iss": "https://evil.example"}, base_url=HTTPS)
    assert r.status_code == 400 and provider.exchange_calls == []


def test_iss_do_callback_correto_aceito(client, provider):
    q = start_login(client)
    r = client.get("/callback", query_string={"code": "code-valido", "state": q["state"][0],
                                              "iss": "https://accounts.google.com"}, base_url=HTTPS)
    assert r.status_code == 302


def test_log_de_acesso_nao_grava_code_nem_state():
    import logging
    from app import RedactSecretsFilter
    rec = logging.LogRecord("werkzeug", logging.INFO, "", 0,
                            '"GET /callback?state=abc123&iss=x&code=4/0AUn6Hd HTTP/1.1" 302 -', None, None)
    RedactSecretsFilter().filter(rec)
    assert "abc123" not in rec.getMessage() and "4/0AUn6Hd" not in rec.getMessage()
    assert "state=[REDACTED]" in rec.getMessage() and "iss=x" in rec.getMessage()


def test_callback_sem_transacao_de_login(client, provider):
    r = client.get("/callback", query_string={"code": "code-valido", "state": "x"}, base_url=HTTPS)
    assert r.status_code == 400 and provider.exchange_calls == []


def test_state_e_de_uso_unico(client, provider):
    q = start_login(client)
    client.get("/callback", query_string={"code": "code-valido", "state": q["state"][0]},
               base_url=HTTPS)
    client.post("/logout", base_url=HTTPS)
    r = client.get("/callback", query_string={"code": "code-valido", "state": q["state"][0]},
                   base_url=HTTPS)
    assert r.status_code in (302, 400)
    assert len(provider.exchange_calls) == 1


# -------------------------------------------- verificador e nonce do lado do cliente
def test_code_verifier_enviado_corresponde_ao_challenge(client, provider):
    full_login(client)
    import hashlib
    from app.oidc import b64url_encode
    _, verifier, _ = provider.exchange_calls[0]
    assert 43 <= len(verifier) <= 128
    assert b64url_encode(hashlib.sha256(verifier.encode()).digest()) == \
        provider.last_auth_params["code_challenge"]


def test_id_token_rejeitado_nao_cria_sessao(client, provider):
    provider.claims_override = {"aud": "outro-cliente"}
    r = full_login(client)
    assert r.status_code == 401
    assert client.get("/perfil", base_url=HTTPS).status_code == 401


def test_10_userinfo_com_sub_diferente_rejeita_login(client, provider):
    provider.userinfo_sub = "outro-sub"
    r = full_login(client)
    assert r.status_code == 401
    assert client.get("/perfil", base_url=HTTPS).status_code == 401


# ---------------------------------------------- 4.6 erro devolvido pelo provedor
def test_access_denied_mensagem_amigavel_sem_sessao(client, provider):
    q = start_login(client)
    r = client.get("/callback", query_string={"error": "access_denied", "state": q["state"][0],
                                              "error_description": "detalhe interno"},
                   base_url=HTTPS)
    body = r.get_data(as_text=True)
    assert r.status_code == 400 and "cancelou" in body and "detalhe interno" not in body
    assert provider.exchange_calls == []
    assert client.get("/perfil", base_url=HTTPS).status_code == 401


# --------------------------------------------- provisionamento (passo 10)
def test_auto_provision_desligado_recusa_usuario_desconhecido(client, app):
    app.extensions["config"].auto_provision = False
    assert full_login(client).status_code == 403
    assert app.extensions["db"].list_users() == []


def test_email_nao_verificado_nao_cria_conta(client, provider, app):
    provider.claims_override = {"email_verified": False}
    assert full_login(client).status_code == 403
    assert app.extensions["db"].list_users() == []


def test_hd_restringe_dominio(client, provider, app):
    app.extensions["config"].allowed_hd = "unoesc.edu.br"
    provider.claims_override = {"hd": "outra.edu.br"}
    assert full_login(client).status_code == 403
    provider.claims_override = {"hd": "unoesc.edu.br"}
    assert full_login(app.test_client()).status_code == 302


# ------------------------------------------------------- teste negativo 13
def test_13_admin_com_role_user_retorna_403(client):
    full_login(client)
    assert client.get("/admin", base_url=HTTPS).status_code == 403


def test_admin_sem_login_retorna_401(client):
    assert client.get("/admin", base_url=HTTPS).status_code == 401


def test_admin_com_role_admin_retorna_200(client, provider, app):
    app.extensions["config"].admin_subs = [provider.sub]
    full_login(client)
    assert client.get("/admin", base_url=HTTPS).status_code == 200


def test_role_revalidado_a_cada_requisicao(client, provider, app):
    app.extensions["config"].admin_subs = [provider.sub]
    full_login(client)
    assert client.get("/admin", base_url=HTTPS).status_code == 200
    db = app.extensions["db"]
    db.set_role(db.list_users()[0]["id"], "user")  # rebaixado no banco
    assert client.get("/admin", base_url=HTTPS).status_code == 403


# ------------------------------------------------------------ logout (4.4)
def test_logout_invalida_sessao_no_servidor(client, app):
    full_login(client)
    sid = client.get_cookie(SID).value
    page = client.get("/perfil", base_url=HTTPS).get_data(as_text=True)
    import re
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    r = client.post("/logout", data={"csrf_token": csrf}, base_url=HTTPS)
    assert r.status_code == 302
    # Reapresentar o sessionID antigo não funciona mais
    client.set_cookie(SID, sid, domain="localhost", secure=True)
    assert client.get("/perfil", base_url=HTTPS).status_code == 401


def test_logout_sem_csrf_recusado(client):
    full_login(client)
    assert client.post("/logout", base_url=HTTPS).status_code == 400
    assert client.get("/perfil", base_url=HTTPS).status_code == 200


def test_sessao_expira_por_inatividade(client, app):
    full_login(client)
    import sqlite3
    conn = sqlite3.connect(app.extensions["config"].database_path)
    conn.execute("UPDATE sessions SET last_seen = last_seen - 31*60")
    conn.commit()
    assert client.get("/perfil", base_url=HTTPS).status_code == 401


def test_sessao_expira_pelo_tempo_absoluto(client, app):
    full_login(client)
    import sqlite3
    conn = sqlite3.connect(app.extensions["config"].database_path)
    conn.execute("UPDATE sessions SET absolute_expiry = 0")
    conn.commit()
    assert client.get("/perfil", base_url=HTTPS).status_code == 401


# ------------------------------------------------------- teste negativo 15
def test_15_rate_limiting_no_login(client, app):
    app.extensions["rate_limiter"].limit = 5
    codes = [client.get("/login", base_url=HTTPS).status_code for _ in range(8)]
    print("\n    -> status das 8 tentativas:", codes)
    assert codes[:5] == [302] * 5 and codes[5:] == [429] * 3


# ------------------------------------------------------------ cabeçalhos
def test_cabecalhos_de_seguranca(client):
    r = client.get("/", base_url=HTTPS)
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_demo_desligado_por_padrao(client):
    assert client.get("/demo", base_url=HTTPS).status_code == 404
    assert client.get("/login?demo=reuso_code", base_url=HTTPS).status_code == 400


def test_demo_redirect_uri_adulterada(client, provider, app):
    app.extensions["config"].demo_mode = True
    for demo, esperado in [("redirect_barra", "/callback/"), ("redirect_param", "/callback?extra=1"),
                           ("redirect_subcaminho", "/callback/sub")]:
        r = client.get(f"/login?demo={demo}", base_url=HTTPS)
        ru = parse_qs(urlparse(r.headers["Location"]).query)["redirect_uri"][0]
        assert ru.endswith(esperado)
