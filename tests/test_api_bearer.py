"""Teste negativo 14: servidor de recursos /api/userinfo conforme o RFC 6750."""
from conftest import HTTPS


def get(client, token=None, raw=None):
    headers = {}
    if raw is not None:
        headers["Authorization"] = raw
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.get("/api/userinfo", headers=headers, base_url=HTTPS)


def test_14a_sem_token_401_com_www_authenticate(client):
    r = get(client)
    print("\n    ->", r.status_code, r.headers["WWW-Authenticate"])
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == 'Bearer realm="app-oidc-33506"'


def test_14b_token_invalido_ou_expirado_401_invalid_token(client):
    r = get(client, "ya29.token-invalido")
    print("\n    ->", r.status_code, r.headers["WWW-Authenticate"])
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith('Bearer realm="app-oidc-33506", error="invalid_token"')
    assert r.get_json()["error"] == "invalid_token"


def test_14c_token_expirado_segundo_tokeninfo_401(client, provider):
    provider.tokeninfo_expires_in = 0
    r = get(client, "ya29.opaco")
    assert r.status_code == 401 and 'error="invalid_token"' in r.headers["WWW-Authenticate"]


def test_token_de_outro_cliente_401(client, provider):
    provider.tokeninfo_aud = "outro-cliente.apps.googleusercontent.com"
    r = get(client, "ya29.opaco")
    assert r.status_code == 401 and "outro cliente" in r.get_json()["error_description"]


def test_authorization_malformado_400(client):
    r = get(client, raw="Basic dXNlcjpzZW5oYQ==")
    assert r.status_code == 400 and 'error="invalid_request"' in r.headers["WWW-Authenticate"]


def test_token_valido_200_com_sub(client, provider):
    r = get(client, "ya29.opaco")
    assert r.status_code == 200
    assert r.get_json()["sub"] == provider.sub
    assert r.headers["Cache-Control"] == "no-store"
