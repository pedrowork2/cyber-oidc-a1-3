"""Modo demonstração: teste 9 (reuso do code) contra o provedor simulado."""
import app.routes as routes
from conftest import HTTPS, start_login


def test_demo_reuso_code_registra_recusa(client, provider, app, monkeypatch):
    app.extensions["config"].demo_mode = True
    monkeypatch.setattr(routes.time, "sleep", lambda s: None)
    original = provider.exchange_code
    calls = {"n": 0}

    def exchange(code, verifier, redirect_uri):
        calls["n"] += 1
        if calls["n"] > 1:  # provedor simulado recusa o reuso
            raise routes.ProviderError("x", oauth_error="invalid_grant", status=400,
                                       body={"error": "invalid_grant"})
        return original(code, verifier, redirect_uri)
    provider.exchange_code = exchange

    r = client.get("/login?demo=reuso_code", base_url=HTTPS)
    from urllib.parse import parse_qs, urlparse
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
    client.get("/callback", query_string={"code": "code-valido", "state": state}, base_url=HTTPS)
    page = client.get("/perfil", base_url=HTTPS).get_data(as_text=True)
    assert "RECUSADA" in page and "invalid_grant" in page
    assert calls["n"] == 2
