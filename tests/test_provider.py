"""Testes da integração com o provedor (descoberta, JWKS, /token) com HTTP simulado."""
import base64

import pytest
import requests

from app.config import Config
from app.oidc import GoogleProvider, ProviderError, b64url_encode, validate_id_token
from conftest import CLIENT_ID, KID

GOOGLE_MD = {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    "code_challenge_methods_supported": ["plain", "S256"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


class Resp:
    def __init__(self, status, body, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.status_code)


class FakeHTTP:
    def __init__(self, jwks):
        self.jwks, self.calls = jwks, []
        self.token_response = Resp(200, {"id_token": "x", "access_token": "y", "token_type": "Bearer"})

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        assert "timeout" in kw
        if url.endswith("openid-configuration"):
            return Resp(200, GOOGLE_MD)
        if url == GOOGLE_MD["jwks_uri"]:
            return Resp(200, self.jwks)
        raise AssertionError(url)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        assert "timeout" in kw
        return self.token_response


def jwk_of(key, kid):
    nums = key.public_key().public_numbers()
    to_b64 = lambda i: b64url_encode(i.to_bytes((i.bit_length() + 7) // 8, "big"))  # noqa: E731
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": to_b64(nums.n),
            "e": to_b64(nums.e)}


@pytest.fixture
def cfg():
    c = Config()
    c.client_id, c.client_secret = CLIENT_ID, "s3cr3t/+="
    return c


def test_token_real_validado_com_chave_do_jwks(cfg, rsa_key, tokens):
    http = FakeHTTP({"keys": [jwk_of(rsa_key, KID)]})
    p = GoogleProvider(cfg, session=http)
    claims = validate_id_token(tokens.sign(), key_resolver=p.get_signing_key, issuers=p.issuers,
                               client_id=CLIENT_ID, nonce="nonce-teste")
    assert claims["sub"]
    assert p.issuers == ["https://accounts.google.com", "accounts.google.com"]


def test_rotacao_de_chave_recarrega_jwks(cfg, rsa_key, other_key, tokens):
    http = FakeHTTP({"keys": [jwk_of(other_key, "antiga")]})
    p = GoogleProvider(cfg, session=http)
    p.get_signing_key("antiga")
    http.jwks = {"keys": [jwk_of(other_key, "antiga"), jwk_of(rsa_key, KID)]}
    p.jwks._loaded_at -= 61  # passou o intervalo mínimo entre recargas
    assert p.get_signing_key(KID) is not None


def test_kid_desconhecido_nao_forca_recarga_em_rajada(cfg, rsa_key):
    http = FakeHTTP({"keys": [jwk_of(rsa_key, KID)]})
    p = GoogleProvider(cfg, session=http)
    p.get_signing_key(KID)
    n = len(http.calls)
    for i in range(20):
        with pytest.raises(KeyError):
            p.get_signing_key(f"aleatorio-{i}")
    assert len(http.calls) == n


def test_jwks_ignora_chaves_que_nao_sao_rsa_de_assinatura(cfg, rsa_key):
    http = FakeHTTP({"keys": [{**jwk_of(rsa_key, "enc"), "use": "enc"},
                              {**jwk_of(rsa_key, "hs"), "alg": "HS256"}]})
    p = GoogleProvider(cfg, session=http)
    for kid in ("enc", "hs"):
        with pytest.raises(KeyError):
            p.get_signing_key(kid)


def test_troca_do_code_usa_client_secret_basic_e_parametros_corretos(cfg, rsa_key):
    http = FakeHTTP({"keys": []})
    GoogleProvider(cfg, session=http).exchange_code("c0de", "verif", "https://localhost:8443/callback")
    method, url, kw = http.calls[-1]
    assert (method, url) == ("POST", GOOGLE_MD["token_endpoint"])
    assert kw["data"] == {"grant_type": "authorization_code", "code": "c0de",
                          "redirect_uri": "https://localhost:8443/callback", "code_verifier": "verif"}
    assert "client_secret" not in kw["data"]
    assert kw["auth"] == (CLIENT_ID, "s3cr3t%2F%2B%3D")  # RFC 6749 §2.3.1: form-urlencoded


def test_invalid_grant_vira_provider_error(cfg):
    http = FakeHTTP({"keys": []})
    http.token_response = Resp(400, {"error": "invalid_grant", "error_description": "Bad Request"})
    with pytest.raises(ProviderError) as exc:
        GoogleProvider(cfg, session=http).exchange_code("c", "v", "r")
    assert exc.value.oauth_error == "invalid_grant"


def test_falha_de_rede_nao_repete_a_troca(cfg):
    http = FakeHTTP({"keys": []})

    def boom(url, **kw):
        http.calls.append(("POST", url, kw))
        raise requests.Timeout()
    http.post = boom
    with pytest.raises(ProviderError):
        GoogleProvider(cfg, session=http).exchange_code("c", "v", "r")
    assert sum(1 for c in http.calls if c[0] == "POST") == 1
