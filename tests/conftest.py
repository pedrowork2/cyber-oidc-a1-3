"""Infraestrutura de testes: um "Google falso" com par de chaves RSA próprio.

Os tokens de ataque são montados byte a byte aqui, para que cada teste negativo
mude exatamente UM aspecto de um token que, fora isso, seria válido.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.config import Config  # noqa: E402
from app.oidc import ProviderError, b64url_encode  # noqa: E402

ISSUER = "https://accounts.google.com"
CLIENT_ID = "app-cybersecurity-33506.apps.googleusercontent.com"
KID = "kid-teste-2026"


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64json(obj) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


class TokenFactory:
    def __init__(self, key):
        self.key = key

    def claims(self, **over):
        now = int(time.time())
        c = {"iss": ISSUER, "sub": "110169484474386276334", "aud": CLIENT_ID, "azp": CLIENT_ID,
             "exp": now + 900, "iat": now, "nonce": "nonce-teste", "name": "Joao Silva",
             "email": "joao.silva@example.com", "email_verified": True}
        c.update(over)
        return {k: v for k, v in c.items() if v is not ...}

    def sign(self, claims=None, header=None, key=None):
        header = header or {"alg": "RS256", "typ": "JWT", "kid": KID}
        signing_input = f"{b64json(header)}.{b64json(claims or self.claims())}".encode()
        sig = (key or self.key).sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return signing_input.decode() + "." + b64url_encode(sig)

    def unsigned(self, claims=None, alg="none"):
        header = {"alg": alg, "typ": "JWT", "kid": KID}
        return f"{b64json(header)}.{b64json(claims or self.claims())}."

    def hs256_with_public_key(self, claims=None):
        """Ataque de confusão de algoritmo: usa a chave PÚBLICA (PEM) como segredo HMAC."""
        secret = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        header = {"alg": "HS256", "typ": "JWT", "kid": KID}
        signing_input = f"{b64json(header)}.{b64json(claims or self.claims())}".encode()
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        return signing_input.decode() + "." + b64url_encode(sig)


@pytest.fixture
def tokens(rsa_key):
    return TokenFactory(rsa_key)


class FakeProvider:
    """Simula o Google: guarda os codes emitidos e a ligação code -> nonce/challenge."""

    def __init__(self, key, factory: TokenFactory):
        self.key, self.factory = key, factory
        self.issuers = [ISSUER, "accounts.google.com"]
        self.metadata = {"issuer": ISSUER}
        self.exchange_calls = []
        self.last_auth_params = None
        self.claims_override = {}
        self.userinfo_sub = None
        self.sub = "110169484474386276334"

    def authorization_url(self, params):
        self.last_auth_params = params
        from urllib.parse import urlencode
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

    def get_signing_key(self, kid):
        if kid != KID:
            raise KeyError(kid)
        return self.key.public_key()

    def exchange_code(self, code, code_verifier, redirect_uri):
        self.exchange_calls.append((code, code_verifier, redirect_uri))
        p = self.last_auth_params
        challenge = b64url_encode(hashlib.sha256(code_verifier.encode()).digest())
        if code != "code-valido" or challenge != p["code_challenge"] or redirect_uri != p["redirect_uri"]:
            raise ProviderError("recusado", oauth_error="invalid_grant", status=400,
                                body={"error": "invalid_grant"})
        claims = self.factory.claims(nonce=p["nonce"], sub=self.sub, **self.claims_override)
        return {"access_token": "ya29.opaco", "token_type": "Bearer", "expires_in": 3599,
                "id_token": self.factory.sign(claims)}

    tokeninfo_aud = CLIENT_ID
    tokeninfo_expires_in = 3500

    def tokeninfo(self, access_token):
        if access_token != "ya29.opaco":
            raise ProviderError("token inválido", status=400)
        return {"aud": self.tokeninfo_aud, "azp": self.tokeninfo_aud,
                "expires_in": str(self.tokeninfo_expires_in), "scope": "openid email profile"}

    def userinfo(self, access_token):
        return {"sub": self.userinfo_sub or self.sub, "name": "Joao Silva",
                "email": "joao.silva@example.com"}


@pytest.fixture
def provider(rsa_key, tokens):
    return FakeProvider(rsa_key, tokens)


@pytest.fixture
def config(tmp_path):
    cfg = Config()
    cfg.client_id = CLIENT_ID
    cfg.client_secret = "segredo-de-teste"
    cfg.redirect_uri = "https://localhost:8443/callback"
    cfg.database_path = str(tmp_path / "test.db")
    cfg.auto_provision = True
    cfg.admin_subs = []
    cfg.allowed_hd = ""
    cfg.demo_mode = False
    cfg.rate_limit_per_minute = 1000
    return cfg


@pytest.fixture
def app(config, provider):
    return create_app(config, provider=provider, setup_logging=False)


@pytest.fixture
def client(app):
    return app.test_client()


HTTPS = "https://localhost:8443"


def start_login(client):
    r = client.get("/login", base_url=HTTPS)
    assert r.status_code == 302
    return parse_qs(urlparse(r.headers["Location"]).query)


def full_login(client, code="code-valido"):
    q = start_login(client)
    return client.get("/callback", query_string={"code": code, "state": q["state"][0]},
                      base_url=HTTPS)
