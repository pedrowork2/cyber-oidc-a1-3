"""Camada OpenID Connect do cliente (Relying Party).

Contém:
  * utilitários de aleatoriedade e PKCE (RFC 7636);
  * a classe GoogleProvider, que fala com o provedor (descoberta, JWKS, /token, /userinfo);
  * validate_id_token(), que implementa o checklist do item 4.3 do enunciado.

Decisão de projeto: a verificação do JWT é feita "à mão" com a biblioteca
`cryptography`, em vez de delegada a uma biblioteca de JWT. Assim cada item do
checklist aparece explicitamente no código e no log, e o algoritmo de
verificação NUNCA é escolhido a partir do campo `alg` do token (RFC 8725 §3.1).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

log = logging.getLogger("oidc")

# ---------------------------------------------------------------------------
# Lista FIXA de algoritmos aceitos (RFC 8725 §2.1 e §3.1).
# "none", HS256 e qualquer outro valor são rejeitados antes de qualquer
# operação criptográfica. O mapeamento abaixo define COMO verificar cada
# algoritmo aceito: o token não tem poder de escolher a função de verificação.
# ---------------------------------------------------------------------------
ALLOWED_ALGS: dict[str, Any] = {
    "RS256": (padding.PKCS1v15, hashes.SHA256),
}


# ---------------------------------------------------------------------------
# Base64URL, aleatoriedade e PKCE
# ---------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    if not isinstance(data, str) or any(c in data for c in "+/= \n"):
        raise ValueError("base64url inválido")
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def random_token(nbytes: int = 32) -> str:
    """Valor imprevisível com 8*nbytes bits de entropia (padrão: 256 bits >= 128 exigidos)."""
    return secrets.token_urlsafe(nbytes)


def pkce_pair() -> tuple[str, str]:
    """Gera (code_verifier, code_challenge) com o método S256.

    code_verifier: 64 bytes aleatórios -> 86 caracteres do alfabeto não reservado
    (RFC 7636 §4.1 exige entre 43 e 128).
    code_challenge = BASE64URL(SHA256(ASCII(code_verifier))) (RFC 7636 §4.2).
    """
    verifier = secrets.token_urlsafe(64)
    challenge = b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def constant_time_equals(a: str | None, b: str | None) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# Decomposição do JWT (passo 7 do item 4.2)
# ---------------------------------------------------------------------------
class TokenValidationError(Exception):
    def __init__(self, check: str, message: str):
        super().__init__(f"[{check}] {message}")
        self.check = check
        self.message = message


@dataclass
class DecodedJWT:
    header_b64: str
    payload_b64: str
    signature_b64: str
    header: dict
    payload: dict
    signature: bytes

    @property
    def signing_input(self) -> bytes:
        return f"{self.header_b64}.{self.payload_b64}".encode("ascii")

    def describe(self) -> dict:
        """Representação para log/relatório. NÃO é confiável até a validação terminar."""
        return {
            "cabecalho": self.header,
            "payload": self.payload,
            "assinatura": {
                "base64url": self.signature_b64,
                "tamanho_bytes": len(self.signature),
                "hex_inicio": self.signature[:16].hex() + "...",
            },
        }


def split_jwt(token: str) -> DecodedJWT:
    if not isinstance(token, str) or token.count(".") != 2:
        raise TokenValidationError("formato", "JWS compacto deve ter exatamente 3 partes")
    h, p, s = token.split(".")
    try:
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
        signature = b64url_decode(s)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise TokenValidationError("formato", f"parte não decodificável: {exc}") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenValidationError("formato", "cabeçalho e payload devem ser objetos JSON")
    return DecodedJWT(h, p, s, header, payload, signature)


# ---------------------------------------------------------------------------
# Validação do ID Token — checklist do item 4.3
# ---------------------------------------------------------------------------
@dataclass
class CheckResult:
    numero: int | str
    item: str
    ok: bool
    detalhe: str


@dataclass
class ValidationReport:
    checks: list[CheckResult] = field(default_factory=list)

    def add(self, numero, item, ok, detalhe):
        self.checks.append(CheckResult(numero, item, ok, detalhe))
        (log.info if ok else log.warning)("checklist %s %-34s %s  %s",
                                          numero, item, "OK " if ok else "FALHA", detalhe)

    def as_list(self) -> list[dict]:
        return [c.__dict__ for c in self.checks]


KeyResolver = Callable[[str], rsa.RSAPublicKey]


def validate_id_token(
    token: str,
    *,
    key_resolver: KeyResolver,
    issuers: list[str],
    client_id: str,
    nonce: str,
    now: float | None = None,
    clock_skew: int = 120,
    report: ValidationReport | None = None,
) -> dict:
    """Valida o ID Token e devolve os claims. Qualquer falha lança TokenValidationError.

    A ordem importa: o algoritmo é checado contra a lista fixa ANTES de buscar
    chave ou verificar assinatura, e nenhum claim é usado antes de a assinatura
    ser conferida.
    """
    report = report if report is not None else ValidationReport()
    now = time.time() if now is None else now

    def fail(numero, item, detalhe):
        report.add(numero, item, False, detalhe)
        raise TokenValidationError(item, detalhe)

    jwt = split_jwt(token)
    header, claims = jwt.header, jwt.payload

    # --- 2. Algoritmo na lista fixa; "none" sempre rejeitado -----------------
    alg = header.get("alg")
    if not isinstance(alg, str) or alg.lower() == "none":
        fail(2, "alg na lista fixa", f'alg={alg!r} rejeitado ("none" nunca é aceito)')
    if alg not in ALLOWED_ALGS:
        fail(2, "alg na lista fixa", f"alg={alg!r} fora da lista aceita {sorted(ALLOWED_ALGS)}")
    if "crit" in header:
        fail(2, "alg na lista fixa", "cabeçalho 'crit' não suportado")
    report.add(2, "alg na lista fixa", True, f"alg={alg} ∈ {sorted(ALLOWED_ALGS)}")

    # --- 1. Assinatura com a chave pública identificada por kid -------------
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        fail(1, "assinatura (kid/JWKS)", "cabeçalho sem kid")
    try:
        public_key = key_resolver(kid)
    except KeyError:
        fail(1, "assinatura (kid/JWKS)", f"kid={kid!r} não encontrado no JWKS do emissor")
    pad_cls, hash_cls = ALLOWED_ALGS[alg]
    try:
        public_key.verify(jwt.signature, jwt.signing_input, pad_cls(), hash_cls())
    except InvalidSignature:
        fail(1, "assinatura (kid/JWKS)", f"assinatura inválida para kid={kid}")
    report.add(1, "assinatura (kid/JWKS)", True, f"RS256 conferida com a chave pública kid={kid}")

    # A partir daqui os claims são autênticos (vieram do emissor).

    # --- 3. iss ---------------------------------------------------------------
    iss = claims.get("iss")
    if iss not in issuers:
        fail(3, "iss", f"iss={iss!r} diferente do emissor esperado {issuers}")
    report.add(3, "iss", True, f"iss={iss}")

    # --- 4. aud contém o client_id -------------------------------------------
    aud = claims.get("aud")
    audiences = [aud] if isinstance(aud, str) else aud
    if not isinstance(audiences, list) or not all(isinstance(a, str) for a in audiences):
        fail(4, "aud", f"aud malformado: {aud!r}")
    if client_id not in audiences:
        fail(4, "aud", f"aud={audiences} não contém o client_id desta aplicação")
    report.add(4, "aud", True, f"aud contém {client_id}")

    # --- 5. azp quando houver mais de um destinatário ------------------------
    azp = claims.get("azp")
    if len(audiences) > 1 and azp is None:
        fail(5, "azp", "aud com vários valores exige azp")
    if azp is not None and azp != client_id:
        fail(5, "azp", f"azp={azp!r} diferente do client_id")
    report.add(5, "azp", True,
               f"azp={azp}" if azp is not None else "aud com valor único; azp não exigido")

    # --- 6. exp ---------------------------------------------------------------
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        fail(6, "exp", "exp ausente ou não numérico")
    if now > exp + clock_skew:
        fail(6, "exp", f"token expirado há {int(now - exp)} s (tolerância {clock_skew} s)")
    report.add(6, "exp", True, f"expira em {int(exp - now)} s")

    # --- 7. iat ---------------------------------------------------------------
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        fail(7, "iat", "iat ausente ou não numérico")
    if iat > now + clock_skew:
        fail(7, "iat", f"iat {int(iat - now)} s no futuro (tolerância {clock_skew} s)")
    report.add(7, "iat", True, f"emitido há {int(now - iat)} s")

    # --- 8. nonce -------------------------------------------------------------
    if not constant_time_equals(claims.get("nonce"), nonce):
        fail(8, "nonce", "nonce do token diferente do enviado em /authorize")
    report.add(8, "nonce", True, "nonce idêntico ao da requisição")

    # sub é a chave de vínculo (usado no item 9, fora desta função)
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub or len(sub) > 255:
        fail(9, "sub", "sub ausente ou inválido")

    return claims


# ---------------------------------------------------------------------------
# JWKS: cache com suporte a rotação de chaves
# ---------------------------------------------------------------------------
def rsa_key_from_jwk(jwk: dict) -> rsa.RSAPublicKey:
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


class JWKSCache:
    """Guarda as chaves públicas por kid.

    Se chegar um kid desconhecido (rotação de chave no provedor), o JWKS é
    recarregado UMA vez — com intervalo mínimo entre recargas para que um
    atacante não force downloads em massa enviando kids aleatórios.
    """

    def __init__(self, fetch: Callable[[], dict], ttl: int = 3600, min_refresh_interval: int = 60):
        self._fetch = fetch
        self._ttl = ttl
        self._min_interval = min_refresh_interval
        self._keys: dict[str, rsa.RSAPublicKey] = {}
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        jwks = self._fetch()
        keys = {}
        for jwk in jwks.get("keys", []):
            if jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig":
                continue
            if jwk.get("alg") not in (None, *ALLOWED_ALGS):
                continue
            if "kid" in jwk:
                keys[jwk["kid"]] = rsa_key_from_jwk(jwk)
        self._keys = keys
        self._loaded_at = time.time()
        log.info("JWKS carregado: kids=%s", sorted(keys))

    def get(self, kid: str) -> rsa.RSAPublicKey:
        with self._lock:
            age = time.time() - self._loaded_at
            if age > self._ttl or (kid not in self._keys and age > self._min_interval):
                self._refresh()
            if kid not in self._keys:
                raise KeyError(kid)
            return self._keys[kid]


# ---------------------------------------------------------------------------
# Provedor (Google) — descoberta, troca do code e userinfo
# ---------------------------------------------------------------------------
class ProviderError(Exception):
    """Erro devolvido pelo provedor ou de rede. `oauth_error` traz o código OAuth, se houver."""

    def __init__(self, message: str, oauth_error: str | None = None, status: int | None = None,
                 body: Any = None):
        super().__init__(message)
        self.oauth_error = oauth_error
        self.status = status
        self.body = body


REQUIRED_METADATA = ("issuer", "authorization_endpoint", "token_endpoint",
                     "userinfo_endpoint", "jwks_uri")


class GoogleProvider:
    def __init__(self, config, session: requests.Session | None = None):
        self.config = config
        self.http = session or requests.Session()
        self._metadata: dict | None = None
        self._lock = threading.Lock()
        self.jwks = JWKSCache(self._fetch_jwks)

    # -- descoberta ---------------------------------------------------------
    @property
    def metadata(self) -> dict:
        with self._lock:
            if self._metadata is None:
                try:
                    resp = self.http.get(self.config.discovery_url, timeout=self.config.http_timeout)
                    resp.raise_for_status()
                    md = resp.json()
                except (requests.RequestException, ValueError) as exc:
                    raise ProviderError(f"descoberta indisponível: {type(exc).__name__}") from None
                missing = [k for k in REQUIRED_METADATA if not md.get(k)]
                if missing:
                    raise ProviderError(f"descoberta incompleta: {missing}")
                if "S256" not in md.get("code_challenge_methods_supported", []):
                    raise ProviderError("provedor não anuncia PKCE S256")
                for k in REQUIRED_METADATA[1:]:
                    if not md[k].startswith("https://"):
                        raise ProviderError(f"{k} não usa HTTPS")
                self._metadata = md
                log.info("Descoberta OIDC carregada: issuer=%s", md["issuer"])
            return self._metadata

    @property
    def issuers(self) -> list[str]:
        return [self.metadata["issuer"], *self.config.extra_issuers]

    def _fetch_jwks(self) -> dict:
        try:
            resp = self.http.get(self.metadata["jwks_uri"], timeout=self.config.http_timeout)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise ProviderError(f"JWKS indisponível: {type(exc).__name__}") from None

    def get_signing_key(self, kid: str) -> rsa.RSAPublicKey:
        return self.jwks.get(kid)

    # -- endpoints ----------------------------------------------------------
    def authorization_url(self, params: dict) -> str:
        from urllib.parse import urlencode
        return f'{self.metadata["authorization_endpoint"]}?{urlencode(params)}'

    def exchange_code(self, code: str, code_verifier: str, redirect_uri: str) -> dict:
        """POST /token. Autenticação do cliente por client_secret_basic (RFC 6749 §2.3.1).

        Chamado no máximo UMA vez por code (4.6): não há retry automático.
        """
        auth = (quote(self.config.client_id, safe=""), quote(self.config.client_secret, safe=""))
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        try:
            resp = self.http.post(self.metadata["token_endpoint"], data=data, auth=auth,
                                  timeout=self.config.http_timeout,
                                  headers={"Accept": "application/json"})
        except requests.RequestException as exc:
            raise ProviderError(f"falha de rede no token_endpoint: {type(exc).__name__}") from None
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code != 200:
            raise ProviderError("token_endpoint recusou a troca",
                                oauth_error=body.get("error"), status=resp.status_code, body=body)
        return body

    def userinfo(self, access_token: str) -> dict:
        try:
            resp = self.http.get(self.metadata["userinfo_endpoint"],
                                 headers={"Authorization": f"Bearer {access_token}"},
                                 timeout=self.config.http_timeout)
        except requests.RequestException as exc:
            raise ProviderError(f"falha de rede no userinfo: {type(exc).__name__}") from None
        if resp.status_code != 200:
            raise ProviderError("userinfo recusou o token", status=resp.status_code,
                                body=resp.headers.get("WWW-Authenticate"))
        return resp.json()
