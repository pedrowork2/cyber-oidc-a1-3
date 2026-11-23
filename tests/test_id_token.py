"""Testes negativos do item 5 que atacam o ID Token (casos 1–7 e 12) + checklist 4.3."""
import time

import pytest

from app.oidc import TokenValidationError, ValidationReport, validate_id_token
from conftest import CLIENT_ID, ISSUER, KID


def validar(token, rsa_key, nonce="nonce-teste", **kw):
    def resolver(kid):
        if kid != KID:
            raise KeyError(kid)
        return rsa_key.public_key()
    return validate_id_token(token, key_resolver=resolver, issuers=[ISSUER, "accounts.google.com"],
                             client_id=CLIENT_ID, nonce=nonce, clock_skew=120, **kw)


def rejeitado(token, rsa_key, check, **kw):
    with pytest.raises(TokenValidationError) as exc:
        validar(token, rsa_key, **kw)
    print(f"\n    -> REJEITADO: {exc.value}")
    assert exc.value.check == check
    return exc.value


# ------------------------------------------------------------------ positivo
def test_token_valido_passa_em_todo_o_checklist(tokens, rsa_key):
    report = ValidationReport()
    claims = validar(tokens.sign(), rsa_key, report=report)
    assert claims["sub"] == "110169484474386276334"
    assert [c.numero for c in report.checks] == [2, 1, 3, 4, 5, 6, 7, 8]
    assert all(c.ok for c in report.checks)


def test_iss_na_forma_sem_https_tambem_aceita(tokens, rsa_key):
    validar(tokens.sign(tokens.claims(iss="accounts.google.com")), rsa_key)


# ------------------------------------------------------- testes negativos (item 5)
def test_01_alg_none_rejeitado(tokens, rsa_key):
    rejeitado(tokens.unsigned(alg="none"), rsa_key, "alg na lista fixa")


def test_01b_alg_None_variacao_de_caixa_rejeitado(tokens, rsa_key):
    rejeitado(tokens.unsigned(alg="NoNe"), rsa_key, "alg na lista fixa")


def test_02_hs256_reassinado_com_chave_publica_rejeitado(tokens, rsa_key):
    rejeitado(tokens.hs256_with_public_key(), rsa_key, "alg na lista fixa")


def test_03_aud_de_outro_client_id_rejeitado(tokens, rsa_key):
    t = tokens.sign(tokens.claims(aud="outro-cliente.apps.googleusercontent.com", azp=...))
    rejeitado(t, rsa_key, "aud")


def test_04_iss_diferente_rejeitado(tokens, rsa_key):
    rejeitado(tokens.sign(tokens.claims(iss="https://evil.example")), rsa_key, "iss")


def test_05_exp_vencido_rejeitado(tokens, rsa_key):
    agora = int(time.time())
    t = tokens.sign(tokens.claims(iat=agora - 3600, exp=agora - 600))
    rejeitado(t, rsa_key, "exp")


def test_06_iat_no_futuro_rejeitado(tokens, rsa_key):
    agora = int(time.time())
    t = tokens.sign(tokens.claims(iat=agora + 3600, exp=agora + 4500))
    rejeitado(t, rsa_key, "iat")


def test_07_nonce_diferente_rejeitado(tokens, rsa_key):
    rejeitado(tokens.sign(), rsa_key, "nonce", nonce="nonce-que-a-app-enviou")


def test_12_um_byte_alterado_na_assinatura_rejeitado(tokens, rsa_key):
    from app.oidc import b64url_decode, b64url_encode
    h, p, s = tokens.sign().split(".")
    sig = bytearray(b64url_decode(s))
    sig[10] ^= 0x01  # inverte 1 bit de 1 byte
    rejeitado(f"{h}.{p}.{b64url_encode(bytes(sig))}", rsa_key, "assinatura (kid/JWKS)")


# --------------------------------------------- verificações adicionais do checklist
def test_payload_alterado_mantendo_assinatura_rejeitado(tokens, rsa_key):
    from conftest import b64json
    h, _, s = tokens.sign().split(".")
    forjado = b64json(tokens.claims(sub="admin-falso"))
    rejeitado(f"{h}.{forjado}.{s}", rsa_key, "assinatura (kid/JWKS)")


def test_kid_desconhecido_e_erro(tokens, rsa_key):
    t = tokens.sign(header={"alg": "RS256", "typ": "JWT", "kid": "kid-inexistente"})
    rejeitado(t, rsa_key, "assinatura (kid/JWKS)")


def test_sem_kid_rejeitado(tokens, rsa_key):
    rejeitado(tokens.sign(header={"alg": "RS256", "typ": "JWT"}), rsa_key, "assinatura (kid/JWKS)")


def test_assinado_por_outra_chave_rejeitado(tokens, rsa_key, other_key):
    rejeitado(tokens.sign(key=other_key), rsa_key, "assinatura (kid/JWKS)")


def test_alg_fora_da_lista_rs512_rejeitado(tokens, rsa_key):
    rejeitado(tokens.sign(header={"alg": "RS512", "typ": "JWT", "kid": KID}), rsa_key,
              "alg na lista fixa")


def test_aud_multipla_sem_azp_rejeitado(tokens, rsa_key):
    t = tokens.sign(tokens.claims(aud=[CLIENT_ID, "outro"], azp=...))
    rejeitado(t, rsa_key, "azp")


def test_aud_multipla_com_azp_de_outro_rejeitado(tokens, rsa_key):
    t = tokens.sign(tokens.claims(aud=[CLIENT_ID, "outro"], azp="outro"))
    rejeitado(t, rsa_key, "azp")


def test_aud_multipla_com_azp_correto_aceito(tokens, rsa_key):
    validar(tokens.sign(tokens.claims(aud=[CLIENT_ID, "outro"], azp=CLIENT_ID)), rsa_key)


def test_exp_dentro_da_tolerancia_aceito(tokens, rsa_key):
    agora = int(time.time())
    validar(tokens.sign(tokens.claims(iat=agora - 960, exp=agora - 60)), rsa_key)


def test_sem_nonce_rejeitado(tokens, rsa_key):
    rejeitado(tokens.sign(tokens.claims(nonce=...)), rsa_key, "nonce")


def test_formato_invalido_rejeitado(rsa_key):
    rejeitado("nao.e.um.jwt", rsa_key, "formato")
