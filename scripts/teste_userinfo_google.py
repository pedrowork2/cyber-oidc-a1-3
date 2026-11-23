"""Teste negativo 14 contra o Google real, mais conferência da descoberta e do JWKS.

Uso: python scripts/teste_userinfo_google.py
Gera evidência em terminal para o relatório.
"""
import json

import requests

DISCOVERY = "https://accounts.google.com/.well-known/openid-configuration"
TIMEOUT = (5, 10)


def titulo(t):
    print("\n" + "=" * 72 + f"\n{t}\n" + "=" * 72)


titulo("Descoberta OIDC do Google")
md = requests.get(DISCOVERY, timeout=TIMEOUT).json()
for k in ("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
          "code_challenge_methods_supported", "id_token_signing_alg_values_supported",
          "token_endpoint_auth_methods_supported"):
    print(f"{k:40} {md.get(k)}")

titulo("JWKS (chaves públicas de assinatura)")
jwks = requests.get(md["jwks_uri"], timeout=TIMEOUT).json()
for key in jwks["keys"]:
    print(f"kid={key['kid']}  kty={key['kty']}  use={key.get('use')}  alg={key.get('alg')}  "
          f"n={key['n'][:24]}…")

casos = [
    ("14a — /userinfo SEM token", {}),
    ("14b — /userinfo com token inválido/expirado", {"Authorization": "Bearer ya29.token-expirado-ou-invalido"}),
]
for nome, headers in casos:
    titulo(f"Teste negativo {nome}")
    r = requests.get(md["userinfo_endpoint"], headers=headers, timeout=TIMEOUT)
    print(f"HTTP {r.status_code}")
    print(f"WWW-Authenticate: {r.headers.get('WWW-Authenticate')}")
    try:
        print(json.dumps(r.json(), indent=2, ensure_ascii=False))
    except ValueError:
        print(r.text[:300])
    esperado = r.status_code == 401 and "Bearer" in (r.headers.get("WWW-Authenticate") or "")
    print("RESULTADO:", "OK — 401 + WWW-Authenticate: Bearer" if esperado else "INESPERADO")
