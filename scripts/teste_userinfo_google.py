"""Teste negativo 14: recurso protegido sem token / com token inválido.

Testa os dois endpoints de userinfo do Google e o servidor de recursos da
própria aplicação (/api/userinfo, RFC 6750). Também confere descoberta e JWKS.

Uso: python scripts/teste_userinfo_google.py   (com a aplicação rodando para o 3º alvo)
"""
import json
import os

import requests

DISCOVERY = "https://accounts.google.com/.well-known/openid-configuration"
APP = os.getenv("APP_URL", "https://localhost:8443")
CERT = os.getenv("TLS_CERT_FILE", "certs/localhost.crt")
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

alvos = [
    ("Google — userinfo da descoberta", md["userinfo_endpoint"], True),
    ("Google — oauth2/v3/userinfo", "https://www.googleapis.com/oauth2/v3/userinfo", True),
    ("Aplicação — /api/userinfo (RFC 6750)", f"{APP}/api/userinfo",
     CERT if os.path.exists(CERT) else True),
]
casos = [
    ("14a sem token", {}),
    ("14b token inválido/expirado", {"Authorization": "Bearer ya29.token-expirado-ou-invalido"}),
]

resumo = []
for nome_alvo, url, verify in alvos:
    for nome_caso, headers in casos:
        titulo(f"Teste {nome_caso} — {nome_alvo}\nGET {url}")
        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=verify)
        except requests.RequestException as exc:
            print(f"não foi possível conectar: {type(exc).__name__} (a aplicação está rodando?)")
            resumo.append((nome_caso, nome_alvo, "sem conexão"))
            continue
        www = r.headers.get("WWW-Authenticate")
        print(f"HTTP {r.status_code}")
        print(f"WWW-Authenticate: {www}")
        try:
            print(json.dumps(r.json(), indent=2, ensure_ascii=False))
        except ValueError:
            print(r.text[:300])
        ok401 = r.status_code == 401
        okhdr = bool(www) and www.lower().startswith("bearer")
        veredito = ("OK — 401 + WWW-Authenticate: Bearer" if ok401 and okhdr
                    else "401, mas SEM WWW-Authenticate (fora do RFC 6750 §3)" if ok401
                    else f"INESPERADO (HTTP {r.status_code})")
        print("RESULTADO:", veredito)
        resumo.append((nome_caso, nome_alvo, veredito))

titulo("Resumo do teste 14")
for caso, alvo, v in resumo:
    print(f"{caso:30} {alvo:40} {v}")
