"""Inicia a aplicação em https://localhost:8443 (TLS obrigatório, enunciado 1.2)."""
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402
from app.config import Config  # noqa: E402

cfg = Config()
if not cfg.client_id or not cfg.client_secret or "troque" in cfg.client_secret:
    sys.exit("Configure GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET no arquivo .env (veja .env.example).")

cert = os.getenv("TLS_CERT_FILE", "certs/localhost.crt")
key = os.getenv("TLS_KEY_FILE", "certs/localhost.key")
if not (os.path.exists(cert) and os.path.exists(key)):
    sys.exit("Certificado TLS não encontrado. Rode: python scripts/gerar_certificado.py")

app = create_app(cfg)

if __name__ == "__main__":
    host, port = os.getenv("HOST", "localhost"), int(os.getenv("PORT", "8443"))
    print(f"Aplicação em https://{host}:{port}  (DEMO_MODE={cfg.demo_mode})")
    app.run(host=host, port=port, ssl_context=(cert, key), debug=False)
