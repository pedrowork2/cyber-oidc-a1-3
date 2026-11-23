"""Administração da tabela local de usuários.

  python scripts/gerenciar_usuarios.py listar
  python scripts/gerenciar_usuarios.py role <id> admin|user
  python scripts/gerenciar_usuarios.py cadastrar --sub <sub> --user-name <email> [--nome "Nome"] [--role admin]

"cadastrar" serve para o modo AUTO_PROVISION=false (pré-cadastro pelo sub).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv  # noqa: E402

load_dotenv()
from app.db import Database  # noqa: E402

GOOGLE_ISS = "https://accounts.google.com"

p = argparse.ArgumentParser()
sp = p.add_subparsers(dest="cmd", required=True)
sp.add_parser("listar")
r = sp.add_parser("role")
r.add_argument("id", type=int)
r.add_argument("role", choices=["admin", "user"])
c = sp.add_parser("cadastrar")
c.add_argument("--sub", required=True)
c.add_argument("--user-name", required=True)
c.add_argument("--nome")
c.add_argument("--role", choices=["admin", "user"], default="user")
args = p.parse_args()

db = Database(os.getenv("DATABASE_PATH", "app.db"))
if args.cmd == "listar":
    print(f"{'id':>3}  {'role':<5}  {'oidc_sub':<24}  user_name")
    for u in db.list_users():
        print(f"{u['id']:>3}  {u['role']:<5}  {u['oidc_sub']:<24}  {u['user_name']}")
elif args.cmd == "role":
    if db.get_user(args.id) is None:
        sys.exit("usuário não encontrado")
    db.set_role(args.id, args.role)
    db.audit("role_alterado", f"id={args.id} role={args.role}")
    print(f"usuário {args.id} agora tem role={args.role} (vale na próxima requisição)")
else:
    uid = db.create_user(iss=GOOGLE_ISS, sub=args.sub, user_name=args.user_name,
                         full_name=args.nome, role=args.role)
    print(f"cadastrado id={uid}")
