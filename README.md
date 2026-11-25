# A1/3 — Cyber Security 33506 · OAuth 2.0 + OpenID Connect (Opção 2: Google)

Aplicação cliente (Relying Party) em **Python + Flask** que implementa o fluxo
**Authorization Code + PKCE (S256)** com o **Google** como OpenID Provider, valida o
**ID Token** (RS256) com o checklist do item 4.3 e cria uma **sessão local server-side**
vinculada ao usuário pelo par **iss + sub**.

> A senha do usuário é digitada só na página do Google. Esta aplicação nunca a recebe, vê ou armazena.

---

## 1. Pré-requisitos

- Python 3.10 ou mais recente
- Uma conta Google para criar o OAuth client ID

## 2. Configurar o Google Cloud Console

1. Acesse <https://console.cloud.google.com/> e crie um projeto (ex.: `cyber-33506`).
2. **APIs e serviços → Tela de consentimento OAuth**: tipo *Externo*, preencha o nome do app e o e-mail.
   Em *Usuários de teste*, adicione os e-mails do grupo.
3. **APIs e serviços → Credenciais → Criar credenciais → ID do cliente OAuth**
   - Tipo: **Aplicativo da Web**
   - *URIs de redirecionamento autorizados*: `https://localhost:8443/callback` (exatamente assim, sem barra final)
4. Copie o **Client ID** e o **Client secret**.

## 3. Instalar e executar

```powershell
# Windows (PowerShell) — no Linux/macOS use "source .venv/bin/activate"
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env        # depois edite .env com o Client ID e o Client secret
python scripts\gerar_certificado.py
python run.py
```

Abra <https://localhost:8443>. Como o certificado é autoassinado, o navegador mostra um aviso:
clique em *Avançado → Continuar para localhost*.

### Tornar um usuário admin

```powershell
python scripts\gerenciar_usuarios.py listar
python scripts\gerenciar_usuarios.py role 1 admin
```

Outra forma: coloque o `sub` em `ADMIN_SUBS` no `.env` antes do primeiro login.

## 4. Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|---|---|
| `GOOGLE_CLIENT_ID` | sim | Client ID do OAuth client |
| `GOOGLE_CLIENT_SECRET` | sim | Client secret (**nunca versionar**) |
| `REDIRECT_URI` | sim | `https://localhost:8443/callback`, idêntica à cadastrada |
| `OIDC_DISCOVERY_URL` | não | Padrão: descoberta do Google |
| `AUTO_PROVISION` | não | `true`: cria o usuário com `role=user` no 1º login; `false`: recusa quem não estiver cadastrado |
| `ADMIN_SUBS` | não | `sub`s que recebem `role=admin` ao serem criados |
| `ALLOWED_HD` | não | Restringe o login a um domínio Workspace pelo claim `hd` (ponto extra) |
| `CLOCK_SKEW_SECONDS` | não | Tolerância de relógio para `exp`/`iat` (padrão 120) |
| `SESSION_IDLE_TIMEOUT_MINUTES` | não | Expiração por inatividade (padrão 30) |
| `SESSION_ABSOLUTE_TIMEOUT_HOURS` | não | Expiração absoluta (padrão 8) |
| `RATE_LIMIT_PER_MINUTE` | não | Limite por IP em `/login` e `/callback` (padrão 10) |
| `DEMO_MODE` | não | `true` habilita `/demo` com os testes negativos 7, 9, 10 e 11 ao vivo |
| `HOST`, `PORT`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `DATABASE_PATH` | não | Servidor e arquivos locais |

## 5. Testes

```powershell
pytest -v                                   # todos os 69 testes (sem rede)
pytest -v -s tests/test_id_token.py         # testes negativos do ID Token, mostrando o motivo da rejeição
python scripts\teste_userinfo_google.py     # teste 14 contra o Google real + descoberta + JWKS
```

### Mapa dos testes negativos (item 5)

| # | Cenário | Como demonstrar |
|---|---|---|
| 1 | `alg: none` | `test_01_alg_none_rejeitado` |
| 2 | HS256 reassinado com a chave pública | `test_02_hs256_reassinado_com_chave_publica_rejeitado` |
| 3 | `aud` de outro client_id | `test_03_aud_de_outro_client_id_rejeitado` |
| 4 | `iss` diferente | `test_04_iss_diferente_rejeitado` |
| 5 | `exp` vencido | `test_05_exp_vencido_rejeitado` |
| 6 | `iat` no futuro | `test_06_iat_no_futuro_rejeitado` |
| 7 | `nonce` diferente | `test_07_nonce_diferente_rejeitado` e `/demo` → *nonce errado* (Google real) |
| 8 | `state` divergente/ausente | `test_08_*`: aborta **antes** de chamar o token_endpoint |
| 9 | Reuso do code | `/demo` → *reuso do code*: o Google responde `invalid_grant` e a app testa se o access token foi revogado |
| 10 | `code_verifier` incorreto | `/demo` → *verifier errado*: o Google responde `invalid_grant` |
| 11 | `redirect_uri` alterada | `/demo` → barra final, parâmetro extra, subcaminho: o Google mostra `redirect_uri_mismatch` e não redireciona |
| 12 | 1 byte alterado na assinatura | `test_12_um_byte_alterado_na_assinatura_rejeitado` |
| 13 | `/admin` com `role=user` | `test_13_admin_com_role_user_retorna_403` e no navegador |
| 14 | `/userinfo` sem token/expirado | `test_14*` e `scripts/teste_userinfo_google.py`: o Google responde 401 mas **sem** `WWW-Authenticate`; o servidor de recursos da app (`/api/userinfo`) responde 401 + `WWW-Authenticate: Bearer` (RFC 6750) |
| 15 | Força bruta | O formulário de senha é do Google, que aplica a própria proteção. Na app: `test_15_rate_limiting_no_login` (HTTP 429) |

Os testes 9, 10 e 11 dependem do servidor de autorização. Na Opção 2 esse servidor é o Google,
por isso eles são demonstrados contra o Google real, no modo demo.

## 6. Estrutura

```
app/
  config.py      variáveis de ambiente
  oidc.py        PKCE, descoberta, JWKS (cache e rotação), /token, /userinfo, validate_id_token()
  db.py          tabela users (4.1), sessões server-side, auditoria
  security.py    sessão (cookie __Host-sid), rate limiting, login_required/role_required
  routes.py      /login, /callback, /perfil, /admin, /logout, /demo, /api/userinfo (Bearer)
  templates/     páginas renderizadas no servidor (sem JavaScript)
scripts/         gerar_certificado.py, gerenciar_usuarios.py, teste_userinfo_google.py
tests/           69 testes pytest (Google simulado com par de chaves RSA próprio)
colecao/         coleção do Postman
```

## 7. Decisões de projeto

- **Algoritmo**: só RS256 está na lista fixa `ALLOWED_ALGS`. O `alg` do cabeçalho só é comparado
  com essa lista: a função de verificação vem do mapeamento interno, nunca do token (RFC 8725 §3.1).
  `none`, HS256 e RS512 são rejeitados antes de qualquer operação criptográfica.
- **Verificação manual com `cryptography`**: cada item do checklist aparece explicitamente no código
  e no log, em vez de ficar escondido dentro de uma biblioteca de JWT.
- **JWKS**: cache de 1 h. Um `kid` desconhecido força uma recarga (rotação de chave), com intervalo
  mínimo de 60 s, para que kids aleatórios não virem um vetor de DoS.
- **Vínculo**: `iss + sub`. O e-mail só preenche `user_name` quando `email_verified = true`.
  Se o mesmo e-mail aparecer com outro `sub` (e-mail reciclado), é criada outra conta.
- **Usuário inexistente**: com `AUTO_PROVISION=true`, o registro é criado só com dados validados,
  `role=user` e exigindo `email_verified=true`. Com `false`, o login é recusado (HTTP 403).
- **Sessão**: sessionID de 256 bits gerado pelo servidor e diferente do JWT e do access token.
  No banco fica só o SHA-256 do ID. O cookie `__Host-sid` usa HttpOnly, Secure, SameSite=Lax e Path=/.
  O ID é rotacionado no login. Expiração: 30 min por inatividade e 8 h absoluta.
- **Tokens do Google**: usados uma vez no callback e descartados. Nada é persistido, e o access token,
  que é opaco, nunca é decodificado.
- **Tempo de vida**: o ID Token do Google vale cerca de 1 h, mas só é usado no instante do login;
  a duração da sessão é controlada pela própria aplicação.
- **Servidor de recursos**: `/api/userinfo` aceita o access token do Google só se o `tokeninfo` confirmar que ele foi emitido para este client_id e ainda vale; erros seguem o RFC 6750 (`WWW-Authenticate: Bearer`, `invalid_token`, `invalid_request`).
- **Logs**: `logs/app.log` registra as três partes decodificadas do ID Token, como pede o passo 7.
  Access token e client secret nunca vão para o log.
