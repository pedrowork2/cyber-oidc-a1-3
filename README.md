# A1/3 — Cyber Security 33506
## OAuth 2.0 + OpenID Connect (Google)

Aplicação cliente (Relying Party) desenvolvida em **Python + Flask**, implementando autenticação com OAuth 2.0 e OpenID Connect (OIDC), utilizando o Google como OpenID Provider.

O projeto utiliza o fluxo **Authorization Code + PKCE (S256)**, validação de ID Token com RS256 e gerenciamento de sessões locais no servidor, vinculadas ao usuário pelo par `iss + sub`.

> A senha do usuário é digitada exclusivamente na página do Google. A aplicação não recebe, visualiza ou armazena essa senha.

---

## 1. Objetivos

- Implementar autenticação federada utilizando Google.
- Aplicar o fluxo Authorization Code com PKCE.
- Validar ID Tokens conforme os requisitos de segurança do OIDC.
- Implementar gerenciamento de sessões no servidor.
- Controlar permissões de acesso por perfil.
- Demonstrar mecanismos de proteção contra ataques relacionados à autenticação.

## 2. Tecnologias utilizadas

- Python 3.10+
- Flask
- OAuth 2.0
- OpenID Connect
- Google Identity
- PKCE (S256)
- RS256
- SQLite
- Pytest
- Postman

## 3. Pré-requisitos

- Python 3.10 ou superior.
- Conta Google.
- Credenciais OAuth 2.0 configuradas no Google Cloud Console.

## 4. Configuração do Google Cloud

1. Acesse https://console.cloud.google.com/.
2. Crie um projeto no Google Cloud.
3. Acesse **APIs e serviços → Tela de consentimento OAuth**.
4. Configure o tipo de usuário como Externo.
5. Informe o nome da aplicação e o e-mail de contato.
6. Adicione os e-mails do grupo como usuários de teste.
7. Acesse **APIs e serviços → Credenciais**.
8. Crie um ID do cliente OAuth do tipo Aplicativo da Web.
9. Configure a URI de redirecionamento:

```text
https://localhost:8443/callback
```

10. Copie o Client ID e o Client Secret.

## 5. Instalação e execução

Clone o repositório:

```bash
git clone https://github.com/pedrowork2/cyber-oidc-a1-3.git
cd cyber-oidc-a1-3
```

Crie e ative o ambiente virtual no Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Instale as dependências:

```powershell
pip install -r requirements.txt
```

Configure as variáveis de ambiente:

```powershell
copy .env.example .env
```

Edite o arquivo `.env` com as credenciais do Google.

Gere o certificado local:

```powershell
python scripts\gerar_certificado.py
```

Inicie a aplicação:

```powershell
python run.py
```

Acesse:

https://localhost:8443

Como o certificado é autoassinado, o navegador poderá apresentar um aviso de segurança. Utilize a opção Avançado e continue para localhost.

## 6. Variáveis de ambiente

| Variável | Descrição |
|---|---|
| `GOOGLE_CLIENT_ID` | Identificador do cliente OAuth |
| `GOOGLE_CLIENT_SECRET` | Segredo do cliente OAuth |
| `REDIRECT_URI` | URI de redirecionamento |
| `OIDC_DISCOVERY_URL` | URL de descoberta OIDC |
| `AUTO_PROVISION` | Permite criação automática de usuários |
| `ADMIN_SUBS` | Identificadores de usuários administradores |
| `ALLOWED_HD` | Restrição por domínio Google Workspace |
| `CLOCK_SKEW_SECONDS` | Tolerância de relógio para tokens |
| `SESSION_IDLE_TIMEOUT_MINUTES` | Tempo máximo de inatividade |
| `SESSION_ABSOLUTE_TIMEOUT_HOURS` | Tempo máximo absoluto da sessão |
| `RATE_LIMIT_PER_MINUTE` | Limite de requisições por minuto |
| `DEMO_MODE` | Habilita demonstrações de testes negativos |
| `HOST`, `PORT` | Configuração do servidor |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Arquivos do certificado TLS |
| `DATABASE_PATH` | Caminho do banco de dados |

**Segurança:** o arquivo `.env` contém informações sensíveis e não deve ser enviado ao GitHub. O Client Secret nunca deve ser versionado.

## 7. Funcionalidades

- Login utilizando conta Google.
- Fluxo Authorization Code com PKCE.
- Validação de ID Token com RS256.
- Descoberta de endpoints OIDC.
- Consulta e atualização de chaves JWKS.
- Gerenciamento de sessões server-side.
- Controle de acesso por perfil de usuário.
- Proteção de rotas administrativas.
- Limitação de requisições.
- Registro de eventos de auditoria.
- Endpoint protegido `/api/userinfo`.
- Demonstração de cenários negativos de segurança.

## 8. Gerenciamento de usuários

Para listar os usuários cadastrados:

```powershell
python scripts\gerenciar_usuarios.py listar
```

Para atribuir perfil de administrador:

```powershell
python scripts\gerenciar_usuarios.py role 1 admin
```

Também é possível configurar o identificador `sub` em `ADMIN_SUBS` no arquivo `.env`.

## 9. Testes automatizados

O projeto utiliza Pytest para verificar os mecanismos de autenticação e segurança.

Executar todos os testes:

```powershell
pytest -v
```

Executar os testes de validação do ID Token:

```powershell
pytest -v -s tests/test_id_token.py
```

Executar o teste de integração com os serviços reais do Google:

```powershell
python scripts\teste_userinfo_google.py
```

O projeto possui 69 testes automatizados, incluindo cenários de rejeição de tokens inválidos, divergência de parâmetros e controle de acesso.

## 10. Cenários de segurança avaliados

| Cenário | Proteção avaliada |
|---|---|
| `alg: none` | Rejeição de algoritmo não assinado |
| HS256 | Rejeição de algoritmo não autorizado |
| Audiência incorreta | Validação de `aud` |
| Emissor incorreto | Validação de `iss` |
| Token expirado | Validação de `exp` |
| Emissão futura | Validação de `iat` |
| Nonce divergente | Validação de `nonce` |
| State inválido | Proteção do fluxo de autenticação |
| Reutilização do code | Proteção contra replay |
| Verifier incorreto | Validação do PKCE |
| Redirect URI alterada | Validação do redirecionamento |
| Assinatura alterada | Verificação criptográfica |
| Acesso administrativo | Controle de permissões |
| Token ausente ou expirado | Proteção do endpoint de usuário |
| Força bruta | Rate limiting |

Os cenários que dependem de interação com o servidor de autorização real são demonstrados utilizando o Google no modo de demonstração.

## 11. Estrutura do projeto

```text
cyber-oidc-a1-3/
│
├── app/
│   ├── config.py
│   ├── oidc.py
│   ├── db.py
│   ├── security.py
│   ├── routes.py
│   └── templates/
│
├── scripts/
├── tests/
├── colecao/
├── evidencias/
│
├── .env.example
├── .gitignore
├── requirements.txt
├── README.md
└── run.py
```

## 12. Decisões de segurança

- Utilização exclusiva do algoritmo RS256 para validação de assinatura.
- Verificação explícita dos claims do ID Token.
- Utilização de JWKS com cache e suporte à rotação de chaves.
- Identificação do usuário pelo par `iss + sub`.
- Criação de sessões com identificadores gerados no servidor.
- Armazenamento do hash do identificador de sessão no banco.
- Rotação do identificador de sessão durante o login.
- Utilização de cookies com `HttpOnly`, `Secure` e `SameSite=Lax`.
- Descarte dos tokens do Google após o processamento do callback.
- Controle de expiração por inatividade e tempo absoluto.
- Proteção do endpoint `/api/userinfo` conforme RFC 6750.

## 13. Considerações finais

O projeto demonstra a aplicação prática de conceitos de segurança da informação, autenticação federada, autorização e gerenciamento de sessões.

A integração entre OAuth 2.0, OpenID Connect e PKCE permite implementar um processo de autenticação com mecanismos de proteção contra diferentes ameaças, além de possibilitar a avaliação dos controles por meio de testes automatizados.

**Disciplina:** Cyber Security 33506  
**Projeto:** A1/3 — Opção 2: Google