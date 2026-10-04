# Threat Model — API de Agendamento Clínico (Exercícios 4 e 5)

Referência oficial para correções (Ex. 9) e estratégia de testes (Ex. 12/13). Os IDs de ameaça (`T-xx`) são os mesmos de `tests/threat_matrix.py` e `docs/matriz_ameaca_teste.md`: **cada ameaça aponta para um controle e para testes que rodam no CI**.

## 1. Escopo, ativos e atores

**Sistema.** API FastAPI com recursos *pacientes*, *profissionais* e *consultas*; 3 clientes (frontend JSON, página HTML da recepção, laboratório M2M); 3 papéis (admin, recepcionista, profissional). Diagrama: `evidence/ex03_ex05_diagramas/dfd_nivel1.png`.

### Ativos (o que protegemos)

| ID | Ativo | Classificação | Por que importa |
|---|---|---|---|
| A1 | Prontuário (`notes`) e histórico de consultas | **Dado de saúde sensível** (LGPD art. 11) | vazamento = incidente notificável (art. 48), dano ao titular |
| A2 | Identificação do paciente (nome, CPF, telefone, e-mail) | Dado pessoal | CPF é identificador forte (fraude) |
| A3 | Credenciais: hash bcrypt, semente MFA, segredo JWT, `client_secret` do laboratório | Segredo | comprometem **todos** os demais ativos |
| A4 | Integridade da agenda (horários, status) | Operacional | consulta alterada/cancelada indevidamente afeta o atendimento |
| A5 | Disponibilidade do agendamento e da integração | Operacional | clínica depende da agenda em horário comercial |
| A6 | Trilha de auditoria | Evidência | repúdio, resposta a incidente |

### Atores (aula 9, etapa 3)

| Ator | Motivação / capacidade |
|---|---|
| Visitante anônimo / bot | automatizado; enumeração, força bruta, scanners |
| Usuário legítimo mal-intencionado (profissional curioso, funcionário insatisfeito) | autenticado; conhece a API; tenta ver/alterar o que não é seu |
| Atacante com credencial roubada (phishing, reuso de senha) | passa por login legítimo; busca escalar |
| Atacante com token do laboratório | tem o `Bearer` m2m; tenta expandir o alcance |
| Desenvolvedor descuidado | cria endpoint novo sem proteger |
| Administrador comprometido | maior privilégio; mitigado por MFA |

## 2. Superfície de ataque

| # | Superfície | Entradas controladas pelo atacante | Autenticação exigida |
|---|---|---|---|
| S1 | `POST /user/signin`, `/user/mfa/verify` | usuário, senha, código TOTP | nenhuma (públicas) → rate limit |
| S2 | `POST /oauth/token` | `client_id`, `client_secret`, `scope` | nenhuma (pública) → rate limit |
| S3 | `/user/*` administrativas | corpo JSON, `user_id` | JWT + papel admin |
| S4 | `/patient/*` | corpo JSON, `patient_id`, `?name=` (busca) | JWT + papel + ownership |
| S5 | `/appointment/*` | corpo JSON (`reason`, `notes`, datas), `appointment_id`, filtros | JWT + papel + ownership |
| S6 | `/web/login`, `/web/agenda` | formulário, `?day=`, cookie | credencial / cookie de sessão |
| S7 | `/availability/` | `professional_id`, `day` | token m2m + escopo |
| S8 | Cabeçalhos HTTP (`Authorization`, `Origin`, `Cookie`) | todos | — |
| S9 | `.env`, dependências, pipeline | segredos, pacotes, Actions | cadeia de suprimentos |
| S10 | `/docs`, `/openapi.json` | leitura | públicas só fora de produção |

## 3. Misuse cases (formato da aula 8)

| ID | Misuse case | Ator | Objetivo | Caminho do atacante | Resposta do sistema (mitigação) | Ameaças |
|---|---|---|---|---|---|---|
| MU-01 | **Ler prontuário alheio** | Profissional curioso | A1/A2 de outro profissional | autentica-se, troca `appointment_id`/`patient_id` na URL | `get_*_or_404` filtra por dono no SQL → 404; audita `object_access_denied` | T-I2, T-T2 |
| MU-02 | **Virar administrador** | Visitante | controle total | `POST /user/signup` com `"role":"admin"` | cadastro só por admin; `extra='forbid'`; `role` é Enum | T-T1, T-E2 |
| MU-03 | **Força bruta / credential stuffing** | Bot | tomar conta de usuário | milhares de senhas em `/user/signin` | 5/min por conta+IP, 20/min por IP, 15/min por conta; bcrypt; MFA admin | T-S2, T-D1 |
| MU-04 | **XSS armazenado na agenda** | Usuário mal-intencionado | roubar sessão da recepção | grava `<script>` em `reason`/nome; recepção abre a agenda | whitelist na entrada, autoescape na saída, CSP sem script, cookie HttpOnly | T-T3, T-E3 |
| MU-05 | **SQL injection na busca** | Autenticado | dump da base de pacientes | `?name=' OR '1'='1` | whitelist + `select().where()` parametrizado + `LIKE` com autoescape | T-T5 |
| MU-06 | **Abuso do token do laboratório** | Atacante com token m2m | ler dados de pacientes / ampliar escopo | usa o `Bearer` em `/patient/` ou pede `patients:read` | `token_use` ≠ `access` → 403; `invalid_scope`; TTL 10 min; só horários livres | T-I4, T-T4, T-E4, T-S5 |
| MU-07 | **Endpoint novo sem proteção** | Dev descuidado | exposição acidental | cria rota e esquece a dependência de auth | middleware deny-by-default; teste percorre todas as rotas | T-X1 |
| MU-08 | **Conta admin sem 2º fator** | Atacante com senha roubada | acesso administrativo | login só com a senha do admin | `signin` do admin devolve só `mfa_token` (inútil na API); TOTP com anti-replay | T-E1 |
| MU-09 | **"Eu não cancelei"** | Usuário | negar autoria | cancela/altera e depois nega | eventos `appointment_*` com `actor_id`; login/negações auditados | T-R1, T-R2 |

## 4. STRIDE por componente

Legenda do status: ✅ mitigado e testado · ◐ mitigado com residual documentado.

### C1 — Autenticação (`/user/signin`, `/user/mfa/verify`, `/web/login`)

| STRIDE | ID | Ameaça | Mitigação | Teste | Status |
|---|---|---|---|---|---|
| **S** Spoofing | T-S1 | JWT forjado/adulterado/expirado/`alg=none`/outra audiência | HS256 fixo; `iss/aud/exp/nbf/jti` obrigatórios; segredo ≥ 32 chars no `.env`; papel conferido no banco | `test_ex06` (5 testes) | ✅ |
| S | T-S2 | Força bruta, credential stuffing | rate limit 3 baldes; bcrypt custo 12; MFA admin | `test_ex10`, `test_ex12` | ◐ R-02 |
| **T** Tampering | T-T1 | Mass assignment de `role` no cadastro | cadastro só admin; `extra='forbid'`; Enum | `test_ex09`, `test_ex06` | ✅ |
| **R** Repudiation | T-R1 | Falhas de login/negações sem registro | `audit()` JSON (sem senha/token) | `test_ex12` | ◐ R-06 |
| **I** Info disclosure | T-I1 | Enumeração de usuários (mensagem e tempo) | mensagem genérica; `burn_cpu` com hash "dummy" | `test_ex06`, `test_ex13` | ✅ |
| **D** DoS | T-D1 | Inundação de tentativas | rate limit; validação antes do bcrypt | `test_ex10`, `test_ex13` | ◐ R-02, R-04 |
| **E** Elevation | T-E1 | `mfa_token` usado como sessão; replay do TOTP | `token_use` no middleware; `mfa_last_step` | `test_ex06` | ✅ |

### C2 — Consultas (`/appointment/*`)

| STRIDE | ID | Ameaça | Mitigação | Teste | Status |
|---|---|---|---|---|---|
| S | T-S3 | Falsificar o dono (`professional_id` no corpo) | campo não existe no schema; vem do token | `test_ex09`, `test_ex01` | ✅ |
| T | T-T2 | BOLA em PUT/DELETE; mass assignment de `status`/IDs | ownership no `WHERE`; `AppointmentUpdate` sem campos de posse | `test_ex09` | ✅ |
| R | T-R2 | Alteração/cancelamento sem rastro | `appointment_updated/cancelled` com `actor_id`; cancelamento lógico | `test_ex12` | ◐ R-06 |
| I | T-I2 | BOLA de leitura; campos internos de auditoria | ownership + `AppointmentPublic` (whitelist) | `test_ex06`, `test_ex02` | ✅ |
| D | T-D2 | Listagem sem limite | `limit ≤ 100`, `offset ≥ 0`; rate limit | `test_ex12` | ◐ R-08 |
| E | T-E2 | Perfil fora do papel (recepção cria consulta) | `require_roles(profissional)` | `test_ex06` | ✅ |

### C3 — Página da recepção (`/web/*`)

| STRIDE | ID | Ameaça | Mitigação | Teste | Status |
|---|---|---|---|---|---|
| S | T-S4 | CSRF em login/logout | token CSRF double-submit; `SameSite=Strict` | `test_ex02`, `test_ex12` | ✅ |
| T | T-T3 | **XSS armazenado** | whitelist + autoescape + CSP `default-src 'none'` | `test_ex02`, `test_ex09` | ✅ |
| I | T-I3 | Dado de saúde em excesso na página/cache | `AgendaItem` (sem CPF/telefone/notas); `no-store` | `test_ex02`, `test_ex10` | ✅ |
| E | T-E3 | Roubo de sessão pelo cookie | `HttpOnly; SameSite=Strict; Secure` (produção) | `test_ex02` | ✅ |

### C4 — Integração do laboratório (`/oauth/token`, `/availability/`)

| STRIDE | ID | Ameaça | Mitigação | Teste | Status |
|---|---|---|---|---|---|
| S | T-S5 | Personificar o cliente M2M | `client_secret` só como hash bcrypt; rate limit; auditoria | `test_ex07` | ◐ R-07 |
| T | T-T4 | Ampliar escopo no pedido | `requested ⊆ allowed` senão `invalid_scope` | `test_ex07` | ✅ |
| I | T-I4 | Laboratório lê dados de pacientes | `AvailabilityResponse` só tem horários | `test_ex07` | ✅ |
| E | T-E4 | Token m2m em rota de usuário (e vice-versa) | `get_current_user` exige `access`; `require_scopes` exige `m2m` | `test_ex07` | ✅ |

### C5 — Persistência (SQLModel)

| STRIDE | ID | Ameaça | Mitigação | Teste | Status |
|---|---|---|---|---|---|
| T | T-T5 | **SQL injection** | `select().where()` parametrizado; whitelist | `test_ex09`, `test_ex11` | ✅ |
| I | T-I5 | Credenciais no código; dump do banco | `.env` + `BaseSettings` sem default; hash bcrypt; semente MFA inútil sem `MFA_MASTER_KEY` | `test_ex11`, `test_ex02` | ◐ R-01 |
| D | — | Banco em arquivo único | PostgreSQL via `DATABASE_URL` | — | ◐ R-09 |

### Transversais

| ID | Ameaça | Mitigação | Teste |
|---|---|---|---|
| T-X1 | Endpoint novo esquecido sem autenticação | `JWTAuthMiddleware` deny-by-default | `test_ex12::test_deny_by_default_em_todas_as_rotas` |
| T-X2 | CORS permissivo / sem headers | allowlist; headers em todas as respostas | `test_ex10` |

## 5. Priorização com DREAD (escala 0–10 da aula 9; estado **antes** das correções)

| ID | Ameaça | D | R | E | A | D | Média |
|---|---|---|---|---|---|---|---|
| T-T1 | Mass assignment de `role` | 10 | 10 | 9 | 10 | 7 | **9,2** |
| T-S1 | JWT forjado (segredo no repositório) | 10 | 10 | 8 | 10 | 6 | **8,8** |
| T-I2 | BOLA de leitura | 8 | 10 | 9 | 7 | 8 | **8,4** |
| T-T2 | BOLA de escrita | 8 | 10 | 9 | 6 | 7 | **8,0** |
| T-T5 | SQL injection | 9 | 9 | 7 | 8 | 6 | **7,8** |
| T-D2 | Listagem/inundação sem limite | 5 | 9 | 8 | 9 | 8 | **7,8** |
| T-S2 | Força bruta no login | 7 | 9 | 6 | 5 | 9 | **7,2** |
| T-T3 | XSS armazenado | 6 | 8 | 6 | 6 | 7 | **6,6** |
| T-X2 | CORS curinga / sem headers | 4 | 9 | 5 | 4 | 7 | **5,8** |

*(D = Dano, R = Reprodutibilidade, E = Explorabilidade, A = Afetados, D = Descoberta.)* A ordem coincide em geral com a priorização por CVSS + impacto de negócio de `docs/cvss_priorizacao.md`; a diferença instrutiva é BOLA, que o DREAD já coloca no topo (A = usuários afetados e D alta) enquanto o CVSS a subestima.

## 6. Árvore de ataque (aula 9) — objetivo: *ler o prontuário de um paciente que não é meu*

```
[RAIZ] Ler prontuário (A1) de paciente de outro profissional
├─ 1. Obter credencial de quem tem acesso
│   ├─ 1.1 Força bruta / credential stuffing ............ MITIGADO: rate limit 3 baldes, bcrypt   (T-S2)
│   ├─ 1.2 Roubar sessão da recepção (XSS) .............. MITIGADO: whitelist+autoescape+CSP+HttpOnly (T-T3, T-E3)
│   └─ 1.3 Forjar JWT ................................... MITIGADO: segredo no .env, HS256 fixo, aud/iss  (T-S1)
├─ 2. Contornar a autorização
│   ├─ 2.1 Trocar o ID na URL (BOLA) .................... MITIGADO: ownership no WHERE → 404          (T-I2, T-T2)
│   ├─ 2.2 Virar admin (mass assignment) ................ MITIGADO: signup só admin, extra=forbid      (T-T1)
│   └─ 2.3 Usar token do laboratório em rota de usuário . MITIGADO: token_use + escopo                (T-E4)
├─ 3. Contornar a aplicação
│   ├─ 3.1 SQL injection ................................ MITIGADO: parametrização + whitelist        (T-T5)
│   └─ 3.2 Endpoint novo sem proteção ................... MITIGADO: deny-by-default + teste de varredura (T-X1)
└─ 4. Ir direto ao dado
    ├─ 4.1 Dump do banco / backup ....................... RESIDUAL: CPF/prontuário sem criptografia de coluna (R-01)
    └─ 4.2 Segredo no repositório/CI .................... MITIGADO: .env, Trivy secret, Actions por SHA   (T-I5)
```

## 7. Vetores de ataque por eixo de segurança de API (Exercício 5)

### Eixo 1 — Design

| Vetor | Como seria explorado | Mitigação de design | Status |
|---|---|---|---|
| Autorização só por papel | dois profissionais, mesmo papel, ID livre (BOLA) | papel **e** dono, fonte única | ✅ |
| Token de máquina com poder de usuário | `Bearer` do laboratório em rota interna | `token_use` + escopos; laboratório só vê horários | ✅ |
| Operação sem dono explícito | "listar todas as consultas" para qualquer papel | cada visão devolve apenas o permitido; recepção sem prontuário | ✅ |
| Enumeração de IDs | 403 × 404 revela que o ID existe | 404 uniforme (e auditoria interna) | ✅ |
| Fluxo de negócio abusável (API6) | travar horários da agenda em massa | só profissional agenda para paciente próprio; rate limit | ◐ |

### Eixo 2 — Implementação

| Vetor | Mitigação | Status |
|---|---|---|
| SQL injection / XSS / SSTI | parametrização; whitelist; autoescape; `{{7*7}}` rejeitado na entrada | ✅ |
| Mass assignment | `extra='forbid'`; campos de posse fora do schema | ✅ |
| JWT: `alg=none`, troca de algoritmo, sem `exp`, audiência errada | `algorithms=["HS256"]`; claims obrigatórias | ✅ |
| Erro que vaza entrada (senha em 422) | handler remove `input` | ✅ |
| Timing de login revela usuários | hash "dummy" em usuário inexistente | ✅ |
| CSRF | token double-submit + SameSite | ✅ |
| Bloqueio do *event loop* (DoS por consulta lenta) | rotas `def` (threadpool) | ✅ |

### Eixo 3 — Infraestrutura

| Vetor | Mitigação | Status |
|---|---|---|
| CORS curinga / origem não confiável | allowlist; `Settings` recusa `*` | ✅ |
| Sem HSTS/XFO/XCTO/CSP | middleware mais externo | ✅ |
| Força bruta / inundação | rate limit 3 baldes + padrão | ◐ R-02 |
| Segredo no código/repositório/CI | `.env`, `SecretStr`, Trivy, `.gitignore`, ZIP sem `.env` | ✅ |
| Dependência vulnerável | versões atuais, pip-audit, Trivy, execução semanal | ✅ |
| Documentação exposta em produção | `ENABLE_DOCS=false` obrigatório por validador | ✅ |
| Sem TLS / corpo gigante | TLS e `client_max_body_size` no proxy (condições do deploy) | ◐ R-08 |
