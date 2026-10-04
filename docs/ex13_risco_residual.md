# Registro de risco residual e decisão de deploy (Exercício 13)

Riscos que **não foram totalmente eliminados** ao final do Assessment, com probabilidade (P) e impacto (I) de 1 (baixo) a 4 (crítico) e a decisão de aceitação.

| ID | Risco residual | P | I | Compensação existente | Decisão | Condição / ação |
|---|---|---|---|---|---|---|
| **R-01** | CPF, telefone e prontuário **em texto claro** no banco/backup (sem criptografia de coluna) | 1 | 4 | API devolve CPF mascarado; acesso ao banco só pela aplicação; hash/segredos protegidos | **Aceito com condição** | Banco e *backups* **criptografados em repouso** + acesso restrito e auditado. **Sem isso → BLOQUEIA o deploy.** Próximo ciclo: criptografia de coluna com chave em KMS. |
| R-02 | Rate limit **em memória** do processo | 2 | 3 | 3 baldes; bcrypt; MFA admin | Aceito (1 réplica) | Com N réplicas o limite efetivo é N×: mover contadores para Redis/gateway **antes** de escalar. |
| R-03 | JWT HS256 com segredo compartilhado; **sem revogação individual** nem rotação (`kid`) | 2 | 3 | TTL 30 min; `get_current_user` consulta o banco (desativar conta corta acesso na hora) | Aceito | Roadmap: RS256/EdDSA + JWKS + rotação; *denylist* por `jti` se exigirem logout imediato. |
| R-04 | **Bloqueio por botnet**: 15 tentativas/min em várias origens travam o login de uma conta | 2 | 2 | Chave composta conta+IP impede bloqueio por **um** atacante (testado) | Aceito | Monitorar `rate_limit` na auditoria; CAPTCHA/step-up se ocorrer. |
| R-05 | MFA **simulado**: sem QR Code, *backup codes*, recuperação; TOTP é phishável | 2 | 3 | Só `admin`; anti-replay; segredo derivado fora do banco | Aceito | Evoluir para WebAuthn/IdP (Keycloak, aula 15). |
| R-06 | Trilha de auditoria **em stdout**, não imutável | 2 | 3 | JSON estruturado; sem segredos/PHI | Aceito com condição | Enviar a SIEM/armazenamento WORM no go-live. |
| R-07 | Cliente M2M autenticado por **segredo compartilhado** (sem mTLS/`private_key_jwt`, sem allowlist de IP) | 2 | 2 | Escopo mínimo (só horários), TTL 10 min, segredo só como hash, limite e auditoria | Aceito | Exigir mTLS/IP allowlist no contrato de renovação. |
| R-08 | **Sem limite de tamanho de corpo** no app | 2 | 2 | Validação por campo (`max_length`); paginação | Aceito com condição | `client_max_body_size` (ex.: 256 KB) no proxy. |
| R-09 | **SQLite em arquivo** (concorrência, HA, *backup*) | 2 | 3 | Camada configurável via `DATABASE_URL` | Aceito (piloto, 1 nó) | PostgreSQL + migrações Alembic para produção multi-nó. |
| R-10 | Whitelist rejeita caracteres legítimos (`<`, `&`, dígitos em nomes) | 3 | 1 | Mensagem de erro clara | Aceito | Revisar com a equipe clínica; ajustar regex. |
| R-11 | **ZAP rodou só em máquina de desenvolvimento** (passivo, 4 scans; 0 bloqueantes) e **IAST** não foi executado | 2 | 3 | Pipeline com `dast-passive`; 197 testes cobrem a lógica que o DAST passivo não vê | Aceito com condição | Repetir o `dast-passive` contra o ambiente de destino (staging) antes do go-live; **zero alertas bloqueantes**. |
| R-12 | **IAST** não implantado | 2 | 2 | Testes de autorização + ZAP autenticado | Aceito | Avaliar agente IAST em QA. |
| R-13 | CVEs futuras em dependências | 3 | 3 | pip-audit/Trivy no PR **e** semanal | Aceito | Responder a alertas do gate em até 7 dias (HIGH/CRITICAL). |
| R-14 | Datas de consulta são **horário local do servidor** (sem fuso: `NaiveDatetime`) | 2 | 1 | Validação de futuro e de bloco de 30 min; uma clínica, um fuso | Aceito | Fixar `TZ` do processo/contêiner; guardar fuso por unidade se houver clínicas em fusos diferentes. |

## Decisão

**GO condicional.** Nenhum risco acima, isoladamente, justifica bloquear a liberação — todos têm compensação ativa e plano de evolução — **desde que as 7 condições abaixo estejam satisfeitas**. A falha de qualquer uma muda a decisão para **NO-GO**.

1. ZAP (já executado localmente: 0 bloqueantes) **repetido no job `dast-passive` contra o ambiente de destino**, sem alertas bloqueantes (R-11).
2. TLS no proxy com HSTS; `APP_ENV=production` (exige `COOKIE_SECURE=true`, `ENABLE_DOCS=false`, bcrypt ≥ 12).
3. Segredos (`JWT_SECRET_KEY`, `MFA_MASTER_KEY`, hash do M2M) em *secret manager*, rotacionados e fora do repositório.
4. Banco e *backups* criptografados em repouso (R-01).
5. Auditoria enviada a SIEM/WORM (R-06).
6. Uma réplica **ou** rate limit no gateway/Redis (R-02).
7. `client_max_body_size` no proxy; PostgreSQL e migrações se houver mais de um nó (R-08, R-09).

**O risco que mais pesa é o R-01**, porque o dado é de saúde: sua aceitação é **a única que depende de uma condição de plataforma** (criptografia em repouso), e é a que eu transformaria em item bloqueante caso a plataforma de destino não a ofereça.
