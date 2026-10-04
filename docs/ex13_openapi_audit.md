# Auditoria da especificação OpenAPI (Exercício 13)

Spec: `API de Agendamento Clínico` v1.0.0 · OpenAPI 3.1.0 · 20 operações em 18 caminhos.
Gerado por `python scripts/audit_openapi.py --write`.

| Check | Resultado | Observação |
|---|---|---|
| O-01 | ✅ PASS | 15 de 20 operações exigem autenticação; públicas = ['GET /', 'GET /health', 'POST /oauth/token', 'POST /user/mfa/verify', 'POST /user/signin'] |
| O-02 | ✅ PASS | todos os corpos JSON declaram `additionalProperties: false` (extra='forbid') |
| O-03 | ✅ PASS | toda string de entrada JSON tem pattern, maxLength, enum ou format |
| O-04 | ✅ PASS | IDs têm mínimo (>0) e `limit` tem máximo (paginação limitada) |
| O-05 | ✅ PASS | todas as respostas 2xx têm schema definido (response_model) |
| O-06 | ✅ PASS | nenhum campo interno (hash, semente MFA, auditoria) aparece em schema de resposta |
| O-07 | ✅ PASS | operações protegidas documentam 401 e 429 (e 403/404 onde aplicável) |
| O-08 | ✅ PASS | esquemas: ['LabClientCredentials', 'OAuth2PasswordBearer']; fluxos: ['clientCredentials', 'password']; escopos M2M: ['availability:read']; credencial em query string: False |
| O-09 | ℹ️ INFO | spec não declara `servers`; em produção publicar apenas https:// (TLS e HSTS no proxy) |
| O-10 | ✅ PASS | campos de formulário limitados |
| O-11 | ✅ PASS | PUT/PATCH/DELETE existem apenas sobre recurso identificado; sem TRACE |
| O-12 | ✅ PASS | operationIds únicos e todas as operações com tag |
