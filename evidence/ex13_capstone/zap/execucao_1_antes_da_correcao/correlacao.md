# Correlação: findings do ZAP → OWASP → correção → teste

| Regra ZAP | Alerta | Risco | CWE | Ocorr. | Encontrado em | OWASP Top 10 | Controle no código | Teste | Status |
|---|---|---|---|---|---|---|---|---|---|
| 90004 | Cross-Origin-Embedder-Policy Header Missing or Invalid | Baixo | 693 | 1 | baseline_web_report | A05:2021 Security Misconfiguration | Cross-Origin-Opener/Resource-Policy — core/security_headers.py | `test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas` | ⚠️ **revisar** — o controle existe, mas o ZAP o viu falhar em alguma URL |
| 10049 | Non-Storable Content | Informativo | 524 | 18 | api_helena_report, api_recepcao_report, baseline_report, baseline_web_report | A05:2021 Security Misconfiguration | `Cache-Control: no-store` em respostas com dado de saúde — core/security_headers.py | `test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas` | ✅ **aceito** — é o EFEITO do `no-store` imposto de propósito (proxies/navegadores não devem armazenar dado de paciente) — confirma o controle de T-I3 |
| 10111 | Authentication Request Identified | Informativo | -1 | 3 | api_helena_report, api_recepcao_report, baseline_web_report | A07:2021 Identification and Authentication Failures | login protegido por rate limit, bcrypt e MFA — routes/users.py | `test_ex10_hardening::test_login_e_limitado_a_5_tentativas_por_janela` | ✅ **aceito** — apenas registra a existência de `POST /user/signin`, endpoint que deve existir |
| 10112 | Session Management Response Identified | Informativo | -1 | 1 | baseline_web_report | a classificar | — | `—` | 🔎 **finding novo** — classificar, corrigir ou aceitar com justificativa |
| 100000 | A Client Error response code was returned by the server | Informativo | 388 | 30 | api_helena_report, api_recepcao_report | A01:2021 Broken Access Control | RBAC, ownership, validação `extra='forbid'` — auth/rbac.py, auth/ownership.py | `test_ex06_authz / test_ex09_input_validation` | ✅ **aceito** — 4xx é o comportamento desejado: 403 = RBAC negando o perfil (T-E2); 422 = validação (T-T1/T-T2); 404 = ownership/inexistente (T-I2); 400 = invalid_scope (T-T4) |

## Controles comprovados pelo silêncio do ZAP

Regras que **rodaram** (`PASS` no log do scan) e **não** geraram alerta — a ausência é a evidência de que o controle funciona nas URLs varridas.

| Regra ZAP | OWASP | Controle verificado |
|---|---|---|
| 10020 | A05:2021 Security Misconfiguration | X-Frame-Options: DENY + CSP frame-ancestors — core/security_headers.py |
| 10021 | A05:2021 Security Misconfiguration | X-Content-Type-Options: nosniff — core/security_headers.py |
| 10035 | A05:2021 Security Misconfiguration | Strict-Transport-Security — core/security_headers.py |
| 10038 | A05:2021 Security Misconfiguration | Content-Security-Policy restritiva — core/security_headers.py |
| 10098 | A05:2021 Security Misconfiguration | CORS com allowlist explícita — main.py / core/config.py |
| 10010 | A05:2021 Security Misconfiguration | Cookie de sessão HttpOnly — routes/web.py |
| 10011 | A02:2021 Cryptographic Failures | Cookie Secure (obrigatório em produção) — core/config.py |
| 10054 | A01:2021 Broken Access Control | Cookie SameSite=Strict — routes/web.py |
| 10202 | A01:2021 Broken Access Control | Token CSRF (double-submit) — core/csrf.py |
| 10036 | A05:2021 Security Misconfiguration | uvicorn --no-server-header |
| 10037 | A05:2021 Security Misconfiguration | Sem X-Powered-By |
| 90022 | A05:2021 Security Misconfiguration | Handler de erros sem eco do input / sem stack trace — main.py |
| 10015 | A05:2021 Security Misconfiguration | Cache-Control: no-store em respostas com dados de saúde |
| 10063 | A05:2021 Security Misconfiguration | Permissions-Policy — core/security_headers.py |
