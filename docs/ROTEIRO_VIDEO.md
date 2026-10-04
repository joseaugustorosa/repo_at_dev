# Roteiro do vídeo (máx. 5 min) — Assessment DR2

> O vídeo é a evidência de autoria: **fale com as suas palavras**, mostre o código rodando. Abaixo está a estrutura e os pontos que não podem faltar — não um texto para ler. Treine uma vez com o cronômetro.

## Preparação (antes de gravar)

1. `source .venv/bin/activate && python scripts/bootstrap_env.py && python scripts/seed_demo.py` (se ainda não fez).
2. Dois terminais lado a lado: (A) `uvicorn main:app --no-server-header`; (B) para comandos.
3. Abas prontas: `http://127.0.0.1:8000/docs`, `evidence/ex08_ex09_antes_depois/antes_depois.png`, `evidence/ex12_pipeline/bandit_antes.txt`, `docs/cvss_priorizacao.md`, `.github/workflows/security-pipeline.yml`.
4. **Não mostre** `.env`, `evidence/.local/` nem o segredo do laboratório. Feche notificações.
5. Reinicie o servidor antes de gravar a demo (zera os contadores de rate limit).

## Linha do tempo

| Tempo | O que mostrar | O que explicar (com suas palavras) |
|---|---|---|
| **0:00–0:30** | Árvore de pastas no editor | O que é a API (pacientes, profissionais, consultas; 3 clientes; 3 papéis; dado de saúde/LGPD). Por que modularizei desde o início (`routes/ models/ database/ auth/ core/`). |
| **0:30–1:30** | `python scripts/e2e_demo.py` rodando + `/docs` com os cadeados | Mostre: sem token → 401; profissional lista só as próprias consultas (sem campos internos); **troca de ID → 404**; `professional_id` no corpo → 422; `<script>` → 422; admin só entra com **MFA**; token do laboratório → 403 nas rotas de usuário. |
| **1:30–2:30** | `antes_depois.png` e um trecho de `resultado_antes.txt` × `resultado_depois.txt` | Ex. 8/9: os 3+ padrões que **achei lendo código** (BOLA, mass assignment, SQLi/XSS, segredo fixo). **BOLA**: o filtro de dono vai **dentro do WHERE** e devolve 404 igual para "não existe" e "não é seu". Cite o **endpoint extra** (`GET /patient/{id}`) e como o middleware deny-by-default evita o esquecimento. 10/10 → 0/10. |
| **2:30–3:40** | `bandit_antes.txt`, `cvss_priorizacao.md`, `security-pipeline.yml` | **O critério de severidade do gate (Ex. 12) — explique com as suas palavras:** (1) rodei o Bandit na versão vulnerável: com `-lll` (só HIGH, como no exemplo da aula) o pipeline **passaria**; com `-ll` a SQL injection (B608, *Medium*) **bloqueia** → por isso o corte é MEDIUM; (2) o CVSS sozinho subestima BOLA (6,5 = Média) mas vazar prontuário é fato gerador de notificação à ANPD → entra o **impacto de negócio** (P1); (3) o que scanner não vê (BOLA, papéis) vira **teste que bloqueia sempre**; (4) fases: SAST/SCA/segredos/testes no PR, DAST passivo com a app no ar, ativo só em staging, IAST descrito (lacuna). Mostre `bash scripts/security_gate_local.sh` → LIBERADO. |
| **3:40–4:40** | `docs/matriz_ameaca_teste.md`, `ex13_openapi_audit.md`, `evidence/ex13_capstone/zap/baseline_web_report.html` (relatório real do **ZAP**), `ex13_zap_correlacao.md`, `ex13_risco_residual.md` | **Decisões do capstone (Ex. 13):** o threat model do Ex. 4 → controle → teste → regra do ZAP (rastreabilidade); a auditoria do OpenAPI **achou 3 lacunas que eu corrigi**; **o ZAP real** — conte a história do achado: o 1º scan apontou `90004` (COEP ausente, Baixo), eu corrigi em `core/security_headers.py`, escrevi o teste e o 2º scan passou; e o que o silêncio dele comprova (15 controles) e **o que ele NÃO enxerga** (autorização/BOLA); **risco residual** — qual você escolheu como mais pesado (R-01, CPF sem criptografia em repouso) e por que a decisão é **GO condicional**. |
| **4:40–5:00** | Placar final: 197 testes verdes | O que aprendeu / o que faria a seguir (RS256 + rotação, Redis, criptografia de coluna, IAST). |

## Perguntas que você deve saber responder (se alguém perguntar)

* Por que **RBAC + ownership** e não só RBAC? (RBAC não impede BOLA: mesmo papel, ID livre.)
* Por que **Client Credentials** para o laboratório e não Authorization Code? (é um sistema; sem usuário/navegador.)
* Por que o rate limit tem **três baldes**? (um só por IP bloqueia a recepção; um só por conta deixa o atacante travar o usuário.)
* Por que a whitelist **e** o autoescape **e** a CSP contra XSS? (defesa em profundidade; mostre o teste que grava `<script>` direto no banco.)
* O que o seu pipeline **não** cobre? (IAST; lógica de negócio nova sem teste; ZAP não prova autorização.)

## YouTube

Enviar → *Visibilidade: **Não listado*** → copiar o link → colar em `RELATORIO_TECNICO.md` e `README.md` (procure `COLOQUE-O-LINK-AQUI`) → conferir o link numa janela anônima.
