"""Gera os diagramas SVG do relatório (Exercícios 3 e 5) em evidence/ex03_ex05_diagramas/.

  dfd_nivel1.svg            DFD com fronteiras de confiança e fluxos de dados sensíveis (Ex. 3)
  arquitetura_particoes.svg partições, interfaces e eixos de segurança de API (Ex. 5)
Convertidos em PNG por scripts/collect_evidence.sh (Chrome headless).
"""
from html import escape
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "evidence" / "ex03_ex05_diagramas"
OUT.mkdir(parents=True, exist_ok=True)

RED, ORANGE, BLUE, GRAY, GREEN = "#c0392b", "#d68910", "#1f6fb2", "#6b7785", "#1e8449"
FONT = "font-family='-apple-system, Segoe UI, Helvetica, Arial, sans-serif'"


class Svg:
    def __init__(self, w: int, h: int, title: str):
        self.w, self.h, self.parts = w, h, []
        markers = "".join(
            f"<marker id='a{c[1:]}' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' "
            f"orient='auto-start-reverse'><path d='M0,0 L10,5 L0,10 z' fill='{c}'/></marker>"
            for c in (RED, ORANGE, BLUE, GRAY, GREEN, "#222222"))
        self.parts.append(f"<defs>{markers}</defs><rect width='{w}' height='{h}' fill='white'/>")
        self.text(w / 2, 30, title, size=20, weight="bold", anchor="middle")

    def text(self, x, y, s, size=13, weight="normal", anchor="start", fill="#222", rotate=None):
        tr = f" transform='rotate({rotate} {x} {y})'" if rotate else ""
        lines = s.split("\n")
        spans = "".join(f"<tspan x='{x}' dy='{0 if i == 0 else size * 1.25:.1f}'>{escape(t)}</tspan>" for i, t in enumerate(lines))
        self.parts.append(f"<text x='{x}' y='{y}' font-size='{size}' font-weight='{weight}' text-anchor='{anchor}' fill='{fill}' {FONT}{tr}>{spans}</text>")

    def box(self, x, y, w, h, s, fill="#ffffff", stroke="#222", rx=6, size=13, dash=None, weight="normal", color="#222"):
        d = f" stroke-dasharray='{dash}'" if dash else ""
        self.parts.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='{rx}' fill='{fill}' stroke='{stroke}' stroke-width='1.6'{d}/>")
        n = s.count("\n") + 1
        self.text(x + w / 2, y + h / 2 - (n - 1) * size * 0.62 + size * 0.35, s, size=size, anchor="middle", weight=weight, fill=color)

    def boundary(self, x, y, w, h, label, color=RED):
        self.parts.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='10' fill='none' stroke='{color}' stroke-width='2.2' stroke-dasharray='9 6'/>")
        self.text(x + 12, y + 20, label, size=12, weight="bold", fill=color)

    def arrow(self, pts, color=GRAY, label=None, lx=None, ly=None, width=2, dash=None, anchor="start", size=11):
        path = "M" + " L".join(f"{x},{y}" for x, y in pts)
        d = f" stroke-dasharray='{dash}'" if dash else ""
        self.parts.append(f"<path d='{path}' fill='none' stroke='{color}' stroke-width='{width}'{d} marker-end='url(#a{color[1:]})'/>")
        if label:
            self.text(lx if lx is not None else pts[0][0] + 6, ly if ly is not None else pts[0][1] - 6, label, size=size, fill=color, anchor=anchor, weight="bold")

    def line(self, x1, y1, x2, y2, color="#222", width=1.6):
        self.parts.append(f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{color}' stroke-width='{width}'/>")

    def datastore(self, x, y, w, h, s, size=12):
        self.line(x, y, x + w, y, width=2.2)
        self.line(x, y + h, x + w, y + h, width=2.2)
        self.parts.append(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' fill='#f4f6f8' opacity='0.8'/>")
        self.line(x, y, x + w, y, width=2.2)
        self.line(x, y + h, x + w, y + h, width=2.2)
        n = s.count("\n") + 1
        self.text(x + w / 2, y + h / 2 - (n - 1) * size * 0.62 + size * 0.35, s, size=size, anchor="middle")

    def save(self, name: str):
        svg = f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {self.w} {self.h}' width='{self.w}' height='{self.h}'>" + "".join(self.parts) + "</svg>"
        (OUT / name).write_text(svg)


def legend(s: Svg, y: int):
    items = [(RED, "dado de saúde / dado pessoal (PHI/PII: CPF, prontuário)"), (ORANGE, "credenciais e segredos (senha, TOTP, client_secret)"),
             (BLUE, "tokens (JWT access / m2m)"), (GRAY, "metadados / eventos sem dado sensível")]
    x = 40
    for c, t in items:
        s.line(x, y, x + 34, y, color=c, width=3)
        s.text(x + 42, y + 4, t, size=11)
        x += 42 + len(t) * 5.6 + 30
    s.text(40, y + 26, "Setas de resposta omitidas: todo fluxo é bidirecional. Linha tracejada vermelha = fronteira de confiança (trust boundary).", size=11, fill=GRAY)


def dfd():
    s = Svg(1300, 830, "DFD nível 1 — API de Agendamento Clínico (Exercício 3)")
    # entidades externas
    s.box(20, 110, 165, 90, "E1 · Frontend SPA\n(profissional / admin)\nnavegador do usuário", rx=2, size=12)
    s.box(20, 320, 165, 90, "E2 · Recepção\nnavegador — página\nHTML (agenda do dia)", rx=2, size=12)
    s.box(20, 530, 165, 90, "E3 · Laboratório\nparceiro — sistema\nM2M, sem navegador", rx=2, size=12)
    s.text(102, 650, "TB0 · Internet\norigem NÃO confiável", size=12, weight="bold", fill=RED, anchor="middle")
    s.boundary(280, 60, 780, 730, "TB1 · Aplicação FastAPI — tudo que atravessa esta fronteira é validado")
    # camada de borda
    s.box(300, 95, 78, 670, "", fill="#fff4d6", stroke=ORANGE, rx=4)
    s.text(344, 430, "BORDA: TLS/HSTS · headers · CORS allowlist · rate limit · JWT deny-by-default", size=12, weight="bold", fill="#7d5a00", anchor="middle", rotate=-90)
    # processos
    s.box(450, 100, 250, 110, "P1 · Autenticação\n/user/signin · /user/mfa/verify\n/oauth/token\nbcrypt · TOTP · emissão de JWT", rx=40, fill="#eef5fc", size=12)
    s.box(450, 270, 250, 110, "P2 · Pacientes e Consultas\n/patient · /appointment\nRBAC + ownership na query\nresponse models (whitelist)", rx=40, fill="#eef5fc", size=12)
    s.box(450, 440, 250, 100, "P3 · Página da recepção\n/web/login · /web/agenda\nJinja2 autoescape · CSP · CSRF", rx=40, fill="#eef5fc", size=12)
    s.box(450, 600, 250, 100, "P4 · Disponibilidade\n/availability (availability:read)\nsó horários — sem PHI", rx=40, fill="#eef5fc", size=12)
    # persistência
    s.boundary(850, 215, 195, 430, "TB2 · Persistência", color=RED)
    s.datastore(865, 250, 165, 130, "D1 · Banco relacional\nusers · patients ·\nappointments (SQLModel,\nqueries parametrizadas)", size=12)
    s.datastore(865, 450, 165, 100, "D2 · Trilha de auditoria\nJSON → stdout → SIEM\n(sem senha/token/PHI)", size=12)
    # fluxos externos -> borda (rótulos curtos, acima das setas)
    s.arrow([(185, 135), (300, 135)], ORANGE, "① senha + TOTP", 192, 126)
    s.arrow([(185, 175), (300, 175)], RED, "② JWT + JSON (PHI)", 192, 192)
    s.arrow([(185, 345), (300, 345)], ORANGE, "③ senha + CSRF", 192, 336)
    s.arrow([(185, 390), (300, 390)], RED, "④ cookie → HTML", 192, 407)
    s.arrow([(185, 560), (300, 560)], ORANGE, "⑤ id + secret", 192, 551)
    s.arrow([(185, 600), (300, 600)], BLUE, "⑥ Bearer m2m", 192, 617)
    # borda -> processos
    s.arrow([(378, 135), (450, 135)], ORANGE)
    s.arrow([(378, 175), (450, 175)], BLUE)
    s.arrow([(378, 320), (450, 320)], RED)
    s.arrow([(378, 490), (450, 490)], RED)
    s.arrow([(378, 650), (450, 650)], BLUE)
    # processos -> persistência
    s.arrow([(700, 150), (790, 150), (790, 270), (865, 270)], ORANGE, "hash bcrypt, semente MFA", 704, 140)
    s.arrow([(700, 325), (865, 325)], RED, "CPF, prontuário", 740, 316)
    s.arrow([(700, 490), (800, 490), (800, 350), (865, 350)], RED, "nome, motivo", 704, 482)
    s.arrow([(700, 650), (820, 650), (820, 368), (865, 368)], GRAY, "slots ocupados", 704, 642)
    s.arrow([(700, 520), (865, 520)], GRAY, "eventos", 760, 512)
    s.text(30, 700, "Fluxos sensíveis de pacientes: ② ④ e\nP2/P3 → D1. Exigem ownership,\nresponse model e cache no-store.", size=11, fill=RED)
    legend(s, 805)
    s.save("dfd_nivel1.svg")


def arquitetura():
    s = Svg(1240, 860, "Partições, interfaces e fronteiras de segurança (Exercício 5)")
    cols = [("CLIENTES", 30, 190), ("BORDA (core/ + auth/middleware)", 245, 220), ("ROTAS (routes/)", 490, 210),
            ("POLÍTICA DE ACESSO (auth/)", 725, 220), ("DADOS (models/ + database/)", 970, 240)]
    for name, x, w in cols:
        s.box(x, 60, w, 34, name, fill="#e9eef3", stroke="#8896a5", size=12, weight="bold")
    s.boundary(20, 100, 215, 600, "Zona 0 — não confiável", RED)
    s.boundary(238, 100, 1000, 600, "Zona 1 — processo da aplicação (confiança condicional)", ORANGE)
    s.boundary(962, 130, 262, 440, "Zona 2 — persistência", RED)
    # clientes
    for i, (t, y) in enumerate([("C1 · Frontend SPA\nJSON + Bearer", 140), ("C2 · Recepção\nHTML + cookie HttpOnly", 270), ("C3 · Laboratório\nclient credentials", 400), ("C4 · Atacante\n(qualquer origem)", 530)]):
        s.box(35, y, 185, 85, t, rx=2, fill="#fdecea" if i == 3 else "#fff")
    # borda
    for t, y in [("SecurityHeadersMiddleware\nHSTS · XFO · XCTO · CSP · no-store", 130), ("CORSMiddleware\nallowlist explícita, sem '*'", 215),
                 ("JWTAuthMiddleware\ndeny-by-default · exp/iss/aud/jti\nalg fixo HS256", 300), ("default_rate_limit (120/min)\nenforce_auth_rate_limit\nconta+IP 5 · IP 20 · conta 15", 415),
                 ("Handler de validação\nsem eco de input (422)", 535)]:
        s.box(255, y, 200, 70 if t.count("\n") < 2 else 85, t, fill="#fff4d6", stroke=ORANGE, size=12)
    # rotas
    for t, y in [("routes/users.py\nsignin · mfa/verify · signup\nme · deactivate", 130), ("routes/patients.py\nnew · list · search · {id}", 235),
                 ("routes/appointments.py\nnew · list · agenda · {id}", 330), ("routes/availability.py\nGET / (escopo m2m)", 425),
                 ("routes/oauth.py\nPOST /token", 505), ("routes/web.py\nlogin · agenda · logout (HTML)", 585)]:
        s.box(500, y, 190, 70, t, fill="#eef5fc", stroke=BLUE, size=12)
    # política
    for t, y in [("auth/authenticate.py\nget_principal · get_current_user", 130), ("auth/rbac.py\nrequire_roles · require_scopes", 225),
                 ("auth/ownership.py\nscope_* · get_*_or_404", 320), ("auth/jwt_handler.py · mfa.py\nhash_password.py · service.py", 415),
                 ("core/audit.py · core/csrf.py\ncore/config.py (.env)", 520)]:
        s.box(735, y, 200, 70, t, fill="#eaf6ee", stroke=GREEN, size=12)
    # dados
    s.box(975, 165, 235, 80, "models/*\nSQLModel (tabelas) +\nPydantic (entrada StrictModel / saída)", fill="#f4f6f8", size=12)
    s.box(975, 270, 235, 66, "database/repository.py\nconsultas parametrizadas", fill="#f4f6f8", size=12)
    s.datastore(985, 380, 215, 90, "Banco relacional\nusers · patients · appointments\n(credencial só via .env)", size=12)
    # fluxos
    for y in (180, 310, 440):
        s.arrow([(220, y), (255, y)], GRAY)
    s.arrow([(220, 570), (255, 570)], RED)
    s.arrow([(455, 350), (500, 350)], GRAY)
    s.arrow([(690, 165), (735, 165)], GRAY)
    s.arrow([(690, 360), (735, 355)], GRAY)
    s.arrow([(935, 355), (975, 205)], GRAY)
    s.arrow([(935, 355), (975, 303)], GRAY)
    s.arrow([(1090, 330), (1090, 380)], RED, "PHI", 1098, 358)
    # eixos
    y0 = 715
    s.text(30, y0 + 5, "Eixos de segurança de APIs (vetores detalhados no relatório):", size=13, weight="bold")
    axes = [("1 · DESIGN", "papéis e ownership definidos antes do código; 404 uniforme;\nM2M separado de usuário; mínimo de dados por visão;\nMFA para admin; contrato OpenAPI auditado", BLUE),
            ("2 · IMPLEMENTAÇÃO", "validação whitelist + extra='forbid'; queries parametrizadas;\nautoescape; bcrypt; JWT estrito; sem segredo no código;\ntestes derivados do threat model", GREEN),
            ("3 · INFRAESTRUTURA", "TLS/HSTS no proxy; CORS allowlist; headers; rate limit\n(Redis se >1 réplica); .env/secret manager; docs desligadas\nem produção; logs para SIEM", ORANGE)]
    for i, (t, d, c) in enumerate(axes):
        x = 30 + i * 405
        s.box(x, y0 + 20, 390, 100, "", stroke=c, fill="#ffffff")
        s.text(x + 12, y0 + 42, t, size=13, weight="bold", fill=c)
        s.text(x + 12, y0 + 62, d, size=11.5)
    s.save("arquitetura_particoes.svg")


if __name__ == "__main__":
    dfd()
    arquitetura()
    print("gerados:", *(p.name for p in sorted(OUT.glob("*.svg"))))
