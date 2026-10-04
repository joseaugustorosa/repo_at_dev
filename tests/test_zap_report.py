"""Gate/relatório do ZAP testados com uma fixture SINTÉTICA (não é evidência de scan real)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import zap_report  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "zap_sample_report.json"
RULES = Path(__file__).resolve().parent.parent / ".zap" / "rules.tsv"


def test_gate_bloqueia_regra_fail_e_risco_medio_ou_alto_e_ignora_regra_ignore():
    alerts = zap_report.load_alerts(FIXTURE)
    bad = {a["pluginid"] for a in zap_report.blocking(alerts, zap_report.load_rules(RULES))}
    assert bad == {"10021", "10055", "40012"}  # FAIL na regra; Médio; Alto — e 10096 (IGNORE) fica de fora


def test_gate_libera_relatorio_apenas_informativo(tmp_path):
    report = tmp_path / "r.json"
    report.write_text('{"site":[{"alerts":[{"pluginid":"10096","riskcode":"0","cweid":"200","count":"1"},'
                      '{"pluginid":"90005","riskcode":"0","cweid":"352","count":"3"}]}]}')
    assert zap_report.cmd_gate(report, RULES) == 0


def test_relatorio_correlaciona_owasp_e_so_comprova_controle_de_regra_que_rodou(tmp_path):
    log = tmp_path / "log.txt"
    log.write_text("PASS: Strict-Transport-Security Header [10035]\nPASS: Anti-clickjacking Header [10020]\n")
    out = tmp_path / "corr.md"
    assert zap_report.cmd_report([FIXTURE], out, [log]) == 0
    text = out.read_text()
    assert "10021" in text and "A05:2021" in text and "finding novo" in text  # 40012/10055 não mapeados
    assert "| 10035 |" in text and "| 10020 |" in text  # rodaram (PASS no log) e não alertaram => comprovados
    assert "| 10038 |" not in text.split("Controles comprovados")[1]  # CSP nem consta no log => NÃO comprovado
    assert "Não verificadas por este scan" in text


def test_sem_log_nada_e_afirmado_sobre_o_silencio(tmp_path):
    out = tmp_path / "corr.md"
    zap_report.cmd_report([FIXTURE], out, None)
    assert "nada é afirmado" in out.read_text()


def test_alertas_informativos_esperados_sao_marcados_como_aceitos(tmp_path):
    report = tmp_path / "r.json"
    report.write_text('{"site":[{"alerts":[{"pluginid":"10049","name":"Non-Storable Content","riskcode":"0","cweid":"524","count":"5"}]}]}')
    out = tmp_path / "corr.md"
    zap_report.cmd_report([report], out, None)
    text = out.read_text()
    assert "aceito" in text and "no-store" in text and "A05:2021" in text and "a classificar" not in text


def test_passed_rules_le_ids_do_console_do_zap(tmp_path):
    log = tmp_path / "l.txt"
    log.write_text("PASS: Cookie No HttpOnly Flag [10010]\nWARN-NEW: Non-Storable Content [10049] x 3 \nPASS: X [90022]\n")
    assert zap_report.passed_rules([log]) == {"10010", "90022"}


def test_todas_as_regras_do_rules_tsv_tem_controle_ou_sao_ignore():
    rules = zap_report.load_rules(RULES)
    for rule, action in rules.items():
        assert action in {"FAIL", "WARN", "IGNORE"}
        if action == "FAIL":
            assert rule in zap_report.CONTROLS, f"regra FAIL {rule} sem controle mapeado"
