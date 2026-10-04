"""Matriz ameaça (Exercício 4) -> testes automatizados (Exercício 12).

Fonte única usada por: tests/test_ex12_threat_vectors.py (verifica que cada teste citado
existe) e scripts/gen_traceability.py (gera a tabela do relatório do Exercício 13).
Formato: ID da ameaça -> (descrição curta, [módulo::[Classe::]função_de_teste, ...]).
"""

THREATS: dict[str, tuple[str, list[str]]] = {
    # --- C1 Autenticação -------------------------------------------------------
    "T-S1": ("JWT forjado/adulterado/expirado", [
        "test_ex06_authz::test_token_expirado_e_rejeitado",
        "test_ex06_authz::test_token_com_assinatura_errada_e_rejeitado",
        "test_ex06_authz::test_token_alg_none_e_rejeitado",
        "test_ex06_authz::test_token_de_outra_audiencia_e_rejeitado",
        "test_ex06_authz::test_token_alterado_para_papel_admin_nao_eleva_privilegio"]),
    "T-S2": ("Força bruta / credential stuffing no login", [
        "test_ex10_hardening::test_login_e_limitado_a_5_tentativas_por_janela",
        "test_ex12_threat_vectors::test_limite_por_conta_vale_mesmo_trocando_de_ip",
        "test_ex12_threat_vectors::test_credential_stuffing_de_um_ip_e_contido",
        "test_ex12_threat_vectors::test_atacante_nao_consegue_travar_o_login_do_usuario_legitimo_em_outro_ip"]),
    "T-T1": ("Mass assignment de role no cadastro", [
        "test_ex09_input_validation::test_signup_nao_aceita_campos_extras_e_exige_admin",
        "test_ex06_authz::test_usuario_sem_papel_admin_nao_acessa_rota_restrita_a_admin"]),
    "T-R1": ("Falhas de login e negações sem registro", [
        "test_ex12_threat_vectors::test_falha_de_login_e_negacao_de_acesso_geram_trilha_de_auditoria"]),
    "T-I1": ("Enumeração de usuários (mensagem/tempo)", [
        "test_ex06_authz::test_login_invalido_usa_mensagem_generica",
        "test_ex13_unit_mocks::TestCriptografiaComMocks::test_login_de_usuario_inexistente_gasta_o_mesmo_custo_de_hash"]),
    "T-D1": ("Inundação de tentativas de login", [
        "test_ex10_hardening::test_token_endpoint_tambem_tem_limite_estrito",
        "test_ex13_unit_mocks::test_rate_limiter_janela_deslizante_libera_apos_a_janela"]),
    "T-E1": ("Token de desafio MFA como sessão / replay do TOTP", [
        "test_ex06_authz::test_admin_exige_mfa_e_nao_recebe_access_token_so_com_senha",
        "test_ex06_authz::test_mfa_codigo_correto_emite_token_e_replay_e_negado"]),
    # --- C2 Consultas ----------------------------------------------------------
    "T-S3": ("Falsificar o dono da consulta (professional_id no corpo)", [
        "test_ex09_input_validation::test_criar_consulta_rejeita_campos_nao_declarados",
        "test_ex01_appointments::test_profissional_cria_e_lista_consulta_do_proprio_paciente"]),
    "T-T2": ("BOLA em alteração/cancelamento e mass assignment de status/IDs", [
        "test_ex09_input_validation::test_bola_em_todos_os_endpoints_por_id",
        "test_ex09_input_validation::test_atualizar_consulta_nao_aceita_trocar_dono_ou_paciente"]),
    "T-R2": ("Alteração/cancelamento sem rastro", [
        "test_ex12_threat_vectors::test_alteracoes_de_consulta_geram_trilha_de_auditoria"]),
    "T-I2": ("BOLA de leitura e campos internos de auditoria vazando", [
        "test_ex06_authz::test_profissional_nao_le_consulta_de_outro_profissional",
        "test_ex02_response_models_xss::test_nenhum_endpoint_de_consulta_vaza_campos_internos"]),
    "T-D2": ("Listagens sem limite (consumo de recursos)", [
        "test_ex12_threat_vectors::test_paginacao_tem_teto_e_rejeita_valores_abusivos"]),
    "T-E2": ("Perfil agindo fora do papel (recepção cria consulta)", [
        "test_ex06_authz::test_recepcionista_nao_cria_consulta",
        "test_ex06_authz::test_profissional_nao_agenda_para_paciente_de_outro"]),
    # --- C3 Página da recepção -------------------------------------------------
    "T-S4": ("CSRF em login/logout da página", [
        "test_ex02_response_models_xss::test_login_web_sem_csrf_e_negado",
        "test_ex12_threat_vectors::test_logout_exige_csrf"]),
    "T-T3": ("XSS armazenado na agenda", [
        "test_ex02_response_models_xss::test_pagina_agenda_escapa_conteudo_malicioso_persistido",
        "test_ex09_input_validation::test_texto_livre_fora_da_whitelist_e_rejeitado"]),
    "T-I3": ("Dados de saúde em excesso na página / cache", [
        "test_ex02_response_models_xss::test_pagina_agenda_nao_expoe_dados_confidenciais",
        "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas"]),
    "T-E3": ("Roubo de sessão via cookie", [
        "test_ex02_response_models_xss::test_cookie_de_sessao_httponly_samesite_strict"]),
    # --- C4 Integração com o laboratório --------------------------------------
    "T-S5": ("Personificação do cliente M2M (segredo errado)", [
        "test_ex07_m2m_scopes::test_token_endpoint_recusa_pedidos_invalidos"]),
    "T-T4": ("Ampliar escopo no pedido de token", [
        "test_ex07_m2m_scopes::test_token_endpoint_recusa_pedidos_invalidos",
        "test_ex07_m2m_scopes::test_token_m2m_com_outro_escopo_nao_acessa_availability"]),
    "T-I4": ("Laboratório lendo dados de pacientes", [
        "test_ex07_m2m_scopes::test_laboratorio_consulta_horarios_livres_sem_dados_de_paciente",
        "test_ex07_m2m_scopes::test_token_do_laboratorio_nao_acessa_rotas_de_usuarios"]),
    "T-E4": ("Token M2M em rotas de usuário e vice-versa", [
        "test_ex07_m2m_scopes::test_token_do_laboratorio_nao_acessa_rotas_de_usuarios",
        "test_ex07_m2m_scopes::test_token_de_profissional_nao_acessa_rota_do_laboratorio"]),
    # --- C5 Persistência -------------------------------------------------------
    "T-T5": ("SQL injection", [
        "test_ex09_input_validation::test_busca_com_payload_sql_e_barrada_pela_whitelist",
        "test_ex09_input_validation::test_payload_que_passa_na_whitelist_e_neutralizado_pela_parametrizacao",
        "test_ex09_input_validation::test_nenhum_codigo_monta_sql_por_concatenacao",
        "test_ex11_persistence::test_consulta_usa_parametros_ligados"]),
    "T-I5": ("Vazamento por credenciais no código / dump do banco", [
        "test_ex11_persistence::test_codigo_nao_contem_credenciais_embutidas",
        "test_ex11_persistence::test_settings_exigem_credenciais_do_ambiente",
        "test_ex02_response_models_xss::test_usuario_nunca_devolve_hash_nem_semente_mfa"]),
    # --- Transversal ------------------------------------------------------------
    "T-X1": ("Endpoint novo esquecido sem autenticação (deny-by-default)", [
        "test_ex12_threat_vectors::test_deny_by_default_em_todas_as_rotas"]),
    "T-X2": ("CORS permissivo / ausência de headers de segurança", [
        "test_ex10_hardening::test_origem_nao_listada_nao_recebe_cors",
        "test_ex10_hardening::test_configuracao_recusa_cors_curinga_ou_malformado",
        "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas"]),
}
