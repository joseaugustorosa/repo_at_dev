"""Respostas de erro documentadas no OpenAPI (contrato explícito para os clientes)."""

PROTECTED_RESPONSES: dict[int | str, dict] = {
    401: {"description": "Token ausente, inválido ou expirado"},
    403: {"description": "Perfil/escopo sem permissão para a operação"},
    429: {"description": "Limite de requisições excedido (veja Retry-After)"},
}
OWNED_RESOURCE_RESPONSES: dict[int | str, dict] = {
    **PROTECTED_RESPONSES,
    404: {"description": "Recurso inexistente OU pertencente a outro usuário (indistinguíveis de propósito)"},
}
AUTH_RESPONSES: dict[int | str, dict] = {
    401: {"description": "Credenciais inválidas (mensagem genérica)"},
    429: {"description": "Limite estrito de tentativas excedido (veja Retry-After)"},
}
