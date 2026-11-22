"""MCP RAG de documentação oficial Microsoft (FastMCP). Não acessa servidores nem guarda credenciais."""
import os
import sys
from pathlib import Path

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def load_env() -> str | None:
    """Carrega o .env de AJUSTES (cache, offline, modo http), sem credenciais. Procura SÓ na pasta de trabalho (o registro do MCP
    usa `uv --directory C:\\mcp\\microsoft_docs_mcp`) ou no caminho de MS_DOCS_ENV_FILE (variável de SISTEMA). Variável já
    definida no ambiente do sistema vence a do arquivo. Arquivo ausente: nada acontece. Devolve o caminho carregado.
    Roda dentro de main(), ANTES de importar o servidor: as constantes do cache são lidas na importação."""
    path = Path(os.getenv("MS_DOCS_ENV_FILE") or Path.cwd() / ".env")
    if not path.is_file():
        return None
    from dotenv import load_dotenv

    load_dotenv(path, override=False)
    return str(path)


def main() -> None:
    """Inicia o servidor MCP.

    MCP_TRANSPORT=stdio (padrão, para Claude Code/Desktop) | http (deploy remoto)
    MCP_HOST / MCP_PORT   endereço do modo http (padrão 127.0.0.1:8001)
    MCP_AUTH_TOKEN        OBRIGATÓRIO no modo http: token Bearer (>= 32 caracteres).
    MCP_ALLOW_INSECURE_LOOPBACK=true  permite http SEM token apenas em loopback (testes locais).
    MS_DOCS_ENV_FILE      (variável de sistema) caminho de outro .env; padrão: .env da pasta de trabalho.
    """
    load_env()
    from .server import mcp

    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        mcp.run()
        return

    host = os.getenv("MCP_HOST", "127.0.0.1")
    token = os.getenv("MCP_AUTH_TOKEN", "")
    insecure_ok = os.getenv("MCP_ALLOW_INSECURE_LOOPBACK", "").lower() == "true" and host in LOOPBACK
    if token:
        if len(token) < 32:
            sys.exit("MCP_AUTH_TOKEN deve ter pelo menos 32 caracteres.")
        from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

        mcp.auth = StaticTokenVerifier(tokens={token: {"client_id": "microsoft-docs-client", "scopes": []}})
    elif not insecure_ok:
        sys.exit("Modo http exige autenticação: defina MCP_AUTH_TOKEN (>= 32 caracteres). "
                 "Sem token, só é permitido em loopback com MCP_ALLOW_INSECURE_LOOPBACK=true.")
    mcp.run(transport=transport, host=host, port=int(os.getenv("MCP_PORT", "8001")))
