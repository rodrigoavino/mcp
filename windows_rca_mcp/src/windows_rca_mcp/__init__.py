"""MCP de OPS para Windows Server (FastMCP + WinRM)."""
import os
import sys

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def main() -> None:
    """Inicia o servidor MCP.

    MCP_TRANSPORT=stdio (padrão, para Claude Code/Desktop) | http (deploy remoto)
    MCP_HOST / MCP_PORT   endereço do modo http (padrão 127.0.0.1:8000)
    MCP_AUTH_TOKEN        OBRIGATÓRIO no modo http: token Bearer (>= 32 caracteres) exigido em toda requisição.
    MCP_ALLOW_INSECURE_LOOPBACK=true  permite http SEM token apenas em loopback (testes locais).
    """
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

        mcp.auth = StaticTokenVerifier(tokens={token: {"client_id": "windows-ops-client", "scopes": []}})
    elif not insecure_ok:
        sys.exit(
            "Modo http exige autenticação: defina MCP_AUTH_TOKEN (>= 32 caracteres). "
            "Sem token, só é permitido em loopback com MCP_ALLOW_INSECURE_LOOPBACK=true."
        )
    mcp.run(transport=transport, host=host, port=int(os.getenv("MCP_PORT", "8000")))
