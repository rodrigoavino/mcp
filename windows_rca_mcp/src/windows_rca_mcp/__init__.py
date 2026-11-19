"""MCP de OPS para Windows Server (FastMCP + WinRM)."""
import os


def main() -> None:
    """Inicia o servidor MCP.

    MCP_TRANSPORT=stdio (padrão, para Claude Code/Desktop) | http (deploy remoto)
    MCP_HOST / MCP_PORT  endereço do modo http (padrão 127.0.0.1:8000)
    """
    from .server import mcp

    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(
            transport=transport,
            host=os.getenv("MCP_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_PORT", "8000")),
        )
