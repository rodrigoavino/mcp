"""Log de auditoria das chamadas de tool (quem consultou o quê, quando e com que resultado).

Uma linha JSON por chamada (``audit.jsonl``): data (GMT-3), tool, host, argumentos, resultado (ok/erro), duração e, em falha, a
mensagem de erro (truncada). **Nunca** grava o conteúdo devolvido (``data``) nem valores de argumentos que pareçam segredo.
Escrever o log jamais derruba uma tool: qualquer falha de gravação é ignorada.

    MCP_AUDIT=off         desliga a auditoria (padrão: ligada)
    MCP_AUDIT_LOG=<caminho>  arquivo (padrão: <projeto>/logs/audit.jsonl; rotação 5 MB x 5)
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import time
from pathlib import Path

from fastmcp.server.middleware import Middleware

from .envelope import _now

SECRET_KEY_RE = re.compile(r"pass|pwd|secret|token|credential|key", re.I)
MAX_ARG_CHARS = 200
MAX_ERR_CHARS = 200
DEFAULT_PATH = Path(__file__).resolve().parents[2] / "logs" / "audit.jsonl"


def sanitize_args(args: dict | None) -> dict:
    """Argumentos para o log: valores de chaves com cara de segredo viram '***'; textos longos são cortados."""
    out: dict = {}
    for k, v in (args or {}).items():
        if SECRET_KEY_RE.search(str(k)):
            out[k] = "***"
        elif isinstance(v, str) and len(v) > MAX_ARG_CHARS:
            out[k] = v[:MAX_ARG_CHARS] + "…"
        elif isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = f"<{type(v).__name__}>"
    return out


def build_record(tool: str, args: dict | None, success: bool, error: str | None, ms: int, now: str | None = None) -> dict:
    """Função pura: uma linha de auditoria. Não recebe (e portanto não pode gravar) o conteúdo devolvido pela tool."""
    a = sanitize_args(args)
    rec = {"time": now or _now(), "tool": tool, "host": a.get("host"), "args": {k: v for k, v in a.items() if k != "host"},
           "ok": bool(success), "ms": int(ms)}
    if not success:
        rec["error"] = (error or "")[:MAX_ERR_CHARS]
    return rec


class AuditLog:
    def __init__(self, path: str | os.PathLike | None = None, enabled: bool | None = None):
        self.enabled = (os.getenv("MCP_AUDIT", "on").lower() != "off") if enabled is None else enabled
        self.path = Path(path or os.getenv("MCP_AUDIT_LOG") or DEFAULT_PATH)
        self._logger: logging.Logger | None = None

    def write(self, rec: dict) -> None:
        if not self.enabled:
            return
        try:
            if self._logger is None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                lg = logging.getLogger(f"windows_rca_mcp.audit.{id(self)}")
                lg.setLevel(logging.INFO)
                lg.propagate = False
                h = logging.handlers.RotatingFileHandler(self.path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
                h.setFormatter(logging.Formatter("%(message)s"))
                lg.addHandler(h)
                self._logger = lg
            self._logger.info(json.dumps(rec, ensure_ascii=False))
        except Exception:
            pass   # auditoria nunca derruba a tool


class AuditMiddleware(Middleware):
    """Registra cada chamada de tool. Fica POR FORA do envelope: lê o resultado já no formato padrão (success/error)."""

    def __init__(self, log: AuditLog | None = None):
        self.log = log or AuditLog()

    async def on_call_tool(self, context, call_next):
        t0 = time.monotonic()
        msg = getattr(context, "message", None)
        tool, args = getattr(msg, "name", "?"), getattr(msg, "arguments", None) or {}
        try:
            result = await call_next(context)
        except Exception as e:
            self.log.write(build_record(tool, args, False, f"{type(e).__name__}: {e}", (time.monotonic() - t0) * 1000))
            raise
        sc = getattr(result, "structured_content", None)
        ok = not getattr(result, "is_error", False) and not (isinstance(sc, dict) and sc.get("success") is False)
        err = sc.get("error") if isinstance(sc, dict) and not ok else None
        self.log.write(build_record(tool, args, ok, err if isinstance(err, str) else None, (time.monotonic() - t0) * 1000))
        return result
