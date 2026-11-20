"""Envelope padrão de resposta do coletor (decidido pelo usuário).

Toda tool responde com o mesmo formato mínimo, e o conteúdo vai SÓ em ``data``:

    {"computerName": "...", "timestamp": "2026-11-20T10:00:00Z", "success": true, "data": ...}

- Análises completas (painel de saúde etc.) acrescentam ``os`` e ``summary`` {status, findings}; os achados ficam em ``data``.
- ``moreAvailable`` (opcional) é UMA linha que apenas SUGERE o que mais pode ser obtido; nada além do perguntado é coletado.
- Falha: {"computerName", "timestamp", "success": false, "error": "..."}.
- Categorias não pedidas (boot, uptime, disco, CPU, memória, serviços, usuários, eventos, volumes, adaptadores) NÃO entram
  no envelope: só aparecem se a pergunta pedir, se forem necessárias para responder ou se forem erro/diagnóstico relacionado.

O envelope é aplicado na FRONTEIRA do MCP (middleware): as funções Python das tools e as chamadas internas entre elas continuam
devolvendo o dado cru, e toda tool nova segue o padrão sem mudar nada.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastmcp.server.middleware import Middleware
from fastmcp.tools.base import ToolResult
from mcp.types import TextContent

_NAME_KEYS = ("computerName", "Host", "host", "Computer", "computer")
_ERROR_ONLY = {"error", "host", "hint", "Error"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_envelope(host: str | None, raw, now: str | None = None) -> dict:
    """Função pura: dado cru de uma tool -> envelope padrão."""
    ts = now or _now()
    name = host or ""
    if isinstance(raw, dict):
        for k in _NAME_KEYS:
            if isinstance(raw.get(k), str) and raw[k]:
                name = raw[k]
                break
    # falha: o dicionário só tem a mensagem de erro (e contexto mínimo)
    if isinstance(raw, dict) and ("error" in raw or "Error" in raw) and set(raw) <= _ERROR_ONLY:
        return {"computerName": name, "timestamp": ts, "success": False, "error": raw.get("error") or raw.get("Error")}
    env: dict = {"computerName": name, "timestamp": ts, "success": True}
    data = raw
    if isinstance(raw, dict):
        data = dict(raw)
        for k in _NAME_KEYS:      # o nome já está no envelope
            data.pop(k, None) if isinstance(data.get(k), str) else None
        for k in ("os", "OS"):
            if isinstance(data.get(k), str):
                env["os"] = data.pop(k)
                break
        status = data.get("overall", data.get("status"))
        items = data.get("findings") if isinstance(data.get("findings"), list) else data.get("evidence")
        if isinstance(items, list) and isinstance(status, str):
            # a frase 'Nenhum sinal encontrado.' é o texto de "sem achados", não um achado
            env["summary"] = {"status": status, "findings": sum(1 for x in items if x != "Nenhum sinal encontrado.")}
        hint = data.pop("more_available", None)
        if isinstance(hint, str):
            env["moreAvailable"] = hint
    env["data"] = data
    return env


class EnvelopeMiddleware(Middleware):
    """Aplica o envelope padrão ao resultado de toda tool. Erros do MCP (exceções, ex.: host inválido) ficam como estão."""

    async def on_call_tool(self, context, call_next):
        result = await call_next(context)
        if getattr(result, "is_error", False):
            return result
        args = getattr(context.message, "arguments", None) or {}
        sc = result.structured_content
        if isinstance(sc, dict) and set(sc) == {"result"}:      # o FastMCP embrulha listas e valores simples em {"result": ...}
            raw = sc["result"]
        elif sc is not None:
            raw = sc
        else:
            raw = None
            for block in result.content or []:
                if isinstance(block, TextContent):
                    try:
                        raw = json.loads(block.text)
                    except ValueError:
                        raw = {"raw": block.text}
                    break
        env = build_envelope(args.get("host"), raw)
        return ToolResult(content=[TextContent(type="text", text=json.dumps(env, ensure_ascii=False))],
                          structured_content=env, meta=getattr(result, "meta", None))
