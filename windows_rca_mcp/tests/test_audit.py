"""Auditoria: o log registra quem consultou o quê, sem conteúdo e sem segredos, e nunca derruba a tool."""
import asyncio
import json

import pytest
from fastmcp import Client, FastMCP

from windows_rca_mcp.audit import AuditLog, AuditMiddleware, build_record, sanitize_args
from windows_rca_mcp.envelope import EnvelopeMiddleware


class TestRegistro:
    def test_registro_basico(self):
        r = build_record("get_uptime", {"host": "h.familia.local", "days": 3}, True, None, 120, "2026-11-20T19:00:00-03:00")
        assert r == {"time": "2026-11-20T19:00:00-03:00", "tool": "get_uptime", "host": "h.familia.local",
                     "args": {"days": 3}, "ok": True, "ms": 120}

    def test_falha_grava_erro_truncado(self):
        r = build_record("t", {"host": "h"}, False, "x" * 500, 1)
        assert r["ok"] is False and len(r["error"]) == 200

    def test_segredos_viram_asteriscos(self):
        a = sanitize_args({"host": "h", "password": "abc", "api_token": "t", "Key": "k", "name": "ok"})
        assert a["password"] == a["api_token"] == a["Key"] == "***" and a["name"] == "ok"

    def test_texto_longo_e_objetos_sao_reduzidos(self):
        a = sanitize_args({"q": "y" * 300, "obj": {"a": 1}, "n": None})
        assert len(a["q"]) == 201 and a["obj"] == "<dict>" and a["n"] is None

    def test_registro_nao_tem_campo_de_dados(self):
        # a função não recebe o conteúdo devolvido pela tool: não há como ele vazar para o log
        assert set(build_record("t", {}, True, None, 0)) == {"time", "tool", "host", "args", "ok", "ms"}


class TestArquivo:
    def test_grava_uma_linha_json_por_chamada(self, tmp_path):
        log = AuditLog(tmp_path / "a" / "audit.jsonl", enabled=True)
        log.write({"x": 1})
        log.write({"x": 2})
        linhas = (tmp_path / "a" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        assert [json.loads(x)["x"] for x in linhas] == [1, 2]

    def test_desligada_nao_cria_arquivo(self, tmp_path):
        AuditLog(tmp_path / "audit.jsonl", enabled=False).write({"x": 1})
        assert not (tmp_path / "audit.jsonl").exists()

    def test_falha_de_gravacao_e_ignorada(self, tmp_path):
        bloqueio = tmp_path / "arquivo"
        bloqueio.write_text("x")                      # um ARQUIVO onde deveria haver pasta: mkdir falha
        AuditLog(bloqueio / "audit.jsonl", enabled=True).write({"x": 1})   # não pode lançar


class TestMiddleware:
    def _servidor(self, tmp_path):
        mcp = FastMCP("t")
        mcp.add_middleware(AuditMiddleware(AuditLog(tmp_path / "audit.jsonl", enabled=True)))
        mcp.add_middleware(EnvelopeMiddleware())

        @mcp.tool
        def ok_tool(host: str, password: str = ""):
            return {"segredo_no_dado": "NAO-DEVE-IR-PARA-O-LOG"}

        @mcp.tool
        def erro_tool(host: str):
            return {"error": "falha de teste", "host": host}

        @mcp.tool
        def boom_tool(host: str):
            raise ValueError("estourou")
        return mcp

    def _chama(self, mcp, nome, args):
        async def go():
            async with Client(mcp) as c:
                try:
                    await c.call_tool(nome, args)
                except Exception:
                    pass
        asyncio.run(go())

    def _linhas(self, tmp_path):
        return [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_sucesso_sem_conteudo_e_sem_segredo(self, tmp_path):
        mcp = self._servidor(tmp_path)
        self._chama(mcp, "ok_tool", {"host": "h", "password": "SENHA123"})
        texto = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert "NAO-DEVE-IR-PARA-O-LOG" not in texto and "SENHA123" not in texto
        r = self._linhas(tmp_path)[0]
        assert r["tool"] == "ok_tool" and r["host"] == "h" and r["ok"] is True and r["args"] == {"password": "***"}

    def test_erro_da_tool_e_registrado(self, tmp_path):
        mcp = self._servidor(tmp_path)
        self._chama(mcp, "erro_tool", {"host": "h"})
        r = self._linhas(tmp_path)[0]
        assert r["ok"] is False and r["error"] == "falha de teste"

    def test_excecao_e_registrada_e_propagada(self, tmp_path):
        mcp = self._servidor(tmp_path)
        self._chama(mcp, "boom_tool", {"host": "h"})
        r = self._linhas(tmp_path)[0]
        assert r["ok"] is False and "estourou" in r["error"]
