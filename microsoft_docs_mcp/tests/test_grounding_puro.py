"""Funções puras do RAG (microsoft-docs). Nenhuma requisição externa."""
import ast
import pathlib

import pytest

from microsoft_docs_mcp import grounding as g

SRC = pathlib.Path(g.__file__).parent


# ---------- porta de entrada: consulta externa só para recomendação, suporte, compatibilidade e boa prática ----------
AUTORIZADAS = [
    ("recommendation", "allocation unit size SQL Server"),
    ("best_practice", "DNS client settings domain controller"),
    ("support", "is dynamic disk supported on Windows Server 2025"),
    ("compatibility", "Hyper-V and BitLocker compatibility"),
    ("best_practice", "recommended cluster size for volumes"),
    ("recommendation", "qual o tamanho de cluster recomendado para SQL Server"),
    ("best_practice", "what is the recommended number of NICs in a team"),
    ("best_practice", "which service accounts does SQL Server recommend"),
    ("best_practice", "what is NTFS allocation unit size"),
    ("support", "which Windows Server versions support this feature"),
]
RECUSADAS = [
    ("recommendation", "list users and groups on the server"),
    ("best_practice", "show running services"),
    ("recommendation", "how many disks are installed"),
    ("recommendation", "what does RID 512 mean"),
    ("best_practice", "S-1-5-32-544 SID meaning"),
    ("recommendation", "list event logs with errors"),
    ("recommendation", "which users are in the administrators group"),
    ("recommendation", "who is logged on to the server"),
    ("best_practice", "what services are running"),
    ("recommendation", "quais usuarios estao no grupo administradores"),
    ("recommendation", "liste os discos do servidor"),
    ("recommendation", "quantos discos tem o servidor"),
    ("best_practice", "what ports are listening"),
    (None, "allocation unit size"),
    ("curiosity", "allocation unit size"),
]


class TestPortaDeEntrada:
    @pytest.mark.parametrize("intent,texto", AUTORIZADAS)
    def test_autorizadas(self, intent, texto):
        assert g.external_gate(intent, texto) is None

    @pytest.mark.parametrize("intent,texto", RECUSADAS)
    def test_recusadas_sem_requisicao(self, intent, texto):
        r = g.external_gate(intent, texto)
        assert r is not None and r["allowed"] is False
        assert r["network"]["search_requests"] == 0 and r["network"]["page_requests"] == 0


# ---------- privacidade da consulta ----------
class TestPrivacidade:
    @pytest.mark.parametrize("ruim", ["server fastmcp.familia.local", "contact rodrigo@example.com", "10.11.0.3 dns"])
    def test_dados_do_ambiente_sao_recusados(self, ruim):
        with pytest.raises(ValueError):
            g.check_query(ruim)

    def test_consulta_generica_passa(self):
        assert g.check_query("NTFS allocation unit size") == "NTFS allocation unit size"


# ---------- fontes e domínios ----------
class TestFontes:
    def test_so_fontes_microsoft(self):
        assert g.source_info("https://learn.microsoft.com/en-us/x")["host"] == "learn.microsoft.com"
        assert g.source_info("https://evil.example.com/x") is None
        assert g.source_info("https://learn.microsoft.com.evil.com/x") is None

    def test_dominios(self):
        assert g.classify_domains("NTFS allocation unit size") == ["storage"]
        assert g.classify_domains("SQL Server cluster size") == ["storage", "sql-server"]
        assert g.classify_domains("xyz") == []

    def test_url_dentro_do_dominio(self):
        pre = g.domain_prefixes(["storage"])
        assert g.in_domain("https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview", pre)
        assert not g.in_domain("https://learn.microsoft.com/en-us/power-platform/", pre)


# ---------- termos ----------
class TestTermos:
    def test_terms_e_strong(self):
        t = g.terms("What is the recommended NTFS cluster size?")
        assert t == ["recommended", "ntfs", "cluster", "size"]
        assert g.strong(g.terms("best practice NTFS size")) == ["ntfs"]    # genéricos não são termos fortes


# ---------- HTML: decodificação e tabelas ----------
HTML_TABELA = """<html><head><title>T</title></head><body><main><h2>Erros KMS</h2><p>Texto antes da tabela.</p>
<table><thead><tr><th>Error code</th><th>Description</th><th>Cause</th></tr></thead>
<tbody><tr><td>0xC004F056</td><td>The Software Licensing Service reported that activation failed.</td><td>No KMS</td></tr>
<tr><td>0x8007232B</td><td><p>DNS name does not exist.</p><p>Check SRV.</p></td><td></td></tr></tbody></table>
<p>Depois da tabela.</p><table><tr><td>a</td><td>b</td></tr><tr><td>c</td><td>d</td></tr></table></main></body></html>"""


class TestHtml:
    def blocos(self):
        return [t for _, t in g.parse_html(HTML_TABELA)["blocks"]]

    def test_linha_com_cabecalho_vira_um_bloco(self):
        b = self.blocos()
        assert ("Error code: 0xC004F056 | Description: The Software Licensing Service reported that activation failed. "
                "| Cause: No KMS") in b

    def test_celula_com_paragrafos_e_celula_vazia(self):
        assert "Error code: 0x8007232B | Description: DNS name does not exist. Check SRV." in self.blocos()

    def test_tabela_sem_cabecalho_junta_as_celulas(self):
        b = self.blocos()
        assert "a | b" in b and "c | d" in b

    def test_texto_fora_da_tabela_continua_igual(self):
        b = self.blocos()
        assert "Texto antes da tabela." in b and "Depois da tabela." in b

    def test_celulas_nao_viram_blocos_soltos(self):
        assert "0xC004F056" not in self.blocos() and "No KMS" not in self.blocos()

    def test_decodificacao_utf8_primeiro(self):
        assert g._decode("você ativação".encode("utf-8"), "iso-8859-1") == "você ativação"   # sem charset o requests diz ISO-8859-1
        assert g._decode("você".encode("cp1252"), None) == "você"                            # legado, não é UTF-8 válido
        assert "você".encode("utf-8").decode("iso-8859-1") != "você"                          # o defeito que foi corrigido

    def test_cache_de_paginas_tem_versao_do_parser(self):
        assert g.PARSER_VERSION == "p2"


# ---------- recomendação literal ----------
class TestRecomendacao:
    def test_valor_literal_de_frase_com_verbo(self):
        r = g.extract_recommendations("For SQL Server data files, Microsoft recommends a 64 KB allocation unit size.", "Best practices", "Perf")
        assert r and r[0]["values"] == ["64 KB"] and r[0]["bytes"] == [65536] and r[0]["strength"] == "recommendation"

    def test_padrao_entre_parenteses_nao_e_recomendacao(self):
        assert g.extract_recommendations("The cluster size is 4 KB (default).", "Overview", "T") == []

    def test_sem_valor_nao_inventa(self):
        assert g.extract_recommendations("This page describes NTFS.", "Overview", "T") == []


# ---------- consulta mínima: teto de páginas (dublês, sem rede) ----------
class TestTetoDePaginas:
    def test_nunca_le_mais_que_o_teto(self, monkeypatch):
        lidas = []

        def fake_search(q, top=8, locale="en-us", net=None):
            return [{"url": f"https://learn.microsoft.com/en-us/windows-server/storage/p{i}", "title": f"Pagina {i}",
                     "description": "nada relevante"} for i in range(25)]

        def fake_get_doc(url, net=None):
            lidas.append(url)
            return {"title": "x", "url": url, "source": g.source_info(url), "blocks": [("", "texto sem relação alguma com a pergunta")],
                    "description": "", "ms_date": "", "updated_at": ""}
        monkeypatch.setattr(g, "search_learn", fake_search)
        monkeypatch.setattr(g, "get_doc", fake_get_doc)
        r = g.ground(["NTFS allocation unit size", "cluster size NTFS"], max_docs=g.MAX_PAGES_TOTAL)
        assert r["evidence_found"] is False and r["message"] == g.NO_EVIDENCE
        assert len(set(lidas)) <= g.MAX_PAGES_TOTAL == 12


# ---------- fronteira: o RAG não fala com servidores ----------
class TestFronteira:
    def test_rag_nao_importa_winrm(self):
        for arq in SRC.glob("*.py"):
            for n in ast.walk(ast.parse(arq.read_text(encoding="utf-8"))):
                mods = [a.name.split(".")[0] for a in n.names] if isinstance(n, ast.Import) else \
                       [n.module.split(".")[0]] if isinstance(n, ast.ImportFrom) and n.module else []
                assert "winrm" not in mods and "pypsrp" not in mods, arq.name

    def test_frase_fixa_sem_evidencia(self):
        assert g.NO_EVIDENCE == "Não encontrei documentação oficial da Microsoft que confirme essa informação."


# ---------- precisão: os termos principais têm de aparecer juntos ----------
class TestProximidade:
    FALSO = ("the new functional level is required for the new 32k database page size feature. " + "x " * 200 +
             "copy the file to the other server.").lower()

    def test_termos_na_mesma_frase_passam(self):
        assert g.near(["page", "file"], "set the page file size to 1.5 times the ram".lower())

    def test_termos_distantes_nao_passam(self):
        assert not g.near(["page", "file"], self.FALSO)

    def test_um_termo_so_nao_ha_o_que_aproximar(self):
        assert g.near(["ntfs"], "ntfs")
        assert g.near([], "qualquer coisa")

    def test_portao_recusa_trecho_com_termos_dispersos(self):
        doc = {"blocks": [("", self.FALSO)]}
        blocks = g.score_blocks(doc, ["page", "file"])
        assert blocks and blocks[0]["strong_coverage"] == 1.0 and blocks[0]["near"] is False
        assert not g.passes(blocks[0], 0.6, 0.75)

    def test_portao_aceita_trecho_com_termos_juntos(self):
        doc = {"blocks": [("", "Recommended page file size is 1.5 times the RAM.")]}
        b = g.score_blocks(doc, ["page", "file"])[0]
        assert b["near"] and g.passes(b, 0.6, 0.75)


# ---------- regra de resposta sem evidência (decidida pelo usuário) ----------
class TestRegraSemEvidencia:
    def test_instrucoes_mantem_frase_fixa_e_secao_rotulada(self):
        from microsoft_docs_mcp import server
        assert g.NO_EVIDENCE in server.INSTRUCTIONS
        assert "Sem fonte oficial (conhecimento do modelo, não verificado)" in server.INSTRUCTIONS
        assert "conhecimento do modelo" in server.INSTRUCTIONS

    def test_instrucoes_nao_liberam_o_conhecimento_como_recomendacao_oficial(self):
        from microsoft_docs_mcp import server
        assert "nunca como recomendação da Microsoft" in server.INSTRUCTIONS
