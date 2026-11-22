"""Correções da validação das tools novas: codificação automática, tamanho do get_dotnet_config e DNS sem repetição."""
import inspect

import pytest

from windows_rca_mcp import server as S

H = "fastmcp.familia.local"
BS = chr(92)
A = "C:" + BS + "x" + BS + "a.json"
B = "C:" + BS + "x" + BS + "b.json"


class TestCodificacaoAutomatica:
    def test_helper_detecta_bom_e_utf8_sem_bom(self):
        g = S.PS_FS_GUARD
        assert "function AutoEnc" in g and "function Get-EncArg" in g
        assert "UTF8Encoding($false, $true)" in g                      # UTF-8 estrito: sequência inválida cai no padrão ANSI
        assert "255" in g and "254" in g and "239" in g                # BOMs UTF-16 e UTF-8 ficam com o Get-Content
        assert "65536" in g

    def test_compare_files_usa_a_codificacao_automatica_e_aceita_encoding(self):
        src = inspect.getsource(S.compare_files)
        assert "Get-EncArg $p" in src and "@ea" in src
        assert "encoding" in inspect.signature(S.compare_files).parameters

    def test_read_file_usa_a_mesma_deteccao(self):
        src = inspect.getsource(S.read_file)
        assert "Get-EncArg $p" in src and "@ea" in src and src.count("{enc}") == 2

    def test_encoding_invalido_recusado(self):
        with pytest.raises(ValueError, match="encoding inválido"):
            S.compare_files(H, A, B, encoding="x;y")
        with pytest.raises(ValueError, match="encoding inválido"):
            S.read_file(H, A, encoding="rm")

    def test_encoding_explicito_vai_para_o_script(self, monkeypatch):
        vistos = []
        monkeypatch.setattr(S, "_ps", lambda host, script, **k: vistos.append(script) or {"Identical": True, "Diffs": []})
        S.compare_files(H, A, B, encoding="UTF8")
        assert "Get-EncArg $p 'utf8'" in vistos[0]
        S.compare_files(H, A, B)
        assert "Get-EncArg $p ''" in vistos[1]


class TestDotnetConfigMenor:
    def test_padroes_e_limites(self):
        p = inspect.signature(S.get_dotnet_config).parameters
        assert p["max_nodes"].default == S.CFG_DEFAULT_NODES == 150 and p["max_depth"].default is None
        assert S.CFG_DEFAULT_NODES < S.CFG_MAX_NODES == 1000

    def test_limite_de_nos_e_profundidade_vao_para_o_script(self, monkeypatch):
        vistos = []
        monkeypatch.setattr(S, "_ps", lambda host, script, **k: vistos.append(script) or {"Nodes": [], "NodeCount": 0})
        f = "C:" + BS + "inetpub" + BS + "web.config"
        S.get_dotnet_config(H, f)
        assert "$maxNodes = 150" in vistos[0] and "$maxDepth = 20" in vistos[0]
        S.get_dotnet_config(H, f, max_nodes=99999, max_depth=2)
        assert "$maxNodes = 1000" in vistos[1] and "$maxDepth = 2" in vistos[1]
        S.get_dotnet_config(H, f, max_nodes=0, max_depth=-5)
        assert "$maxNodes = 1" in vistos[2] and "$maxDepth = 0" in vistos[2]

    def test_nos_vazios_sao_omitidos(self, monkeypatch):
        monkeypatch.setattr(S, "_ps", lambda host, script, **k: {"NodeCount": 2, "Truncated": False, "Nodes": [
            {"Path": "configuration", "Attributes": {}, "Text": ""},
            {"Path": "configuration/a", "Attributes": {"k": "v"}, "Text": ""}]})
        r = S.get_dotnet_config(H, "C:" + BS + "inetpub" + BS + "web.config")
        assert r["Nodes"] == [{"Path": "configuration"}, {"Path": "configuration/a", "Attributes": {"k": "v"}}]
        assert "Hint" not in r

    def test_dica_quando_cortado(self, monkeypatch):
        monkeypatch.setattr(S, "_ps", lambda host, script, **k: {"NodeCount": 150, "Truncated": True, "Nodes": [{"Path": "c", "Attributes": {"a": "1"}}]})
        h = S.get_dotnet_config(H, "C:" + BS + "inetpub" + BS + "web.config")["Hint"]
        assert "section" in h and "max_depth" in h

    def test_dica_quando_secao_nao_existe(self, monkeypatch):
        monkeypatch.setattr(S, "_ps", lambda host, script, **k: {"NodeCount": 1, "Truncated": False, "Nodes": [{"Path": "configuration", "Attributes": {}}]})
        h = S.get_dotnet_config(H, "C:" + BS + "inetpub" + BS + "web.config", "appSettings")["Hint"]
        assert "appSettings" in h

    def test_segredos_continuam_mascarados_apos_compactar(self, monkeypatch):
        monkeypatch.setattr(S, "_ps", lambda host, script, **k: {"NodeCount": 1, "Truncated": False, "Nodes": [
            {"Path": "configuration/appSettings/add", "Attributes": {"key": "DbPassword", "value": "x"}, "Text": ""}]})
        r = S.get_dotnet_config(H, "C:" + BS + "inetpub" + BS + "web.config")
        assert r["Nodes"][0]["Attributes"]["value"] == "<mascarado>" and r["AppSettings"][0]["value"] == "<mascarado>"


class TestDnsSemRepeticao:
    def test_script_agrupa_registros_identicos(self):
        src = inspect.getsource(S.get_dns_cache)
        assert "Group-Object" in src and "Copies=$g.Count" in src and "MatchedUnique=$grp.Count" in src

    def test_truncado_usa_a_contagem_sem_repeticao(self):
        r = S._dns_cache_shape({"Total": 4, "Matched": 2, "MatchedUnique": 1, "Entries": [{"Type": 1, "Status": 0, "Copies": 2}]}, None, 5)
        assert r["Truncated"] is False and r["Entries"][0]["Copies"] == 2
        r = S._dns_cache_shape({"Total": 9, "Matched": 9, "MatchedUnique": 3, "Entries": [{"Type": 1, "Status": 0}]}, None, 1)
        assert r["Truncated"] is True

    def test_resposta_antiga_sem_matched_unique_continua_valida(self):
        assert S._dns_cache_shape({"Total": 3, "Matched": 3, "Entries": [{"Type": 1, "Status": 0}]}, None, 1)["Truncated"] is True
