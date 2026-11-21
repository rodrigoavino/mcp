"""list_event_logs e get_dotnet_config: validações, mascaramento de segredos e formato (sem WinRM)."""
import inspect

import pytest

from windows_rca_mcp import server as S

BS = chr(92)
H = "fastmcp.familia.local"


class TestListaDeLogs:
    @pytest.mark.parametrize("ok", ["*", "Security", "Microsoft-Windows-GroupPolicy*", "Microsoft-Windows-TaskScheduler/Operational", "Setup"])
    def test_filtros_validos(self, ok):
        assert S.EVLOG_FILTER_RE.match(ok)

    @pytest.mark.parametrize("ruim", ["a;b", "a'b", "a$b", "a|b", "", "x" * 101])
    def test_filtros_invalidos(self, ruim):
        assert not S.EVLOG_FILTER_RE.match(ruim)
        with pytest.raises(ValueError):
            S.list_event_logs(H, ruim)

    def test_percentual_de_uso(self):
        r = S._evlog_shape({"Matched": 2, "Logs": [{"MaximumSizeInBytes": 1000, "FileSize": 250}, {"MaximumSizeInBytes": 0, "FileSize": 5}]}, 100)
        assert r["Logs"][0]["UsedPct"] == 25.0 and r["Logs"][1]["UsedPct"] is None

    def test_log_unico_vira_lista_e_truncamento(self):
        r = S._evlog_shape({"Matched": 9, "Logs": {"LogName": "System", "MaximumSizeInBytes": 10, "FileSize": 10}}, 1)
        assert isinstance(r["Logs"], list) and r["Truncated"] is True and r["Logs"][0]["UsedPct"] == 100.0

    def test_erro_passa_sem_alteracao(self):
        assert S._evlog_shape({"error": "x", "host": "h"}, 1) == {"error": "x", "host": "h"}


class TestMascaramentoDeConfig:
    def test_senha_em_connection_string_mascara_so_o_valor(self):
        assert S._mask_config_text("Server=db1;Database=app;User Id=sa;Password=Sup3r;Encrypt=true") == \
            "Server=db1;Database=app;User Id=sa;Password=***;Encrypt=true"
        assert S._mask_config_text("Data Source=x;Pwd=abc") == "Data Source=x;Pwd=***"
        assert S._mask_config_text("sem segredo") == "sem segredo"

    def test_atributo_com_nome_de_segredo(self):
        n = S._mask_config_node({"Path": "configuration/x", "Attributes": {"password": "p", "userName": "u"}, "Text": ""})
        assert n["Attributes"] == {"password": "<mascarado>", "userName": "u"}

    def test_entrada_cuja_chave_sugere_segredo_mascara_o_value(self):
        n = S._mask_config_node({"Path": "configuration/appSettings/add[2]", "Attributes": {"key": "DbPassword", "value": "x"}})
        assert n["Attributes"] == {"key": "DbPassword", "value": "<mascarado>"}
        n = S._mask_config_node({"Path": "p", "Attributes": {"key": "Timeout", "value": "30"}})
        assert n["Attributes"] == {"key": "Timeout", "value": "30"}

    def test_texto_de_elemento_com_nome_de_segredo(self):
        n = S._mask_config_node({"Path": "configuration/smtp/password", "Attributes": {}, "Text": "abc"})
        assert n["Text"] == "<mascarado>"
        n = S._mask_config_node({"Path": "configuration/title", "Attributes": {}, "Text": "olá"})
        assert n["Text"] == "olá"

    def test_connection_string_atribui_senha_dentro_do_atributo(self):
        n = S._mask_config_node({"Path": "p", "Attributes": {"name": "Db", "connectionString": "Server=a;Pwd=zzz"}})
        assert n["Attributes"]["connectionString"] == "Server=a;Pwd=***"


class TestAtalhos:
    NODES = [
        {"Path": "configuration/appSettings", "Attributes": {}},
        {"Path": "configuration/appSettings/add[1]", "Attributes": {"key": "Env", "value": "prod"}},
        {"Path": "configuration/appSettings/add[2]", "Attributes": {"key": "ApiKey", "value": "<mascarado>"}},
        {"Path": "configuration/connectionStrings/add", "Attributes": {
            "name": "Main", "providerName": "System.Data.SqlClient",
            "connectionString": "Data Source=sql01;Initial Catalog=Vendas;Integrated Security=True"}},
    ]

    def test_app_settings(self):
        r = S._config_summary(self.NODES)
        assert r["AppSettings"] == [{"key": "Env", "value": "prod"}, {"key": "ApiKey", "value": "<mascarado>"}]

    def test_connection_strings_com_servidor_e_banco(self):
        c = S._config_summary(self.NODES)["ConnectionStrings"][0]
        assert (c["name"], c["server"], c["database"], c["integrated_security"]) == ("Main", "sql01", "Vendas", "True")

    def test_sem_secoes_comuns(self):
        assert S._config_summary([{"Path": "configuration", "Attributes": {}}]) == {"AppSettings": [], "ConnectionStrings": []}


class TestEntradasDoConfig:
    @pytest.mark.parametrize("ruim", [
        "C:" + BS + "inetpub" + BS + "wwwroot" + BS + "web.exe",                       # extensão
        "C:" + BS + "Windows" + BS + "System32" + BS + "config" + BS + "x.xml",        # área bloqueada
        "C:" + BS + "Users" + BS + "a" + BS + ".ssh" + BS + "c.config",
        "C:" + BS + "x" + BS + ".." + BS + "web.config", "web.config",
    ])
    def test_caminho_recusado(self, ruim):
        with pytest.raises(ValueError):
            S.get_dotnet_config(H, ruim)

    def test_secao_invalida(self):
        with pytest.raises(ValueError):
            S.get_dotnet_config(H, "C:" + BS + "inetpub" + BS + "web.config", "a;b")

    def test_xml_sem_dtd_e_com_limites(self):
        src = inspect.getsource(S.get_dotnet_config)
        assert "DtdProcessing]::Prohibit" in src and "XmlResolver = $null" in src
        assert "Guard $p" in src and S.CFG_MAX_BYTES == 2 * 1024 * 1024 and S.CFG_MAX_NODES == 1000

    def test_nao_seleciona_por_texto_curinga_sem_escape(self):
        assert "[regex]::Escape($sect)" in inspect.getsource(S.get_dotnet_config)
