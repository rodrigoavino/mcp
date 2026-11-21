"""Leitura de logs: só pastas permitidas, só .log/.txt, sem '..', segredos mascarados (sem WinRM)."""
import pytest

from windows_rca_mcp import server as S

BS = chr(92)


def p(*partes):
    return "C:" + BS + BS.join(partes)


class TestCaminhoPermitido:
    @pytest.mark.parametrize("ok", [
        p("Windows", "Logs", "CBS", "CBS.log"),
        p("Windows", "System32", "LogFiles", "HTTPERR", "httperr1.log"),
        p("inetpub", "logs", "LogFiles", "W3SVC1", "u_ex261120.log"),
        p("Windows", "debug", "netlogon.log"),
        p("WINDOWS", "logs", "dism", "dism.LOG"),                 # sem diferenciar maiúsculas
    ])
    def test_aceita_logs_de_pastas_permitidas(self, ok):
        path, root = S._log_path(ok)
        assert path.lower() == ok.lower() and root

    @pytest.mark.parametrize("ruim", [
        p("Windows", "System32", "config", "SAM"),                           # fora da lista (e sem extensão)
        p("Windows", "System32", "drivers", "etc", "hosts"),
        p("Users", "Administrator", "NTUSER.DAT"),
        p("Windows", "Logs", "..", "System32", "config", "SAM.log"),       # '..'
        p("Windows", "Logs", "CBS", "CBS.exe"),                               # extensão
        p("Windows", "Logs", "chave.pfx"),
        p("Windows", "LogsExtras", "x.log"),                                  # prefixo parecido: não é a pasta
        p("Windows", "Logs") + BS + "a/b.log",                                # barra normal
        "D:" + BS + "Windows" + BS + "Logs" + BS + "x.log",                    # outro volume
        "",
    ])
    def test_recusa_o_que_nao_e_log_permitido(self, ruim):
        with pytest.raises(ValueError):
            S._log_path(ruim)

    def test_pasta_pode_ser_listada_sem_extensao(self):
        path, root = S._log_path(p("Windows", "Logs", "CBS"), must_be_file=False)
        assert root.lower().endswith("logs")

    def test_pastas_extras_pelo_ambiente(self, monkeypatch):
        monkeypatch.setenv("WINRM_LOG_DIRS_EXTRA", "D:" + BS + "AppLogs;C:" + BS + "x" + BS + ".." + BS + "y;nao-e-caminho")
        dirs = S._log_dirs()
        assert "D:" + BS + "AppLogs" in dirs
        assert not any(".." in d or d == "nao-e-caminho" for d in dirs)    # extras inválidos são ignorados
        assert S._log_path("D:" + BS + "AppLogs" + BS + "app.log")

    def test_sem_variavel_so_a_lista_padrao(self, monkeypatch):
        monkeypatch.delenv("WINRM_LOG_DIRS_EXTRA", raising=False)
        assert S._log_dirs() == S.LOG_DIRS_DEFAULT


class TestSegredos:
    @pytest.mark.parametrize("entrada, saida", [
        ("login password=abc123 ok", "login password=*** ok"),
        ("Token: eyJhbGci.xyz fim", "Token: *** fim"),
        ("api_key = \"segredo com espaco\" x", "api_key = *** x"),
        ("PWD='x y'", "PWD=***"),
        ("ConnectionString=Server=a;Password=b", "ConnectionString=***"),
        ("sem segredo aqui", "sem segredo aqui"),
        ("passport=ok", "passport=ok"),          # 'pass' só vale como palavra inteira
    ])
    def test_mascara_o_valor(self, entrada, saida):
        assert S._mask_secrets(entrada) == saida

    def test_nao_texto_passa(self):
        assert S._mask_secrets(None) is None


class TestResultado:
    def test_recusa_do_servidor_vira_erro(self):
        assert S._log_result({"Refused": "Link simbólico"}, "h") == {"host": "h", "error": "Link simbólico"}

    def test_linhas_e_trechos_sao_mascarados(self):
        r = S._log_result({"Lines": ["a password=x", "b"], "Matches": [{"Line": 1, "Text": "token=abc"}]}, "h")
        assert r["Lines"] == ["a password=***", "b"] and r["Matches"][0]["Text"] == "token=***"

    def test_linha_que_chega_como_objeto_vira_texto_e_e_mascarada(self):
        # Get-Content anexa propriedades PS* às strings; se o JSON as serializar como objeto, só o texto é usado
        obj = {"value": "x password=abc", "PSPath": "C:" + BS + "Windows" + BS + "Logs" + BS + "a.log", "PSDrive": {"Root": "C:" + BS}}
        r = S._log_result({"Lines": [obj]}, "h")
        assert r["Lines"] == ["x password=***"]

    def test_script_do_tail_converte_cada_linha_em_texto(self):
        import inspect
        assert "[string]$_" in inspect.getsource(S.get_log_tail)

    def test_linha_unica_vira_lista(self):
        assert S._log_result({"Lines": "uma"}, "h")["Lines"] == ["uma"]


class TestEntradas:
    def test_pattern(self):
        assert S._check_pattern("error 0x80070005")
        for ruim in ("", "x" * 101, "a\nb", "a\x00b"):
            with pytest.raises(ValueError):
                S._check_pattern(ruim)

    def test_tools_recusam_antes_de_conectar(self):
        with pytest.raises(ValueError):
            S.get_log_tail("fastmcp.familia.local", p("Windows", "System32", "config", "SAM"))
        with pytest.raises(ValueError):
            S.search_log("fastmcp.familia.local", p("Windows", "Logs", "x.log"), "")
        with pytest.raises(ValueError):
            S.list_log_files("fastmcp.familia.local", p("Windows", "System32"))

    def test_scripts_protegem_contra_link_simbolico(self):
        assert "ReparsePoint" in S.PS_LOG_GUARD
