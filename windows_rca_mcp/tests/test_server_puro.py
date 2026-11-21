"""Funções puras do coletor (windows-ops). Nada aqui abre conexão."""
import ast
import json
import pathlib
import re

import pytest

from windows_rca_mcp import server as S
from windows_rca_mcp.envelope import build_envelope

SRC = pathlib.Path(S.__file__).parent


# ---------- entradas e allowlist ----------
class TestEntradas:
    def test_host_valido_e_invalido(self):
        assert S.HOST_RE.match("dc-w25-03.familia.local")
        for ruim in ("bad;host", "a b", "x'y", "host`cmd`", "", "a" * 300):
            assert not S.HOST_RE.match(ruim), ruim

    def test_allowlist_fail_closed(self):
        assert S._host_allowed("fastmcp.familia.local")
        assert S._host_allowed("LOCALHOST")                     # sem diferença de caixa
        assert not S._host_allowed("servidor-externo.example.com")
        assert not S._host_allowed("familia.local.evil.com")    # curinga não casa sufixo enganoso

    def test_caminho_valido_e_injecao(self):
        assert S._path("C:\\Windows\\Logs") == "C:\\Windows\\Logs"
        for ruim in ("C:/x'; rm", "C:\\x;calc", "\\\\srv\\share", "C:\\a`b", "C:\\a$b", "relativo"):
            with pytest.raises(ValueError):
                S._path(ruim)

    def test_days_limites(self):
        assert S._days(0) == 1 and S._days(-5) == 1
        assert S._days(3) == 3
        assert S._days(10_000) == S.MAX_LOG_DAYS == 90

    def test_cbs_mode_aliases_e_erro(self):
        assert S._cbs_mode("rapida") == "rapida"
        assert S._cbs_mode("DETALHADA") == "detalhada"
        with pytest.raises(ValueError):
            S._cbs_mode("lenta")


# ---------- XPath do Event Log ----------
class TestXpath:
    def test_ids_provider_e_dias(self):
        x = S._xpath(ids=[41, 6008], provider="Microsoft-Windows-Kernel-Power", days=1)
        assert "(EventID=41 or EventID=6008)" in x
        assert "Provider[@Name='Microsoft-Windows-Kernel-Power']" in x
        assert "timediff(@SystemTime) <= 86400000" in x

    def test_nivel_informativo_inclui_logalways(self):
        assert "Level=0" in S._xpath(levels=[4])
        assert "Level=0" not in S._xpath(levels=[2])

    def test_sem_filtro(self):
        assert S._xpath() == "*"

    def test_provider_invalido_recusado(self):
        with pytest.raises(ValueError):
            S._xpath(provider="x'] or 1=1 or ['")

    def test_ids_sao_inteiros(self):
        with pytest.raises(ValueError):
            S._xpath(ids=["41 or 1=1"])


# ---------- datas ----------
class TestDatas:
    def test_data_normal(self):
        assert S._fmt_date(1763679600000) == "2025-11-20T23:00:00Z"

    def test_data_sentinela_do_windows_nao_quebra(self):
        assert S._fmt_date(-11644473600000).startswith("0001-01-01")     # 1601/1600: "sem data"
        assert S._fmt_date(-99999999999999999).startswith("0001-01-01")  # fora do intervalo

    def test_real_date(self):
        assert S._real_date(None) is None
        assert S._real_date("") is None
        assert S._real_date("0001-01-01T00:00:00Z") is None
        assert S._real_date("1600-12-31T16:00:00Z") is None
        assert S._real_date("2026-11-20T10:00:00Z") == "2026-11-20T10:00:00Z"


# ---------- estados neutros (só fatos) ----------
class TestEstados:
    def test_ordem(self):
        assert S._worst() == S.SEM
        assert S._worst(S.SEM, S.SIG) == S.SIG
        assert S._worst(S.SIG, S.INC, S.SEM) == S.INC

    def test_valores_sao_neutros(self):
        assert {S.SEM, S.SIG, S.INC} == {"sem_sinais", "sinais_presentes", "verificacao_incompleta"}


# ---------- serviços ----------
class TestServicos:
    def test_1077_nao_e_falha(self):
        r = S._service_facts([{"Name": "x", "State": "Stopped", "ExitCode": 1077}])
        sv = r["services"][0]
        assert sv["never_started_since_boot"] and not sv["failed_exit_code"]
        assert r["signals"]["failedExitCode"] == []

    def test_codigo_de_falha_e_estado_transitorio(self):
        r = S._service_facts([{"Name": "a", "State": "Stopped", "ExitCode": 1},
                              {"Name": "b", "State": "StartPending", "ExitCode": 0},
                              {"Name": "c", "State": "Stopped", "ExitCode": 0}])
        assert r["signals"] == {"failedExitCode": ["a"], "transitionalState": ["b"]}
        assert not r["services"][2]["failed_exit_code"]

    def test_nao_classifica(self):
        sv = S._service_facts([{"Name": "x", "State": "Stopped", "ExitCode": 0}])["services"][0]
        assert not {"suspicious", "expected", "suspeito", "esperado"} & set(sv)


# ---------- grupos locais ----------
class TestOrigemDoMembro:
    @pytest.mark.parametrize("sid,local,esperado", [
        ("S-1-5-21-1-2-3-500", True, "Local"),
        ("S-1-5-21-1-2-3-512", False, "Domínio"),
        ("S-1-12-1-1-2-3-4", False, "Azure AD"),
        ("S-1-5-32-544", False, "Interno (BUILTIN)"),
        ("S-1-5-18", False, "Sistema (NT AUTHORITY)"),
        ("S-1-1-0", False, "Sistema (NT AUTHORITY)"),
        ("S-9-9", False, "Externo"),
    ])
    def test_origem(self, sid, local, esperado):
        assert S._member_source(sid, local) == esperado


# ---------- plataforma ----------
class TestPlataforma:
    def test_kvm(self):
        r = S._classify_platform({"ComputerSystem": {"Manufacturer": "QEMU", "Model": "Standard PC (Q35 + ICH9, 2009)"},
                                  "Bios": {"Manufacturer": "SeaBIOS", "Version": "rel-1.16.3"},
                                  "Services": [{"Name": "qemu-ga", "Status": "Running"}]})
        assert r["platform"] == "virtual" and r["virtualization"] == ["KVM/QEMU"]
        assert r["detected_by"][0]["key"] == "kvm_qemu" and "SMBIOS" in r["detected_by"][0]["evidence"]

    def test_fisico(self):
        r = S._classify_platform({"ComputerSystem": {"Manufacturer": "Dell Inc.", "Model": "PowerEdge R740"},
                                  "Bios": {"Manufacturer": "Dell Inc.", "Version": "2.10"}, "Services": []})
        assert r["platform"] == "physical" and not r["virtualization"] and not r["cloud_provider"]

    def test_sem_dado_nao_afirma_fisico(self):
        """Sem ComputerSystem não há evidência alguma: é indeterminado, nunca 'físico'."""
        assert S._classify_platform({})["platform"] == "indeterminate"

    def test_hypervisor_sem_assinatura_e_indeterminado(self):
        r = S._classify_platform({"ComputerSystem": {"Manufacturer": "Acme", "Model": "X", "HypervisorPresent": True},
                                  "Bios": {}, "Services": []})
        assert r["platform"] == "indeterminate"


# ---------- carga do servidor ----------
class TestCarga:
    def test_sql_so_com_evidencia(self):
        w = S._classify_workloads({"Services": [{"Name": "MSSQLSERVER", "State": "Running", "StartMode": "Auto"}], "Software": []})
        assert list(w["workloads"]) == ["sql_server_engine"]

    def test_ssms_sozinho_nao_e_motor(self):
        w = S._classify_workloads({"Services": [], "Software": [{"DisplayName": "SQL Server Management Studio", "DisplayVersion": "20"}]})
        assert w["workloads"] == {} and w["sql_client_tools_only"] is True

    def test_sem_evidencia_nao_declara_nada(self):
        w = S._classify_workloads({"Services": [], "Software": []})
        assert w["workloads"] == {} and "sql_server_engine" in w["not_identified"]


# ---------- envelope padrão ----------
class TestEnvelope:
    NOW = "2026-11-20T10:00:00Z"

    def test_sucesso_minimo(self):
        e = build_envelope("srv.familia.local", {"a": 1}, self.NOW)
        assert e == {"computerName": "srv.familia.local", "timestamp": self.NOW, "success": True, "data": {"a": 1}}

    def test_nome_vem_do_dado_e_sai_do_data(self):
        e = build_envelope("srv.familia.local", {"Host": "SRV", "x": 1}, self.NOW)
        assert e["computerName"] == "SRV" and "Host" not in e["data"]

    def test_erro(self):
        e = build_envelope("h", {"error": "falhou", "host": "h"}, self.NOW)
        assert e["success"] is False and e["error"] == "falhou" and "data" not in e

    def test_summary_por_findings_e_evidence(self):
        e = build_envelope("h", {"overall": "sinais_presentes", "findings": ["a", "b"]}, self.NOW)
        assert e["summary"] == {"status": "sinais_presentes", "findings": 2}
        e = build_envelope("h", {"status": "sem_sinais", "evidence": ["Nenhum sinal encontrado."]}, self.NOW)
        assert e["summary"] == {"status": "sem_sinais", "findings": 0}   # a frase de "sem achados" não é achado

    def test_os_e_more_available(self):
        e = build_envelope("h", {"os": "Windows Server 2025", "more_available": "há mais", "k": 1}, self.NOW)
        assert e["os"] == "Windows Server 2025" and e["moreAvailable"] == "há mais"
        assert set(e["data"]) == {"k"}

    def test_lista_vira_data(self):
        assert build_envelope("h", [1, 2], self.NOW)["data"] == [1, 2]


# ---------- regras do projeto, guardadas no código ----------
class TestRegrasDoProjeto:
    def _source(self):
        return (SRC / "server.py").read_text(encoding="utf-8")

    def test_coletor_nao_chama_a_internet(self):
        """Regra: o coletor não tem nenhuma chamada externa (só WinRM)."""
        proibidos = {"requests", "httpx", "urllib", "urllib3", "aiohttp", "http", "socket"}
        for arq in SRC.glob("*.py"):
            for n in ast.walk(ast.parse(arq.read_text(encoding="utf-8"))):
                mods = [a.name.split(".")[0] for a in n.names] if isinstance(n, ast.Import) else \
                       [n.module.split(".")[0]] if isinstance(n, ast.ImportFrom) and n.module else []
                assert not (set(mods) & proibidos), f"{arq.name} importa {set(mods) & proibidos}"

    def test_sem_severidade_no_codigo(self):
        """Regra: nada de OK/Atenção/Crítico como estado, nem ação recomendada ou dica."""
        src = self._source()
        assert not re.search(r"""["'](Crítico|Atenção)["']""", src)
        assert "recommended_actions" not in src and "WU_HINTS" not in src and "SERVICING_HINTS" not in src

    def test_tools_registradas(self):
        import asyncio
        from fastmcp import Client

        async def nomes():
            async with Client(S.mcp) as c:
                return {t.name for t in await c.list_tools()}
        n = asyncio.run(nomes())
        assert len(n) == 78
        for esperado in ("get_license_status", "get_workload_evidence", "get_platform_info", "get_storage_overview",
                         "get_stopped_auto_services", "get_local_groups", "get_installed_software", "get_registry", "get_environment_variables", "get_permissions", "get_dns_cache", "resolve_dns_name", "get_local_users", "list_log_files", "get_log_tail", "search_log", "get_security_context", "list_directory", "find_files", "file_info", "read_file", "compare_files", "find_duplicate_files", "list_event_logs", "get_dotnet_config", "start_job", "get_job", "list_jobs", "list_hosts", "run_on_hosts", "get_sql_diagnostics"):
            assert esperado in n

    def test_resposta_do_wmi_para_json_e_ida_e_volta(self):
        assert json.loads(json.dumps(S._service_facts([])))["signals"]["failedExitCode"] == []


# ---------- fuso padrão GMT-3 ----------
class TestFuso:
    def test_converte_data_iso_utc(self):
        from windows_rca_mcp.envelope import to_local
        assert to_local("2026-11-21T02:19:30Z") == "2026-11-20T23:19:30-03:00"

    def test_virada_de_dia(self):
        from windows_rca_mcp.envelope import to_local
        assert to_local("2026-11-20T01:00:00Z") == "2026-11-19T22:00:00-03:00"

    def test_sentinela_e_texto_livre_ficam_como_estao(self):
        from windows_rca_mcp.envelope import to_local
        assert to_local("0001-01-01T00:00:00Z") == "0001-01-01T00:00:00Z"
        assert to_local("Falha em 2026-11-21T02:19:30Z no serviço") == "Falha em 2026-11-21T02:19:30Z no serviço"
        assert to_local("abc") == "abc"

    def test_envelope_converte_o_data_e_listas_aninhadas(self):
        e = build_envelope("h", {"a": {"t": "2026-11-21T02:00:00Z"}, "l": [{"t": "2026-11-21T03:00:00Z"}], "n": 5, "m": "texto"}, "x")
        assert e["data"] == {"a": {"t": "2026-11-20T23:00:00-03:00"}, "l": [{"t": "2026-11-21T00:00:00-03:00"}], "n": 5, "m": "texto"}

    def test_timestamp_padrao_sai_em_gmt_menos_3(self):
        assert build_envelope("h", {})["timestamp"].endswith("-03:00")

    def test_fuso_ajustavel_por_variavel(self, monkeypatch):
        from windows_rca_mcp.envelope import to_local
        monkeypatch.setenv("MCP_TZ_OFFSET_HOURS", "0")
        assert to_local("2026-11-21T02:00:00Z") == "2026-11-21T02:00:00+00:00"
        monkeypatch.setenv("MCP_TZ_OFFSET_HOURS", "lixo")
        assert to_local("2026-11-21T02:00:00Z") == "2026-11-20T23:00:00-03:00"
