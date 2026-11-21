"""get_performance_snapshot com média de amostras: limites e formato (sem WinRM)."""
import inspect

import pytest

from windows_rca_mcp import server as S


class TestLimites:
    @pytest.mark.parametrize("entrada, esperado", [
        ((3, 2), (3, 2)), ((1, 1), (1, 1)), ((0, 0), (1, 1)), ((-5, -5), (1, 1)),
        ((99, 99), (10, 10)), (("4", "3"), (4, 3)),
    ])
    def test_amostras_e_intervalo_sao_limitados(self, entrada, esperado):
        assert S._perf_args(*entrada) == esperado

    def test_filtro_de_processo_valido(self):
        for ok in ("sqlservr*", "w3wp#1", "svchost", "a.b-c_d?"):
            assert S.PERF_PROC_RE.match(ok)

    @pytest.mark.parametrize("ruim", ["a;b", "a'b", "a b", "a$b", "", "x" * 101, "a|b"])
    def test_filtro_de_processo_invalido(self, ruim):
        assert not S.PERF_PROC_RE.match(ruim)
        with pytest.raises(ValueError):
            S.get_performance_snapshot("fastmcp.familia.local", process_filter=ruim)


class TestFormato:
    def test_processo_unico_vira_lista(self):
        r = S._perf_shape({"Samples": 3, "Processes": {"Name": "x"}})
        assert r["Processes"] == [{"Name": "x"}]

    def test_sem_processos(self):
        assert S._perf_shape({"Samples": 1, "Processes": None})["Processes"] == []

    def test_erro_passa_sem_alteracao(self):
        assert S._perf_shape({"error": "x", "host": "h"}) == {"error": "x", "host": "h"}


class TestScript:
    def test_usa_cim_e_nao_get_counter(self):
        src = inspect.getsource(S.get_performance_snapshot).split("res = _ps(", 1)[1]    # só o script, não a docstring
        assert "Win32_PerfFormattedData_PerfOS_Processor" in src
        assert "Get-Counter" not in src                       # independe do idioma do Windows

    def test_prazo_cresce_com_amostras_e_intervalo(self):
        src = inspect.getsource(S.get_performance_snapshot)
        assert "timeout=(n - 1) * iv + 90" in src

    def test_campos_novos(self):
        src = inspect.getsource(S.get_performance_snapshot)
        for campo in ("CpuPctMax", "DiskQueueMax", "DiskReadMBs", "DiskWriteMBs", "DiskBusyPct", "NetworkMBs",
                      "TcpEstablished", "ProcessCount", "Threads", "IoReadKBs", "IoWriteKBs"):
            assert campo in src
