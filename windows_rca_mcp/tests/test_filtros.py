"""Filtros novos em get_events, get_top_processes, get_expiring_certificates, conexões/portas e tarefas (sem WinRM)."""
import inspect

import pytest

from windows_rca_mcp import server as S

H = "fastmcp.familia.local"


class TestEventosEmHoras:
    @pytest.mark.parametrize("entrada, esperado", [(6, 6), (1, 1), (0, 1), (-3, 1), (720, 720), (9999, 720), ("12", 12)])
    def test_janela_em_horas_e_limitada(self, entrada, esperado):
        assert S._hours(entrada) == esperado

    def test_horas_substituem_dias_no_filtro(self):
        src = inspect.getsource(S.get_events)
        assert "AddHours(-{_hours(hours)})" in src and "AddDays(-{_days(days)})" in src

    def test_validacoes_anteriores_continuam(self):
        with pytest.raises(ValueError):
            S.get_events(H, log_name="a;b")
        with pytest.raises(ValueError):
            S.get_events(H, levels=[9])


class TestTopProcessos:
    @pytest.mark.parametrize("ruim", ["a;b", "a'b", "a b", ""])
    def test_filtro_invalido(self, ruim):
        with pytest.raises(ValueError):
            S.get_top_processes(H, name_filter=ruim)

    def test_sort_by_invalido_e_recusado(self):
        with pytest.raises(ValueError):
            S.get_top_processes(H, sort_by="disk")

    def test_filtro_entra_no_script_e_top_e_limitado(self):
        src = inspect.getsource(S.get_top_processes)
        assert "-like '{name_filter}'" in src and "max(1, min(int(top), 100))" in src


class TestCertificados:
    def test_local_e_repositorio_validos(self):
        assert "LocalMachine" in S.CERT_LOCATIONS and "CurrentUser" in S.CERT_LOCATIONS
        assert {"My", "WebHosting", "Root", "CA", "Remote Desktop"} <= set(S.CERT_STORES)

    @pytest.mark.parametrize("loc, store", [("Machine", "My"), ("LocalMachine", "My'; calc; '"), ("LocalMachine", "Foo"),
                                            ("CurrentUser;", "My"), ("..", "My")])
    def test_recusa_valores_fora_da_lista(self, loc, store):
        with pytest.raises(ValueError):
            S.get_expiring_certificates(H, 30, loc, store)


class TestPortas:
    @pytest.mark.parametrize("porta", [0, 65536, -1])
    def test_porta_fora_do_intervalo(self, porta):
        with pytest.raises(ValueError):
            S.get_listening_ports(H, port=porta)
        with pytest.raises(ValueError):
            S.get_network_connections(H, port=porta)

    def test_filtro_de_porta_entra_nos_dois_scripts(self):
        assert "__PORT__" in inspect.getsource(S.get_listening_ports)
        assert "__PORT__" in inspect.getsource(S.get_network_connections)
        assert "PortMatches" in inspect.getsource(S.get_network_connections)


class TestTarefas:
    @pytest.mark.parametrize("ok", ["*backup*", "Daily Job", "a-b_c.d", "task?"])
    def test_filtro_valido(self, ok):
        assert S.TASK_NAME_RE.match(ok)

    @pytest.mark.parametrize("ruim", ["a;b", "a'b", "a$b", "", "x" * 101, "a|b", "\\\\Microsoft\\\\x"])
    def test_filtro_invalido(self, ruim):
        assert not S.TASK_NAME_RE.match(ruim)
        with pytest.raises(ValueError):
            S.get_scheduled_tasks(H, name_filter=ruim)
