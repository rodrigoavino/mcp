"""get_services(detail=True): interpretação das ações de recuperação e formato (sem WinRM)."""
import pytest

from windows_rca_mcp import server as S


def hexdw(*valores):
    return "".join(int(v).to_bytes(4, "little").hex().upper() for v in valores)


# reset 86400 s, sem mensagem/comando, 3 ações (offset 0x14): Restart 60 s, Restart 120 s, nenhuma
SPOOLER = hexdw(86400, 0, 0, 3, 20, 1, 60000, 1, 120000, 0, 0)


class TestRecuperacao:
    def test_acoes_e_periodo(self):
        r = S._parse_failure_actions(SPOOLER)
        assert r["ResetPeriodSeconds"] == 86400
        assert r["Actions"] == [{"Action": "Restart", "DelaySeconds": 60}, {"Action": "Restart", "DelaySeconds": 120},
                                {"Action": "None", "DelaySeconds": 0}]
        assert r["HasCommand"] is False and r["HasRebootMessage"] is False

    def test_reboot_comando_e_mensagem(self):
        r = S._parse_failure_actions(hexdw(0, 100, 200, 2, 20, 3, 5000, 2, 0))
        assert [a["Action"] for a in r["Actions"]] == ["RunCommand", "Reboot"]
        assert r["HasCommand"] and r["HasRebootMessage"] and r["ResetPeriodSeconds"] == 0

    def test_reset_infinito(self):
        r = S._parse_failure_actions(hexdw(0xFFFFFFFF, 0, 0, 1, 20, 1, 1000))
        assert r["ResetPeriodSeconds"] is None            # INFINITE

    def test_tipo_desconhecido_fica_numerico(self):
        r = S._parse_failure_actions(hexdw(10, 0, 0, 1, 20, 9, 1000))
        assert r["Actions"][0]["Action"] == "9"

    @pytest.mark.parametrize("ruim", [None, "", "ZZ", "00", "0" * 41, hexdw(1, 0, 0, 99, 20),     # contagem absurda
                                      hexdw(1, 0, 0, 3, 20, 1, 1000),                              # truncado
                                      hexdw(1, 0, 0, 1, 4, 1, 1000)])                              # deslocamento inválido
    def test_dado_ausente_ou_invalido_devolve_none(self, ruim):
        assert S._parse_failure_actions(ruim) is None


class TestFormato:
    def test_normaliza_listas_e_interpreta_recuperacao(self):
        res = {"Total": 1, "Services": {"Name": "Spooler", "DependsOn": "RPCSS", "DependedBy": None, "FailureActionsHex": SPOOLER}}
        r = S._service_detail_shape(res)
        s = r["Services"][0]
        assert s["DependsOn"] == ["RPCSS"] and s["DependedBy"] == []
        assert s["Recovery"]["Actions"][0]["Action"] == "Restart" and "FailureActionsHex" not in s
        assert r["Truncated"] is False

    def test_truncamento_informado(self):
        r = S._service_detail_shape({"Total": 120, "Services": [{"Name": "a"}] * 50})
        assert r["Truncated"] is True

    def test_sem_acoes_de_recuperacao(self):
        r = S._service_detail_shape({"Total": 1, "Services": [{"Name": "x", "FailureActionsHex": None}]})
        assert r["Services"][0]["Recovery"] is None

    def test_erro_passa_sem_alteracao(self):
        assert S._service_detail_shape({"error": "x", "host": "h"}) == {"error": "x", "host": "h"}

    def test_modo_normal_continua_valido(self):
        with pytest.raises(ValueError):
            S.get_services("fastmcp.familia.local", state="Paused")
        with pytest.raises(ValueError):
            S.get_services("fastmcp.familia.local", name_filter="a;b", detail=True)
