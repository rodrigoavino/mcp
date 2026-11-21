"""Relógio e fuso do servidor em get_system_overview/get_time_config: campos e formato (sem WinRM)."""
import re

from windows_rca_mcp import server as S
from windows_rca_mcp.envelope import build_envelope, to_local


class TestScript:
    def test_campos_do_relogio(self):
        for campo in ("TimeZoneId", "TimeZoneName", "BaseUtcOffset", "CurrentUtcOffset", "SupportsDaylightSaving",
                      "DaylightSavingNow", "ServerLocalTime", "ServerUtcTime"):
            assert campo in S.PS_CLOCK

    def test_as_duas_tools_incluem_o_relogio(self):
        import inspect
        for tool in (S.get_system_overview, S.get_time_config):
            src = inspect.getsource(tool)
            assert "__CLOCK__" in src and 'replace("__CLOCK__", PS_CLOCK)' in src

    def test_json_com_profundidade_suficiente(self):
        import inspect
        assert "ConvertTo-Json -Depth 3" in inspect.getsource(S.get_system_overview)
        assert "ConvertTo-Json -Depth 3" in inspect.getsource(S.get_time_config)


class TestFormatoNaoEConvertido:
    """O relógio é a leitura bruta do servidor: o envelope não pode convertê-la para GMT-3."""

    def test_utc_do_servidor_nao_casa_com_o_formato_iso_com_z(self):
        assert to_local("2026-11-21 03:02:32 UTC") == "2026-11-21 03:02:32 UTC"

    def test_hora_local_com_deslocamento_fica_como_veio(self):
        assert to_local("2026-11-20 19:02:32 -08:00") == "2026-11-20 19:02:32 -08:00"

    def test_envelope_preserva_o_bloco_clock(self):
        clock = {"TimeZoneId": "Pacific Standard Time", "ServerUtcTime": "2026-11-21 03:02:32 UTC",
                 "ServerLocalTime": "2026-11-20 19:02:32 -08:00"}
        e = build_envelope("h", {"Host": "H", "Clock": clock}, "x")
        assert e["data"]["Clock"] == clock

    def test_o_formato_do_script_e_o_que_os_testes_esperam(self):
        assert "'yyyy-MM-dd HH:mm:ss zzz'" in S.PS_CLOCK and "+ ' UTC'" in S.PS_CLOCK
        assert not re.search(r"Z'\)", S.PS_CLOCK)      # nenhum formato ISO com 'Z' literal
