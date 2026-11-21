"""get_security_context: formato e níveis de integridade (sem WinRM)."""
import inspect

import pytest

from windows_rca_mcp import server as S


class TestFormato:
    def test_integridade_por_nome(self):
        r = S._security_context_shape({"Groups": [], "Privileges": [], "IntegritySid": "S-1-16-12288"})
        assert r["IntegrityLevel"] == "High"

    @pytest.mark.parametrize("sid, nome", [("S-1-16-4096", "Low"), ("S-1-16-8192", "Medium"), ("S-1-16-16384", "System")])
    def test_outros_niveis(self, sid, nome):
        assert S._security_context_shape({"Groups": [], "IntegritySid": sid})["IntegrityLevel"] == nome

    def test_sid_desconhecido_fica_como_veio_e_ausente_vira_none(self):
        assert S._security_context_shape({"Groups": [], "IntegritySid": "S-1-16-99999"})["IntegrityLevel"] == "S-1-16-99999"
        assert S._security_context_shape({"Groups": [], "IntegritySid": None})["IntegrityLevel"] is None

    def test_grupo_e_privilegio_unicos_viram_lista(self):
        r = S._security_context_shape({"Groups": {"SID": "S-1-1-0", "Name": "Everyone"}, "Privileges": {"Name": "SeChangeNotifyPrivilege", "State": "Enabled"}})
        assert len(r["Groups"]) == 1 and len(r["Privileges"]) == 1

    def test_erro_passa_sem_alteracao(self):
        assert S._security_context_shape({"error": "x", "host": "h"}) == {"error": "x", "host": "h"}


class TestScript:
    def test_independe_do_idioma(self):
        src = inspect.getsource(S.get_security_context).split("res = _ps(", 1)[1]
        assert "WindowsIdentity" in src and "S-1-5-32-544" in src       # SID, não o nome do grupo
        assert "whoami /all" not in src                               # texto traduzido

    def test_sem_julgamento(self):
        src = (inspect.getsource(S.get_security_context) + inspect.getsource(S._security_context_shape)).lower()
        for termo in ("perigos", "excessiv", "recomend", "inseguro"):
            assert termo not in src
