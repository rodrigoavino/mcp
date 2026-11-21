"""get_local_users: contagens objetivas e validação (sem WinRM)."""
import pytest

from windows_rca_mcp import server as S


def user(**kw):
    base = {"Name": "u", "Enabled": True, "PasswordNeverExpires": False, "LastLogon": "2026-11-20T10:00:00Z"}
    base.update(kw)
    return base


class TestContagens:
    def test_contagens_basicas(self):
        res = {"Computer": "H", "Users": [
            user(Name="a"),
            user(Name="b", Enabled=False, LastLogon=None),
            user(Name="c", PasswordNeverExpires=True),
            user(Name="d", PasswordNeverExpires=True, Enabled=False),
        ]}
        c = S._users_shape(res)["Counts"]
        assert c == {"Total": 4, "Enabled": 2, "Disabled": 2, "EnabledPasswordNeverExpires": 1, "NeverLoggedOn": 1}

    def test_usuario_unico_vira_lista(self):
        r = S._users_shape({"Users": {"Name": "a", "Enabled": True}})
        assert isinstance(r["Users"], list) and r["Counts"]["Total"] == 1

    def test_sem_usuarios(self):
        r = S._users_shape({"Computer": "H", "Users": []})
        assert r["Counts"]["Total"] == 0

    def test_erro_passa_sem_alteracao(self):
        assert S._users_shape({"error": "x", "host": "h"}) == {"error": "x", "host": "h"}

    def test_enabled_desconhecido_nao_conta_nem_como_habilitada_nem_desabilitada(self):
        r = S._users_shape({"Users": [{"Name": "a", "Enabled": None}]})
        assert r["Counts"]["Enabled"] == 0 and r["Counts"]["Disabled"] == 0


class TestEntrada:
    def test_nome_invalido_recusado_antes_de_conectar(self):
        with pytest.raises(ValueError):
            S.get_local_users("fastmcp.familia.local", "a;b")

    def test_sem_julgamento_na_tool(self):
        import inspect
        src = (inspect.getsource(S.get_local_users) + inspect.getsource(S._users_shape)).lower()
        for termo in ("risco", "perigos", "inseguro", "recomend", "crítico"):
            assert termo not in src.replace("não classifica nenhuma conta", "")
