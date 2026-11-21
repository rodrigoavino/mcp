"""get_permissions: validação do caminho e normalização da resposta (sem WinRM)."""
import pytest

from windows_rca_mcp import server as S

BS = chr(92)


class TestCaminho:
    def test_aceita_pasta_e_arquivo(self):
        assert S._path("C:" + BS + "Windows")
        assert S._path("D:" + BS + "Dados" + BS + "arquivo.txt")

    @pytest.mark.parametrize("ruim", ["Windows", BS + BS + "srv" + BS + "share", "C:" + BS + "a;b", "C:" + BS + "a'b",
                                      "C:" + BS + "a$b", "C:" + BS + "a*", "C:" + BS + "a|b", ""])
    def test_recusa_caminhos_fora_do_formato(self, ruim):
        with pytest.raises(ValueError):
            S._path(ruim)

    def test_a_tool_recusa_caminho_invalido_antes_de_conectar(self):
        with pytest.raises(ValueError):
            S.get_permissions("fastmcp.familia.local", "Windows")


class TestFormato:
    def _res(self, n=3, deny=1):
        entries = [{"Identity": "X", "Type": "Allow"} for _ in range(n - deny)] + [{"Identity": "Y", "Type": "Deny"} for _ in range(deny)]
        return {"Exists": True, "EntryCount": n, "Entries": entries}

    def test_conta_entradas_deny_como_fato(self):
        r = S._acl_shape(self._res(3, 1))
        assert r["DenyEntries"] == 1 and r["Truncated"] is False

    def test_entrada_unica_vira_lista(self):
        r = S._acl_shape({"Exists": True, "EntryCount": 1, "Entries": {"Identity": "X", "Type": "Allow"}})
        assert isinstance(r["Entries"], list) and len(r["Entries"]) == 1

    def test_truncamento_e_informado(self):
        r = S._acl_shape({"Exists": True, "EntryCount": 250, "Entries": [{"Type": "Allow"}] * 200})
        assert r["Truncated"] is True

    def test_nao_existe_ou_erro_passam_sem_alteracao(self):
        assert S._acl_shape({"Exists": False, "Error": "x"}) == {"Exists": False, "Error": "x"}
        assert S._acl_shape({"error": "falhou", "host": "h"}) == {"error": "falhou", "host": "h"}

    def test_sem_julgamento_na_tool(self):
        import inspect
        src = inspect.getsource(S.get_permissions) + inspect.getsource(S._acl_shape)
        for termo in ("excessiv", "perigos", "inseguro", "recomend"):
            assert termo not in src.lower().replace("não classifica nenhuma permissão como excessiva ou adequada", "")


class TestDireitosNumericos:
    def test_generic_all(self):
        assert S._decode_rights("268435456") == "GenericAll"

    def test_combinacao_com_sinal(self):
        # -1610612736 = 0xA0000000 = GenericExecute + GenericRead
        assert S._decode_rights("-1610612736") == "GenericExecute, GenericRead"

    def test_bits_fora_do_generic_ficam_em_hexadecimal(self):
        assert S._decode_rights(str(0x10000000 | 0x1F01FF)) == "GenericAll, 0x001F01FF"

    def test_texto_legivel_nao_e_alterado(self):
        assert S._decode_rights("FullControl") is None
        assert S._decode_rights("ReadAndExecute, Synchronize") is None
        assert S._decode_rights(None) is None

    def test_entrada_numerica_recebe_o_campo_decodificado(self):
        r = S._acl_shape({"Exists": True, "EntryCount": 2, "Entries": [{"Rights": "268435456", "Type": "Allow"},
                                                                       {"Rights": "FullControl", "Type": "Allow"}]})
        assert r["Entries"][0]["RightsDecoded"] == "GenericAll" and "RightsDecoded" not in r["Entries"][1]
