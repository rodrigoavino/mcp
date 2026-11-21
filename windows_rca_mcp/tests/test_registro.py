"""get_registry e get_environment_variables: validação de caminho, mascaramento de segredos e estrutura (sem WinRM)."""
import pytest

from windows_rca_mcp import server as S

BS = chr(92)


def reg(*partes):
    return "HKLM:" + BS + BS.join(partes)


class TestCaminhoDoRegistro:
    def test_aceita_chaves_normais(self):
        assert S._reg_path(reg("SOFTWARE", "Microsoft", "Windows NT", "CurrentVersion")).endswith("CurrentVersion")
        assert S._reg_path(reg("SYSTEM", "CurrentControlSet", "Services", "W32Time", "Parameters"))

    def test_barra_final_e_removida(self):
        assert S._reg_path(reg("SOFTWARE", "Microsoft") + BS) == reg("SOFTWARE", "Microsoft")

    @pytest.mark.parametrize("ruim", [
        "HKCU:" + BS + "Software",                       # só HKLM
        "HKEY_LOCAL_MACHINE" + BS + "SOFTWARE",          # formato não aceito
        "HKLM:" + BS + "SAM" + BS + "SAM",               # hive de contas
        "HKLM:" + BS + "SECURITY",                       # hive de segredos
        "HKLM:" + BS + "security" + BS + "Policy",       # sem diferenciar maiúsculas
        "HKLM:" + BS + "SOFTWARE" + BS + ".." + BS + "SAM",
        "HKLM:" + BS + "SOFTWARE" + BS + "*",            # curinga
        "HKLM:" + BS + "SOFTWARE'; calc; '",             # aspas
        "HKLM:" + BS + "SOFTWARE" + BS + "a$b",
        "",
    ])
    def test_recusa_caminhos_perigosos(self, ruim):
        with pytest.raises(ValueError):
            S._reg_path(ruim)

    def test_sam_com_prefixo_parecido_nao_e_bloqueado(self):
        # "SAMBA" não é o hive SAM: só SAM e SECURITY exatos (e suas subchaves) são recusados
        assert S._reg_path(reg("SOFTWARE", "SAMBA"))


class TestSegredos:
    @pytest.mark.parametrize("nome", ["DefaultPassword", "AdminPwd", "ClientSecret", "AuthToken", "ApiKey", "api_key",
                                      "PrivateKey", "ConnectionString", "Connection_String", "SharedKey", "Credential"])
    def test_nomes_que_sugerem_segredo(self, nome):
        assert S.is_secret_name(nome)

    @pytest.mark.parametrize("nome", ["Version", "ProductName", "KeyboardLayout", "InstallDate", "Path", "SystemRoot", ""])
    def test_nomes_comuns_nao_sao_mascarados(self, nome):
        assert not S.is_secret_name(nome)

    def test_regex_do_powershell_e_a_mesma_do_python(self):
        # o mesmo texto é injetado no script: se mudar num lado, muda nos dois
        import inspect
        assert "__RX__" in inspect.getsource(S.get_registry) and "__RX__" in inspect.getsource(S.get_environment_variables)


class TestVariaveis:
    def test_path_vira_lista(self):
        v = S._env_entries({"Name": "Path", "Value": "C:" + BS + "Windows;C:" + BS + "Windows" + BS + "System32;;", "Masked": False})
        assert v == {"Name": "Path", "Entries": ["C:" + BS + "Windows", "C:" + BS + "Windows" + BS + "System32"]}

    def test_outras_variaveis_ficam_como_estao(self):
        v = {"Name": "TEMP", "Value": "C:" + BS + "Temp", "Masked": False}
        assert S._env_entries(v) == v

    def test_variavel_mascarada_nao_e_separada(self):
        v = {"Name": "Path", "Value": "<mascarado>", "Masked": True}
        assert S._env_entries(v) == v

    def test_escopo_invalido(self):
        with pytest.raises(ValueError):
            S.get_environment_variables("fastmcp.familia.local", "process")
