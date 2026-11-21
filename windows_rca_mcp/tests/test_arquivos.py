"""Arquivos e pastas (list_directory, find_files, file_info, read_file, compare_files): bloqueios e formato (sem WinRM)."""
import inspect

import pytest

from windows_rca_mcp import server as S

BS = chr(92)
H = "fastmcp.familia.local"


def p(*partes):
    return "C:" + BS + BS.join(partes)


class TestAreasBloqueadas:
    @pytest.mark.parametrize("ruim", [
        p("Windows", "System32", "config"),
        p("Windows", "System32", "config", "SAM"),
        p("WINDOWS", "system32", "CONFIG", "SYSTEM"),                        # sem diferenciar maiúsculas
        p("Windows", "NTDS", "ntds.dit"),
        p("Windows", "SYSVOL", "..", "x"),                                   # '..'
        p("Users", "adm", "AppData", "Roaming", "Microsoft", "Credentials"),
        p("Users", "adm", "AppData", "Roaming", "Microsoft", "Protect", "S-1-5-21"),
        p("ProgramData", "Microsoft", "Crypto", "RSA", "MachineKeys"),
        p("Users", "adm", ".ssh"),
        p("Users", "adm", ".ssh", "id_rsa"),
        p("System Volume Information"),
        p("Dados", "ntds", "x"),                                             # NTDS em qualquer nível
    ])
    def test_recusa_areas_sensiveis(self, ruim):
        with pytest.raises(ValueError):
            S._fs_path(ruim)

    @pytest.mark.parametrize("ok", [
        p("Windows", "System32", "drivers", "etc", "hosts"),
        p("Windows", "System32", "configuration", "x.txt"),                  # prefixo parecido com 'config'
        p("Windows", "NTDSA", "x"),                                          # prefixo parecido com 'ntds'
        p("inetpub", "wwwroot", "web.config"),
        p("Users", "adm", "Documents", "notas.txt"),
        "C:" + BS,
    ])
    def test_libera_o_que_nao_e_sensivel(self, ok):
        assert S._fs_path(ok)

    def test_extra_pelo_ambiente(self, monkeypatch):
        monkeypatch.setenv("WINRM_FILE_DENY_EXTRA", "D:" + BS + "Segredos;nao-e-caminho;C:" + BS + "x" + BS + ".." + BS + "y")
        assert S._fs_blocked_path("D:" + BS + "Segredos" + BS + "a.txt")
        assert S._fs_blocked_path("D:" + BS + "SegredosOutros") is None     # limite de pasta
        assert S._fs_deny_extra() == ["D:" + BS + "Segredos"]               # entradas inválidas são ignoradas

    def test_sem_variavel_so_a_lista_padrao(self, monkeypatch):
        monkeypatch.delenv("WINRM_FILE_DENY_EXTRA", raising=False)
        assert S._fs_deny_extra() == []


class TestArquivosBloqueados:
    @pytest.mark.parametrize("nome", ["cert.pfx", "A.P12", "chave.pem", "x.key", "banco.kdbx", "dump.dmp", "Mini.MDMP",
                                      "disco.vhdx", "conexao.rdp", "ntds.dit", "id_rsa", "id_ed25519", ".git-credentials",
                                      ".netrc", "NTUSER.DAT", "NTUSER.DAT.LOG1", "Unattend.xml", "autounattend.xml", "sysprep.inf"])
    def test_nomes_e_extensoes_bloqueados(self, nome):
        assert S._fs_blocked_name(nome)

    @pytest.mark.parametrize("nome", ["hosts", "web.config", "notas.txt", "app.log", "id_rsa.pub.txt", "keyboard.txt", "readme.md", ""])
    def test_nomes_comuns_liberados(self, nome):
        assert S._fs_blocked_name(nome) is None

    def test_read_file_recusa_arquivo_bloqueado_antes_de_conectar(self):
        for ruim in (p("Temp", "cert.pfx"), p("Windows", "System32", "config", "SAM"), p("Users", "a", "id_rsa")):
            with pytest.raises(ValueError):
                S.read_file(H, ruim)
        with pytest.raises(ValueError):
            S.file_info(H, p("Temp", "cert.pfx"), hash=True)
        with pytest.raises(ValueError):
            S.compare_files(H, p("Temp", "a.txt"), p("Temp", "b.pfx"))


class TestEntradas:
    def test_encoding_invalido(self):
        with pytest.raises(ValueError):
            S.read_file(H, p("Temp", "a.txt"), encoding="utf99")

    def test_intervalo_invalido(self):
        with pytest.raises(ValueError):
            S.read_file(H, p("Temp", "a.txt"), start_line=10, end_line=5)

    @pytest.mark.parametrize("ruim", ["a;b", "a'b", "a$b", "a|b", "", "x" * 101])
    def test_filtros_de_nome_invalidos(self, ruim):
        assert not S.FS_NAME_FILTER_RE.match(ruim)
        with pytest.raises(ValueError):
            S.list_directory(H, p("Temp"), ruim)
        with pytest.raises(ValueError):
            S.find_files(H, p("Temp"), ruim)

    def test_caminho_fora_do_formato(self):
        for ruim in ("Temp", BS + BS + "srv" + BS + "share", "C:" + BS + "a/b", "C:" + BS + "a'b"):
            with pytest.raises(ValueError):
                S.list_directory(H, ruim)


class TestConteudo:
    def test_chave_privada_recusa_o_arquivo(self):
        res = {"Lines": ["-----BEGIN RSA PRIVATE KEY-----", "MIIE..."]}
        r = S._fs_result(res, "h")
        assert "chave privada" in r["error"] and "Lines" not in r

    def test_segredos_sao_mascarados(self):
        r = S._fs_result({"Lines": ["a password=abc", "b token: xyz"]}, "h")
        assert r["Lines"] == ["a password=***", "b token: ***"]

    def test_linha_como_objeto_vira_texto(self):
        r = S._fs_result({"Lines": [{"value": "x pwd=1", "PSPath": "C:" + BS + "a"}]}, "h")
        assert r["Lines"] == ["x pwd=***"]

    def test_diferencas_sao_mascaradas_e_a_chave_privada_recusa(self):
        r = S._fs_result({"Diffs": [{"Side": "OnlyInA", "Line": 1, "Text": "api_key=zzz"}]}, "h")
        assert r["Diffs"][0]["Text"] == "api_key=***"
        r = S._fs_result({"Diffs": [{"Side": "OnlyInB", "Line": 2, "Text": "-----BEGIN PRIVATE KEY-----"}]}, "h")
        assert "chave privada" in r["error"]

    def test_recusa_do_servidor_vira_erro(self):
        assert S._fs_result({"Refused": "Arquivo binário"}, "h") == {"host": "h", "error": "Arquivo binário"}

    def test_linha_unica_vira_lista(self):
        assert S._fs_result({"Lines": "uma"}, "h")["Lines"] == ["uma"]


class TestScripts:
    def test_guarda_de_arquivo(self):
        for marcador in ("ReparsePoint", "-contains 0", "ReadWrite", "FileAttributes"):
            assert marcador in S.PS_FS_GUARD
        assert "ReparsePoint" in S.PS_FS_DIRGUARD

    def test_busca_nao_segue_links_e_pula_pastas_bloqueadas(self):
        src = inspect.getsource(S.find_files)
        assert "ReparsePoint" in src and "-inotmatch $deny" in src and "Visited" in src

    def test_regex_de_bloqueio_do_powershell_vem_dos_mesmos_padroes(self, monkeypatch):
        monkeypatch.setenv("WINRM_FILE_DENY_EXTRA", "D:" + BS + "Segredos")
        rx = S._fs_deny_regex()
        assert "system32" in rx and "ntds" in rx and "segredos" in rx
        assert "'" not in rx.replace("''", "")

    def test_prazos_e_limites(self):
        assert S.FS_MAX_LINES == 500 and S.FS_MAX_LIST == 200 and S.FS_FIND_VISIT_CAP == 50000
        assert "-TotalCount (__ML__ + 1)" in inspect.getsource(S.compare_files)

    def test_sem_julgamento(self):
        src = "".join(inspect.getsource(f) for f in (S.list_directory, S.find_files, S.file_info, S.read_file, S.compare_files)).lower()
        for termo in ("perigos", "inseguro", "recomend"):
            assert termo not in src
