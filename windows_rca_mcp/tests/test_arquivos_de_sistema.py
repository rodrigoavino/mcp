"""pagefile.sys/hiberfil.sys/swapfile.sys: o Get-Item não os enxerga; a listagem da pasta com -Force enxerga."""
import inspect

from windows_rca_mcp import server as S


class TestOfensoresDeEspaco:
    def test_arquivos_de_sistema_sao_procurados_pela_listagem_da_pasta(self):
        src = inspect.getsource(S.get_common_space_offenders)
        assert "Get-ChildItem -LiteralPath (Split-Path $f -Parent) -Force -File" in src
        assert "$i = Get-Item" not in src                              # o cmdlet que não enxerga o pagefile saiu
        for nome in ("MEMORY.DMP", "pagefile.sys", "hiberfil.sys", "swapfile.sys"):
            assert nome in src

    def test_comparacao_de_nome_sem_diferenciar_maiusculas(self):
        assert "-ieq (Split-Path $f -Leaf)" in inspect.getsource(S.get_common_space_offenders)


class TestFileInfoDeArquivoDeSistema:
    def test_cai_na_listagem_da_pasta_quando_get_item_falha(self, monkeypatch):
        vistos = []
        monkeypatch.setattr(S, "_ps", lambda host, script, **k: vistos.append(script) or {"Exists": True, "IsDirectory": False})
        S.file_info("fastmcp.familia.local", "C:" + chr(92) + "pagefile.sys")
        s = vistos[0]
        assert "Get-Item -LiteralPath $p -Force -ErrorAction Stop" in s            # caminho normal continua primeiro
        assert "Get-ChildItem -LiteralPath (Split-Path $p -Parent) -Force" in s     # reserva para os arquivos de sistema
        assert "Exists=$false; Error=$err" in s                                    # sem o arquivo, mantém o erro original

    def test_hash_de_arquivo_bloqueado_continua_recusado(self):
        import pytest
        with pytest.raises(ValueError, match="bloqueado"):
            S.file_info("fastmcp.familia.local", "C:" + chr(92) + "Windows" + chr(92) + "System32" + chr(92) + "config" + chr(92) + "SAM", hash=True)
