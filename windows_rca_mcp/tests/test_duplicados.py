"""find_duplicate_files: validações, formato e, no Windows, integração do script PowerShell + helper C# numa pasta temporária."""
import inspect
import json
import shutil
import subprocess
import sys
import textwrap

import pytest

from windows_rca_mcp import server as S

BS = chr(92)
H = "fastmcp.familia.local"
PS = shutil.which("powershell")
WINDOWS = sys.platform == "win32" and PS is not None


class TestEntradas:
    @pytest.mark.parametrize("ruim", [
        "Temp", "C:" + BS + "Windows" + BS + "System32" + BS + "config", "C:" + BS + "Users" + BS + "a" + BS + ".ssh",
        "C:" + BS + "a'b", "C:" + BS + "a" + BS + ".." + BS + "b",
    ])
    def test_caminho_invalido_ou_bloqueado(self, ruim):
        with pytest.raises(ValueError):
            S.find_duplicate_files(H, ruim)

    def test_script_nao_segue_links_e_pula_areas_e_arquivos_bloqueados(self):
        src = inspect.getsource(S.find_duplicate_files)
        assert "ReparsePoint" in src and "-inotmatch $deny" in src and "-inotmatch $denyName" in src

    def test_helper_e_so_de_leitura(self):
        h = S.PS_DUP_HELPER
        assert "FileAccess.Read" in h and "FileMode.Open" in h
        for escrita in ("FileAccess.Write", "FileMode.Create", "Delete(", "WriteAllBytes", "Move("):
            assert escrita not in h
        assert "Delete(" not in inspect.getsource(S.find_duplicate_files)

    def test_regex_de_nomes_bloqueados(self):
        import re
        rx = re.compile(S._fs_deny_name_regex().replace("''", "'"), re.I)
        for ruim in ("cert.pfx", "x.KDBX", "dump.dmp", "id_rsa", "NTUSER.DAT", "unattend.xml"):
            assert rx.search(ruim), ruim
        for ok in ("video.mp4", "backup.zip", "notas.txt", "readme.md"):
            assert not rx.search(ok), ok

    def test_sem_julgamento_e_sem_acao(self):
        src = inspect.getsource(S.find_duplicate_files).lower()
        for termo in ("remover", "apagar o", "recomend", "inseguro"):
            assert termo not in src.replace("só informa: não apaga", "")


class TestFormato:
    def test_calcula_gb_e_trunca(self):
        res = {"GroupsFound": 3, "TotalWastedBytes": 3 * 1073741824,
               "Groups": [{"SizeBytes": 1073741824, "WastedBytes": 1073741824, "Files": {"Path": "C:" + BS + "a"}}]}
        r = S._dup_shape(res)
        assert r["TotalWastedGB"] == 3.0 and r["GroupsTruncated"] is True
        g = r["Groups"][0]
        assert g["WastedGB"] == 1.0 and g["SizeMB"] == 1024.0 and isinstance(g["Files"], list)

    def test_sem_grupos(self):
        r = S._dup_shape({"GroupsFound": 0, "TotalWastedBytes": 0, "Groups": None})
        assert r["Groups"] == [] and r["GroupsTruncated"] is False

    def test_erro_passa_sem_alteracao(self):
        assert S._dup_shape({"error": "x", "host": "h"}) == {"error": "x", "host": "h"}


SCRIPT = textwrap.dedent(r"""
    param([string]$Cmd)
    $ErrorActionPreference = 'Stop'
    $base = Join-Path $env:TEMP ("duptest_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $base, "$base\a", "$base\b", "$base\c" | Out-Null
    try {
      $x = New-Object byte[] 2097152; (New-Object Random 1).NextBytes($x)
      $y = New-Object byte[] 2097152; (New-Object Random 2).NextBytes($y)
      $z = New-Object byte[] 2097152; [Array]::Copy($x, $z, 2097152); $z[2097151] = ($z[2097151] + 1) % 256   # igual até o último byte
      [IO.File]::WriteAllBytes("$base\a\x1.bin", $x); [IO.File]::WriteAllBytes("$base\b\x2.bin", $x)   # duplicado real
      [IO.File]::WriteAllBytes("$base\c\y1.bin", $y)
      cmd /c mklink /H "$base\c\y_link.bin" "$base\c\y1.bin" | Out-Null                                  # hard link: não é duplicado
      [IO.File]::WriteAllBytes("$base\a\z.bin", $z)                                                      # mesmo tamanho e prefixo, conteúdo diferente
      $w = New-Object byte[] 2097152; (New-Object Random 3).NextBytes($w); [IO.File]::WriteAllBytes("$base\b\w.bin", $w)   # mesmo tamanho, prefixo diferente
      [IO.File]::WriteAllBytes("$base\a\pequeno1.txt", (New-Object byte[] 100)); [IO.File]::WriteAllBytes("$base\b\pequeno2.txt", (New-Object byte[] 100))
      [IO.File]::WriteAllBytes("$base\a\segredo.pfx", $y); [IO.File]::WriteAllBytes("$base\b\segredo2.pfx", $y)   # bloqueado
      $script = Get-Content -Raw -Encoding UTF8 $Cmd
      & ([scriptblock]::Create($script.Replace('__ROOT__', $base)))
    } finally { Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue }
""")


def montar_script(min_mb: int = 1) -> str:
    """O mesmo script que a tool envia, com a raiz trocada por __ROOT__ no momento da execução."""
    import re
    src = inspect.getsource(S.find_duplicate_files)
    corpo = src.split('script = PS_DUP_HELPER + r"""', 1)[1].split('"""', 1)[0]
    corpo = S.PS_DUP_HELPER + corpo
    for k, v in (("__MIN__", str(min_mb * 1048576)), ("__DEPTH__", "5"), ("__LIMIT__", "120"), ("__MAXHASH__", str(5 * 1073741824)),
                 ("__TOPG__", "10"), ("__CANDCAP__", "1000"), ("__VISITCAP__", "10000"), ("__PARTIAL__", str(S.DUP_PARTIAL_BYTES)),
                 ("__FPG__", "10"), ("__DENYNAME__", S._fs_deny_name_regex()), ("__DENY__", S._fs_deny_regex())):
        corpo = corpo.replace(k, v)
    return corpo


@pytest.fixture(scope="module")
def resultado(tmp_path_factory):
    d = tmp_path_factory.mktemp("dup")
    (d / "run.ps1").write_text(SCRIPT, encoding="utf-8")
    cmd = d / "cmd.ps1"
    cmd.write_text(montar_script(), encoding="utf-8")
    r = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(d / "run.ps1"), "-Cmd", str(cmd)],
                       capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stderr[-800:] + r.stdout[-400:]
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(not WINDOWS, reason="integração: compila o C# e usa o PowerShell do Windows")
class TestIntegracao:
    def test_acha_so_o_duplicado_real(self, resultado):
        d = resultado
        assert d["GroupsFound"] == 1 and len(d["Groups"]) == 1
        g = d["Groups"][0]
        assert g["SizeBytes"] == 2097152 and g["Copies"] == 2 and g["WastedBytes"] == 2097152
        nomes = sorted(f["Path"].rsplit(BS, 1)[-1] for f in _lst(g["Files"]))
        assert nomes == ["x1.bin", "x2.bin"]

    def test_hard_link_nao_e_duplicado(self, resultado):
        assert resultado["HardLinkOnlyGroups"] == 1                       # y1.bin e y_link.bin: uma cópia física só
        assert all("y_link" not in f["Path"] and "y1" not in f["Path"] for g in resultado["Groups"] for f in _lst(g["Files"]))

    def test_mesmo_tamanho_e_prefixo_mas_conteudo_diferente_nao_casa(self, resultado):
        assert all("z.bin" not in f["Path"] for g in resultado["Groups"] for f in _lst(g["Files"]))

    def test_arquivos_bloqueados_nunca_sao_lidos(self, resultado):
        assert all(".pfx" not in f["Path"] for g in resultado["Groups"] for f in _lst(g["Files"]))
        # 6 candidatos >= 1 MiB: x1, x2, z, y1, y_link, w (os .pfx e os pequenos ficam fora)
        assert resultado["Candidates"] == 6

    def test_arquivos_abaixo_do_minimo_ficam_fora(self, resultado):
        assert all("pequeno" not in f["Path"] for g in resultado["Groups"] for f in _lst(g["Files"]))

    def test_so_leu_o_necessario(self, resultado):
        # 6 arquivos de 2 MiB: prefixo dos 6; SHA-256 completo só dos 5 que coincidem no prefixo (w tem prefixo único)
        assert resultado["SizeGroups"] == 1 and resultado["Partial"] is False and resultado["Unreadable"] == 0
        assert resultado["FilesHashed"] == 6 + 5
        assert resultado["BytesHashed"] == 6 * 65536 + 5 * 2097152


def _lst(x):
    return x if isinstance(x, list) else ([] if not x else [x])
