"""Scanner de disco (diskscan.cs): argumentos do Python e, no Windows, um teste de integração que COMPILA o C# e o roda
numa pasta temporária local com arquivos de verdade (hard link, compactado, esparso, pequenos). Sem WinRM."""
import inspect
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from windows_rca_mcp import server as S

CS = Path(S.__file__).parent / "diskscan.cs"
PS = shutil.which("powershell")
WINDOWS = sys.platform == "win32" and PS is not None


class TestArgumentos:
    def test_measure_invalido(self):
        with pytest.raises(ValueError):
            S.get_disk_usage_tree("fastmcp.familia.local", measure="blocks")

    def test_caminho_invalido(self):
        with pytest.raises(ValueError):
            S.get_disk_usage_tree("fastmcp.familia.local", path="C:" + chr(92) + "a'b")

    def test_script_passa_os_dois_novos_argumentos(self):
        src = inspect.getsource(S.get_disk_usage_tree)
        assert "'$true' if measure == 'disk' else '$false'" in src and "'$true' if dedupe_hardlinks else '$false'" in src

    def test_o_scanner_declara_a_assinatura_nova(self):
        cs = CS.read_text(encoding="utf-8")
        assert "int oldDays, bool byDisk, bool dedupe)" in cs
        for api in ("GetCompressedFileSizeW", "GetDiskFreeSpaceW", "GetFileInformationByHandle", "FindFirstFileExW"):
            assert api in cs

    def test_scanner_usa_so_recursos_do_csharp_5(self):
        cs = CS.read_text(encoding="utf-8")
        for proibido in ('$"', "?.", "out var", " => {", "nameof("):
            assert proibido not in cs.replace("=> b.", "").replace("=> a.", ""), proibido


SCRIPT = textwrap.dedent(r"""
    param([string]$Cs, [string]$ByDisk, [string]$Dedupe)
    $ErrorActionPreference = 'Stop'
    $base = Join-Path $env:TEMP ("scantest_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $base, "$base\a", "$base\b" | Out-Null
    try {
      $rnd = New-Object byte[] 1048576; (New-Object Random 7).NextBytes($rnd)
      [IO.File]::WriteAllBytes("$base\a\grande.bin", $rnd)
      cmd /c mklink /H "$base\b\grande_link.bin" "$base\a\grande.bin" | Out-Null
      [IO.File]::WriteAllBytes("$base\a\zeros.dat", (New-Object byte[] 5242880))
      cmd /c compact /c "$base\a\zeros.dat" | Out-Null
      1..20 | % { [IO.File]::WriteAllBytes("$base\b\p$_.txt", (New-Object byte[] 100)) }
      $fs = [IO.File]::Create("$base\a\esparso.dat"); $fs.Close()
      cmd /c fsutil sparse setflag "$base\a\esparso.dat" | Out-Null      # esparso ANTES de estender: nada é alocado
      $fs = [IO.File]::Open("$base\a\esparso.dat", 'Open', 'Write'); $fs.SetLength(10485760); $fs.Close()
      Add-Type -TypeDefinition (Get-Content -Raw -Encoding UTF8 $Cs)
      [DiskScan]::Run($base, 3, 10, 10, 1, 4, 60, 365, [bool]::Parse($ByDisk), [bool]::Parse($Dedupe))
    } finally { Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue }
""")


def rodar(tmp_path, by_disk: bool, dedupe: bool) -> dict:
    ps1 = tmp_path / "scan.ps1"
    ps1.write_text(SCRIPT, encoding="utf-8")
    r = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1), "-Cs", str(CS),
                        "-ByDisk", str(by_disk), "-Dedupe", str(dedupe)], capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, r.stderr[-800:]
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def sem_dedupe(tmp_path_factory):
    return rodar(tmp_path_factory.mktemp("s1"), False, False)


@pytest.fixture(scope="module")
def com_dedupe(tmp_path_factory):
    return rodar(tmp_path_factory.mktemp("s2"), True, True)


@pytest.mark.skipif(not WINDOWS, reason="integração: compila o C# no Windows")
class TestIntegracao:
    LOGICO = 2 * 1048576 + 5242880 + 10485760 + 20 * 100        # grande + link + zeros + esparso + 20 pequenos

    def test_tamanho_logico_e_contagens(self, sem_dedupe):
        d = sem_dedupe
        assert d["total_bytes"] == self.LOGICO and d["files"] == 24 and d["dirs"] == 2
        assert d["measure"] == "logical" and d["partial"] is False and d["hardlinks"]["deduplicated"] is False

    def test_em_disco_e_menor_que_o_logico_por_causa_do_esparso_e_do_compactado(self, sem_dedupe):
        d = sem_dedupe
        # esparso (10 MiB, nada alocado) e zeros compactados (5 MiB) quase não ocupam disco: sobram o arquivo de 1 MiB,
        # o hard link (sem dedupe conta de novo) e 20 pequenos arredondados ao cluster
        esperado = 2 * 1048576 + 20 * d["cluster_bytes"]
        assert esperado <= d["total_disk_bytes"] <= esperado + 256 * 1024
        assert d["cluster_bytes"] >= 512

    def test_arquivos_pequenos_arredondam_para_o_cluster(self, sem_dedupe):
        b = next(c for c in sem_dedupe["tree"]["children"] if c["name"] == "b")
        # 20 arquivos de 100 bytes + o hard link de 1 MiB (sem dedupe, o link conta); cada pequeno ocupa >= 1 cluster
        assert b["size_bytes"] == 1048576 + 2000
        assert b["disk_bytes"] >= 1048576 + 20 * sem_dedupe["cluster_bytes"] - 1

    def test_dedupe_conta_o_hard_link_uma_vez(self, com_dedupe, sem_dedupe):
        assert com_dedupe["files"] == 23
        assert com_dedupe["total_bytes"] == self.LOGICO - 1048576
        h = com_dedupe["hardlinks"]
        assert h["deduplicated"] is True and h["repeated_files_skipped"] == 1

    def test_modo_disco_ordena_e_calcula_percentual_pelo_disco(self, com_dedupe):
        assert com_dedupe["measure"] == "disk"
        kids = com_dedupe["tree"]["children"]
        assert kids == sorted(kids, key=lambda c: -c["disk_bytes"])
        assert abs(sum(c["pct"] for c in kids) - 100) < 0.5

    def test_saida_traz_os_dois_tamanhos_em_todos_os_niveis(self, sem_dedupe):
        def todos(n):
            yield n
            for c in n.get("children", []):
                yield from todos(c)
        for n in todos(sem_dedupe["tree"]):
            assert {"size_gb", "disk_gb", "size_bytes", "disk_bytes", "pct", "files"} <= set(n)
        assert all({"size_gb", "disk_gb"} <= set(f) for f in sem_dedupe["top_files"])
        assert all({"size_gb", "disk_gb", "files"} <= set(e) for e in sem_dedupe["by_extension"])
