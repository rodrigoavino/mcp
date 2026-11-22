"""get_disk_usage_tree: conciliação da soma da varredura com o espaço usado do volume (sem WinRM)."""
import pytest

from windows_rca_mcp import server as S

GB = 1073741824
H = "fastmcp.familia.local"
BS = chr(92)
VOL = {"Root": "C:" + BS, "Size": 31 * GB, "Free": 3 * GB, "Format": "NTFS"}      # usado: 28 GB


def scan(disk_gb, **extra):
    base = {"total_disk_bytes": int(disk_gb * GB), "partial": False, "access_denied": 0, "links_skipped": 0,
            "hardlinks": {"deduplicated": True}}
    base.update(extra)
    return base


class TestConciliacao:
    def test_scan_maior_que_o_volume(self):
        r = S._volume_reconciliation(scan(37.3), "C:" + BS, VOL)
        assert r["comparison"] == "scan_exceeds_volume_used" and r["is_volume_root"] is True
        assert r["volume_used_gb"] == 28.0 and r["scanned_disk_gb"] == 37.3 and r["difference_gb"] == -9.3
        assert any("superestimados" in n for n in r["notes"])

    def test_volume_usa_mais_que_o_scan(self):
        r = S._volume_reconciliation(scan(20), "C:" + BS, VOL)
        assert r["comparison"] == "volume_uses_more_than_scan" and r["difference_gb"] == 8.0
        assert any("não são enumerados" in n for n in r["notes"])

    def test_conciliado_dentro_da_tolerancia(self):
        r = S._volume_reconciliation(scan(27.9), "C:" + BS, VOL)
        assert r["comparison"] == "reconciled" and r["tolerance_gb"] == 0.56      # 2% de 28 GB > 256 MB

    def test_tolerancia_minima_em_volume_pequeno(self):
        pequeno = {"Root": "D:" + BS, "Size": 2 * GB, "Free": 1 * GB, "Format": "NTFS"}        # usado 1 GB; 2% = 20 MB
        assert S._volume_reconciliation(scan(1.2), "D:" + BS, pequeno)["comparison"] == "reconciled"     # 0,2 GB < 256 MB
        assert S._volume_reconciliation(scan(1.5), "D:" + BS, pequeno)["comparison"] == "scan_exceeds_volume_used"

    def test_subpasta_nao_concilia_e_informa_participacao(self):
        r = S._volume_reconciliation(scan(7), "C:" + BS + "Users", VOL)
        assert r["is_volume_root"] is False and r["comparison"] == "not_applicable"
        assert r["share_of_volume_used_pct"] == 25.0 and "difference_bytes" not in r
        assert any("não é a do volume" in n for n in r["notes"])

    def test_raiz_sem_barra_final_conta_como_raiz(self):
        assert S._volume_reconciliation(scan(28), "c:", VOL)["is_volume_root"] is True

    def test_notas_objetivas_das_limitacoes(self):
        r = S._volume_reconciliation(scan(28, partial=True, access_denied=3, links_skipped=2, hardlinks={"deduplicated": False}), "C:" + BS, VOL)
        txt = " ".join(r["notes"])
        assert "parcial" in txt and "3 itens sem permissão" in txt and "2 links" in txt and "dedupe_hardlinks=false" in txt

    def test_volume_indisponivel(self):
        assert S._volume_reconciliation(scan(1), "C:" + BS, {"error": "falhou", "host": H}) == {"available": False, "reason": "falhou"}
        assert S._volume_reconciliation(scan(1), "C:" + BS, None)["available"] is False
        assert S._volume_reconciliation(scan(1), "C:" + BS, {"Size": 0})["available"] is False

    def test_sem_texto_de_causa_afirmada(self):
        """Só fatos: a conciliação não atribui a diferença a uma causa."""
        for gb in (37.3, 20):
            txt = " ".join(S._volume_reconciliation(scan(gb), "C:" + BS, VOL)["notes"]).lower()
            assert "causa provável" not in txt and "recomend" not in txt and "deve ser" not in txt


class TestIntegracaoNaTool:
    def _fake(self, monkeypatch, vol):
        chamadas = []

        def fake_long(host, script, timeout=0):
            return {"path": "C:" + BS, "total_disk_bytes": 37 * GB, "partial": False, "access_denied": 0, "links_skipped": 0,
                    "hardlinks": {"deduplicated": True}}

        def fake_ps(host, script, **k):
            chamadas.append(script)
            return vol

        monkeypatch.setattr(S, "_ps_long", fake_long)
        monkeypatch.setattr(S, "_ps", fake_ps)
        return chamadas

    def test_anexa_a_conciliacao(self, monkeypatch):
        chamadas = self._fake(monkeypatch, VOL)
        r = S.get_disk_usage_tree(H, "C:" + BS)
        assert r["volume_reconciliation"]["comparison"] == "scan_exceeds_volume_used"
        assert "IO.DriveInfo" in chamadas[0] and "C:" in chamadas[0]

    def test_falha_na_leitura_do_volume_nao_derruba_a_varredura(self, monkeypatch):
        self._fake(monkeypatch, {"error": "sem acesso", "host": H})
        r = S.get_disk_usage_tree(H, "C:" + BS)
        assert r["total_disk_bytes"] == 37 * GB and r["volume_reconciliation"]["available"] is False

    def test_erro_do_scanner_nao_tenta_conciliar(self, monkeypatch):
        chamadas = self._fake(monkeypatch, VOL)
        monkeypatch.setattr(S, "_ps_long", lambda *a, **k: {"error": "Add-Type bloqueado", "host": H})
        r = S.get_disk_usage_tree(H, "C:" + BS)
        assert "hint" in r and "volume_reconciliation" not in r and chamadas == []
