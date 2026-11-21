"""Inventário com tags e disparo em lote: seleção de hosts, isolamento de falhas, limites e auditoria (sem WinRM)."""
import json
import threading
import time

import pytest

from windows_rca_mcp import server as S


@pytest.fixture(autouse=True)
def ambiente(monkeypatch, tmp_path):
    inv = tmp_path / "hosts.json"
    inv.write_text(json.dumps({"hosts": {
        "a.familia.local": {"tags": ["lab", "dc"], "description": "controlador"},
        "b.familia.local": {"tags": ["lab"]},
        "c.familia.local": {"tags": ["prod"]},
        "fora.exemplo.com": {"tags": ["lab"]},                 # fora da lista de hosts permitidos
        "nome invalido!": {"tags": ["lab"]},                   # ignorado
        "d.familia.local": {"tags": ["lab", "tag inválida!"]},  # tag inválida é descartada
    }}), encoding="utf-8")
    monkeypatch.setenv("WINRM_HOSTS_FILE", str(inv))
    from windows_rca_mcp import audit
    monkeypatch.setattr(audit, "_DEFAULT_LOG", audit.AuditLog(tmp_path / "audit.jsonl", enabled=True))
    gate = threading.Event()

    def f_ok(host, dias=1):
        return {"host": host, "dias": dias}

    def f_falha_em_b(host):
        if host.startswith("b."):
            raise ConnectionError("sem rota")
        return {"ok": True}

    def f_devolve_erro(host):
        return {"error": "acesso negado", "host": host}

    def f_lenta(host):
        if host.startswith("a."):
            gate.wait(10)
        return {"ok": True}

    def f_grande(host):
        return {"blob": "x" * 5000}

    for nome, fn in (("t_ok", f_ok), ("t_falha_b", f_falha_em_b), ("t_erro", f_devolve_erro), ("t_lenta", f_lenta), ("t_grande", f_grande)):
        monkeypatch.setattr(S, nome, fn, raising=False)
    monkeypatch.setattr(S, "FANOUT_TOOLS", S.FANOUT_TOOLS + ("t_ok", "t_falha_b", "t_erro", "t_lenta", "t_grande"))
    yield gate
    gate.set()


class TestInventario:
    def test_le_nomes_e_tags_e_descarta_o_invalido(self):
        inv = S._load_inventory()
        assert set(inv) == {"a.familia.local", "b.familia.local", "c.familia.local", "fora.exemplo.com", "d.familia.local"}
        assert inv["a.familia.local"] == {"tags": ["lab", "dc"], "description": "controlador"}
        assert inv["d.familia.local"]["tags"] == ["lab"]

    @pytest.mark.parametrize("conteudo", ["", "não é json", "[]", '{"hosts": []}', '{"hosts": {"a": 1}}'])
    def test_arquivo_ausente_ou_ruim_vira_inventario_vazio_ou_sem_tags(self, tmp_path, monkeypatch, conteudo):
        f = tmp_path / "x.json"
        f.write_text(conteudo, encoding="utf-8")
        monkeypatch.setenv("WINRM_HOSTS_FILE", str(f))
        assert all(i["tags"] == [] for i in S._load_inventory().values())
        monkeypatch.setenv("WINRM_HOSTS_FILE", str(tmp_path / "nao_existe.json"))
        assert S._load_inventory() == {}

    def test_list_hosts_mostra_permitido_e_tags(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        r = S.list_hosts()
        por_nome = {h["host"]: h for h in r["hosts"]}
        assert por_nome["a.familia.local"]["allowed"] is True and por_nome["fora.exemplo.com"]["allowed"] is False
        assert r["tags"] == ["dc", "lab", "prod"] and r["exists"] is True
        assert {h["host"] for h in S.list_hosts("prod")["hosts"]} == {"c.familia.local"}

    def test_tag_invalida(self):
        with pytest.raises(ValueError):
            S.list_hosts("a;b")


class TestSelecao:
    def test_por_nome_e_por_tag_sem_repeticao(self):
        assert S._select_hosts(["A.familia.local", "b.familia.local"], "lab")[:2] == ["a.familia.local", "b.familia.local"]
        nomes = S._select_hosts(["a.familia.local"], "lab")
        assert nomes.count("a.familia.local") == 1 and "d.familia.local" in nomes

    def test_sem_selecao_e_erro(self):
        for args in ((None, None), ([], None), (None, "inexistente")):
            with pytest.raises(ValueError, match="nenhum host"):
                S._select_hosts(*args)

    @pytest.mark.parametrize("ruim", ["a;b", "a b", "a'b", "", "x" * 300])
    def test_host_invalido(self, ruim):
        with pytest.raises(ValueError, match="host inválido"):
            S._select_hosts([ruim], None)

    def test_limite_de_hosts(self):
        with pytest.raises(ValueError, match="no máximo"):
            S._select_hosts([f"h{i}.familia.local" for i in range(S.FANOUT_MAX_HOSTS + 1)], None)


class TestDisparoEmLote:
    def test_resultado_por_host_no_formato_padrao(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        r = S.run_on_hosts("t_ok", ["a.familia.local", "c.familia.local"], arguments={"dias": 7})
        assert r["requested"] == 2 and r["succeeded"] == 2 and r["failed"] == 0
        for x in r["results"]:
            assert x["ok"] is True and x["result"]["success"] is True and x["result"]["data"]["dias"] == 7
        assert [x["host"] for x in r["results"]] == ["a.familia.local", "c.familia.local"]      # ordem pedida

    def test_falha_de_um_host_nao_afeta_os_outros(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        r = S.run_on_hosts("t_falha_b", ["a.familia.local", "b.familia.local", "c.familia.local"])
        assert (r["succeeded"], r["failed"]) == (2, 1)
        b = next(x for x in r["results"] if x["host"].startswith("b."))
        assert b["ok"] is False and "sem rota" in b["error"] and "result" not in b

    def test_tool_que_devolve_erro_conta_como_falha(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        r = S.run_on_hosts("t_erro", ["a.familia.local"])
        assert r["failed"] == 1 and r["results"][0]["error"] == "acesso negado"

    def test_host_fora_da_lista_nem_chega_a_conectar(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        r = S.run_on_hosts("t_ok", ["a.familia.local", "fora.exemplo.com"])
        fora = next(x for x in r["results"] if x["host"] == "fora.exemplo.com")
        assert fora["ok"] is False and "WINRM_ALLOWED_HOSTS" in fora["error"]
        assert r["succeeded"] == 1

    def test_por_tag(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        r = S.run_on_hosts("t_ok", tag="prod")
        assert [x["host"] for x in r["results"]] == ["c.familia.local"]

    def test_timeout_marca_so_o_que_faltou(self, monkeypatch, ambiente):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        monkeypatch.setattr(S, "FANOUT_MIN_TIMEOUT", 1)          # no uso real o mínimo é 30 s
        t0 = time.monotonic()
        r = S.run_on_hosts("t_lenta", ["a.familia.local", "b.familia.local"], timeout_s=1)     # a. fica preso no gate
        a = next(x for x in r["results"] if x["host"].startswith("a."))
        b = next(x for x in r["results"] if x["host"].startswith("b."))
        assert a["ok"] is False and a["error"].startswith("timeout") and b["ok"] is True
        assert (r["succeeded"], r["failed"]) == (1, 1) and time.monotonic() - t0 < 8

    def test_prazo_minimo_real_e_30_segundos(self):
        assert S.FANOUT_MIN_TIMEOUT == 30

    def test_resultado_grande_e_resumido(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        r = S.run_on_hosts("t_grande", ["a.familia.local"], max_chars_per_host=1000)
        res = r["results"][0]["result"]
        assert res["truncated"] is True and res["size_chars"] > 1000 and "blob" not in json.dumps(res)

    def test_limite_total_da_resposta(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        monkeypatch.setattr(S, "FANOUT_TOTAL_CHARS", 6000)
        r = S.run_on_hosts("t_grande", ["a.familia.local", "b.familia.local", "c.familia.local"], max_chars_per_host=100000)
        assert sum(1 for x in r["results"] if x.get("truncated")) >= 1


class TestValidacoes:
    def test_tool_fora_da_lista(self):
        for ruim in ("get_registry", "read_file", "start_job", "run_on_hosts", "find_duplicate_files", "__import__"):
            with pytest.raises(ValueError, match="não permitida"):
                S.run_on_hosts(ruim, ["a.familia.local"])

    def test_argumentos(self):
        with pytest.raises(ValueError, match="valores simples"):
            S.run_on_hosts("t_ok", ["a.familia.local"], arguments={"dias": {"x": 1}})
        with pytest.raises(ValueError, match="host"):
            S.run_on_hosts("t_ok", ["a.familia.local"], arguments={"host": "outro.familia.local"})
        with pytest.raises(ValueError, match="não casam"):
            S.run_on_hosts("t_ok", ["a.familia.local"], arguments={"nada": 1})

    def test_lista_so_tem_tools_reais_de_leitura_e_nenhuma_de_conteudo_ou_job(self):
        reais = set(S.FANOUT_TOOLS) - {"t_ok", "t_falha_b", "t_erro", "t_lenta", "t_grande"}
        for nome in reais:
            assert callable(getattr(S, nome)), nome
        assert not reais & {"read_file", "get_registry", "start_job", "get_log_tail", "search_log", "get_dotnet_config", "compare_files"}


class TestAuditoria:
    def test_cada_host_gera_um_registro(self, monkeypatch, tmp_path):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        S.run_on_hosts("t_falha_b", ["a.familia.local", "b.familia.local"])
        linhas = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        regs = {r["host"]: r for r in linhas if r["tool"] == "fanout:t_falha_b"}
        assert regs["a.familia.local"]["ok"] is True and regs["b.familia.local"]["ok"] is False
        assert "sem rota" in regs["b.familia.local"]["error"]
