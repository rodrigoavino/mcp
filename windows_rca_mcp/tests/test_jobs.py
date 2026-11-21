"""Jobs assíncronos: ciclo de vida, limites e validações, com tools de mentira (sem WinRM)."""
import threading
import time

import pytest

from windows_rca_mcp import server as S

H = "fastmcp.familia.local"


@pytest.fixture(autouse=True)
def limpo(monkeypatch, tmp_path):
    """Registro de jobs vazio, auditoria num arquivo temporário e tools de mentira liberadas."""
    S._jobs.clear()
    from windows_rca_mcp import audit
    monkeypatch.setattr(audit, "_DEFAULT_LOG", audit.AuditLog(tmp_path / "audit.jsonl", enabled=True))
    gate = threading.Event()

    def ferramenta_lenta(host, path="C:", n=1):
        gate.wait(5)
        return {"host": host, "path": path, "n": n}

    def ferramenta_rapida(host):
        return {"host": host, "ok": True}

    def ferramenta_com_erro(host):
        raise ValueError("falha de teste")

    def ferramenta_grande(host):
        return {"blob": "x" * (S.JOB_RESULT_MAX_BYTES + 10)}

    def ferramenta_que_devolve_erro(host):
        return {"error": "sem acesso", "host": host}

    for nome, fn in (("t_lenta", ferramenta_lenta), ("t_rapida", ferramenta_rapida), ("t_erro", ferramenta_com_erro),
                     ("t_grande", ferramenta_grande), ("t_devolve_erro", ferramenta_que_devolve_erro)):
        monkeypatch.setattr(S, nome, fn, raising=False)
    monkeypatch.setattr(S, "JOB_TOOLS", S.JOB_TOOLS + ("t_lenta", "t_rapida", "t_erro", "t_grande", "t_devolve_erro"))
    yield gate
    gate.set()
    S._jobs.clear()


def espera(jid, segundos=5):
    return S.get_job(jid, wait_seconds=segundos)


class TestCicloDeVida:
    def test_job_concluido_devolve_o_resultado_enveloped(self):
        j = S.start_job(H, "t_rapida")
        assert j["status"] == "running" and len(j["job_id"]) == 12
        r = espera(j["job_id"])
        assert r["status"] == "done" and r["finished"]
        env = r["result"]
        assert env["success"] is True and env["computerName"] == H and env["data"] == {"ok": True}

    def test_get_job_espera_ate_o_fim(self, limpo):
        j = S.start_job(H, "t_lenta", {"path": "D:", "n": 3})
        assert S.get_job(j["job_id"])["status"] == "running"          # sem espera: ainda rodando
        limpo.set()
        r = espera(j["job_id"])
        assert r["status"] == "done" and r["result"]["data"] == {"path": "D:", "n": 3}

    def test_excecao_vira_estado_error(self):
        r = espera(S.start_job(H, "t_erro")["job_id"])
        assert r["status"] == "error" and "falha de teste" in r["error"] and "result" not in r

    def test_resultado_grande_demais_vira_error(self):
        r = espera(S.start_job(H, "t_grande")["job_id"])
        assert r["status"] == "error" and "maior que" in r["error"]

    def test_tool_que_devolve_erro_termina_como_done_com_success_false(self):
        r = espera(S.start_job(H, "t_devolve_erro")["job_id"])
        assert r["status"] == "done" and r["result"]["success"] is False and r["result"]["error"] == "sem acesso"

    def test_list_jobs_nao_traz_resultado(self):
        espera(S.start_job(H, "t_rapida")["job_id"])
        l = S.list_jobs()
        assert l["count"] == 1 and l["running"] == 0 and "result" not in l["jobs"][0]


class TestLimites:
    def test_no_maximo_quatro_em_execucao(self, limpo):
        ids = [S.start_job(H, "t_lenta")["job_id"] for _ in range(S.JOB_MAX_RUNNING)]
        with pytest.raises(ValueError, match="jobs em execução"):
            S.start_job(H, "t_lenta")
        limpo.set()
        for i in ids:
            espera(i)
        assert S.start_job(H, "t_rapida")["status"] == "running"           # liberou vaga

    def test_jobs_terminados_expiram(self, monkeypatch):
        jid = S.start_job(H, "t_rapida")["job_id"]
        espera(jid)
        with S._jobs_lock:
            S._jobs[jid]["finished_mono"] -= S.JOB_TTL_S + 1
        assert S.list_jobs()["count"] == 0
        assert "não encontrado" in S.get_job(jid)["error"]

    def test_so_guarda_os_mais_recentes(self, monkeypatch):
        monkeypatch.setattr(S, "JOB_MAX_KEPT", 3)
        for _ in range(5):
            espera(S.start_job(H, "t_rapida")["job_id"])
        assert S.list_jobs()["count"] <= 3


class TestValidacoes:
    def test_tool_fora_da_lista(self):
        for ruim in ("get_registry", "read_file", "start_job", "get_job", "nao_existe", "__import__"):
            with pytest.raises(ValueError, match="não permitida"):
                S.start_job(H, ruim)

    def test_argumentos_so_simples(self):
        with pytest.raises(ValueError, match="valores simples"):
            S.start_job(H, "t_lenta", {"path": {"a": 1}})
        with pytest.raises(ValueError, match="valores simples"):
            S.start_job(H, "t_lenta", {"path": object()})

    def test_argumentos_que_nao_casam_com_a_tool(self):
        with pytest.raises(ValueError, match="não casam"):
            S.start_job(H, "t_rapida", {"inexistente": 1})

    def test_job_id_invalido(self):
        for ruim in ("", "xyz", "../etc", "A" * 12, "0" * 11):
            with pytest.raises(ValueError):
                S.get_job(ruim)

    def test_job_inexistente(self):
        assert "não encontrado" in S.get_job("0" * 12)["error"]

    def test_lista_de_tools_do_job_so_tem_tools_reais_de_leitura(self):
        import inspect
        reais = (set(S.JOB_TOOLS) - {"t_lenta", "t_rapida", "t_erro", "t_grande", "t_devolve_erro"})
        for nome in reais:
            assert callable(getattr(S, nome)), nome
        assert not {"start_job", "get_job", "list_jobs"} & reais
        src = inspect.getsource(S._job_run)
        assert "fn(host" in src and "daemon" in inspect.getsource(S.start_job)


class TestAuditoria:
    def test_job_gera_registro_de_auditoria(self, tmp_path):
        import json
        from windows_rca_mcp import audit
        espera(S.start_job(H, "t_lenta" if False else "t_rapida")["job_id"])
        time.sleep(0.2)
        linhas = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        rec = json.loads(linhas[-1])
        assert rec["tool"] == "job:t_rapida" and rec["host"] == H and rec["ok"] is True
