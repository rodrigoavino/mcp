"""Pré-voo do WinRM: classificação de erros, sonda (DNS/TCP/TLS/wsman), fail-fast no middleware e a tool check_winrm."""
import asyncio
import json
import socket
import ssl

import pytest
from fastmcp import Client, FastMCP

from windows_rca_mcp import preflight as P
from windows_rca_mcp import server as S
from windows_rca_mcp.envelope import EnvelopeMiddleware, build_envelope

H = "sql01.familia.local"


@pytest.fixture(autouse=True)
def ambiente(monkeypatch):
    for k in ("MCP_PREFLIGHT", "MCP_PREFLIGHT_TIMEOUT", "MCP_PREFLIGHT_TTL_OK", "MCP_PREFLIGHT_TTL_FAIL", "WINRM_PORT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("WINRM_SSL", "true")
    monkeypatch.setenv("WINRM_VALIDATE_CERT", "ignore")


class TestClassificacao:
    @pytest.mark.parametrize("texto,categoria,camada", [
        ("ConnectionError: HTTPSConnectionPool: Max retries exceeded (Caused by NameResolutionError(Failed to resolve [Errno 11001] getaddrinfo failed))", "dns", "dns"),
        ("ConnectTimeout: HTTPSConnectionPool(host='x', port=5986): Max retries exceeded (Connection to x timed out. (connect timeout=35))", "rede_timeout", "rede"),
        ("ConnectionRefusedError: [WinError 10061] actively refused", "conexao_recusada", "rede"),
        ("OSError: [Errno 113] No route to host", "rede_inacessivel", "rede"),
        ("SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate", "tls_certificado", "tls"),
        ("SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number", "tls", "tls"),
        ("InvalidCredentialsError: the specified credentials were rejected by the server", "autenticacao", "autenticação"),
        ("AuthenticationError: 401 Unauthorized", "autenticacao", "autenticação"),
        ("Kerberos: KDC_ERR_S_PRINCIPAL_UNKNOWN, SPN not found", "dominio", "domínio"),
        ("RemoteTimeout: Prazo de 60s excedido; comando remoto encerrado.", "prazo_comando", "prazo"),
        ("ReadTimeout: HTTPSConnectionPool: Read timed out. (read timeout=35)", "leitura_timeout", "rede"),
        ("WinRMTransportError: Bad HTTP response returned from server. Code 500", "servico_winrm", "serviço"),
        ("ConnectionResetError: Connection reset by peer", "conexao_perdida", "rede"),
        ("algo que ninguém conhece", "desconhecido", "desconhecida"),
        ("", "desconhecido", "desconhecida"),
    ])
    def test_categorias(self, texto, categoria, camada):
        c = P.classify_error(texto)
        assert (c["category"], c["layer"]) == (categoria, camada) and c["summary"] and c["next_checks"]

    def test_conn_error_do_servidor_traz_diagnostico(self):
        r = S._conn_error(H, RuntimeError("the specified credentials were rejected by the server"))
        assert r["host"] == H and r["error"].startswith("RuntimeError") and r["diagnosis"]["category"] == "autenticacao"

    def test_envelope_de_falha_leva_o_diagnostico(self):
        env = build_envelope(H, {"error": "x", "host": H, "diagnosis": {"category": "dns"}})
        assert env["success"] is False and env["diagnosis"] == {"category": "dns"}
        assert "diagnosis" not in build_envelope(H, {"error": "x", "host": H})


class FakeConn:
    def __init__(self, status=401, www="Negotiate, Kerberos, NTLM", boom=None):
        self.status, self.www, self.boom = status, www, boom

    def request(self, *a, **k):
        if self.boom:
            raise self.boom

    def getresponse(self):
        outer = self

        class R:
            status = outer.status

            def getheader(self, n):
                return outer.www if n == "WWW-Authenticate" else None

            def read(self):
                return b""
        return R()

    def close(self):
        pass


def resolver_ok(host, port, type=None):
    return [(2, 1, 6, "", ("10.10.0.29", port))]


def conector(abrem=(), erro=None):
    """Conector de mentira: abre só as portas em 'abrem'; as outras levantam 'erro'."""
    chamadas = []

    def c(addr, timeout):
        chamadas.append(addr[1])
        if addr[1] in abrem:
            class S_:
                def close(self):
                    pass
            return S_()
        raise erro or TimeoutError("timed out")
    c.chamadas = chamadas
    return c


class TestSonda:
    def test_tudo_certo(self):
        r = P.probe_winrm(H, resolver=resolver_ok, connector=conector({5986}), http_factory=lambda *a: FakeConn())
        assert r["ok"] and r["category"] == "ok" and [s["step"] for s in r["steps"]] == ["dns", "tcp", "tls_wsman"]
        assert r["auth_schemes"] == ["Kerberos", "NTLM", "Negotiate"]

    def test_dns(self):
        def mau(*a, **k):
            raise socket.gaierror(11001, "getaddrinfo failed")
        r = P.probe_winrm(H, resolver=mau, connector=conector({5986}))
        assert not r["ok"] and r["category"] == "dns" and r["layer"] == "dns" and len(r["steps"]) == 1

    def test_timeout_na_5986_com_5985_aberta(self):
        c = conector({5985})
        r = P.probe_winrm(H, resolver=resolver_ok, connector=c, timeout=1)
        assert not r["ok"] and r["category"] == "rede_timeout" and r["alt_port"] == {"port": 5985, "open": True}
        assert "5985 abre" in r["message"] and "não há listener na 5986" in r["message"]
        assert c.chamadas == [5986, 5986, 5985]                # 2 tentativas na porta principal (só por timeout) e 1 na alternativa

    def test_timeout_com_as_duas_portas_fechadas(self):
        r = P.probe_winrm(H, resolver=resolver_ok, connector=conector(set()), timeout=1)
        assert r["alt_port"] == {"port": 5985, "open": False} and "também não abre" in r["message"]

    def test_recusada_nao_tenta_de_novo(self):
        c = conector(set(), ConnectionRefusedError("[WinError 10061] actively refused"))
        r = P.probe_winrm(H, resolver=resolver_ok, connector=c, timeout=1)
        assert r["category"] == "conexao_recusada" and c.chamadas.count(5986) == 1

    def test_certificado_recusado(self):
        erro = ssl.SSLCertVerificationError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")
        r = P.probe_winrm(H, resolver=resolver_ok, connector=conector({5986}), http_factory=lambda *a: FakeConn(boom=erro))
        assert not r["ok"] and r["category"] == "tls_certificado" and r["layer"] == "tls"

    def test_porta_aberta_que_nao_e_winrm(self):
        r = P.probe_winrm(H, resolver=resolver_ok, connector=conector({5986}), http_factory=lambda *a: FakeConn(status=404, www=""))
        assert not r["ok"] and r["category"] == "servico_winrm" and "HTTP 404" in r["message"]

    def test_porta_configurada_em_winrm_port(self, monkeypatch):
        monkeypatch.setenv("WINRM_PORT", "15986")
        c = conector({15986})
        r = P.probe_winrm(H, resolver=resolver_ok, connector=c, http_factory=lambda *a: FakeConn())
        assert r["ok"] and r["port"] == 15986

    def test_sem_credenciais_na_sonda(self):
        import inspect
        src = inspect.getsource(P)
        for var in ("WINRM_PASSWORD", "WINRM_USER"):
            assert f'getenv("{var}"' not in src and f'environ["{var}"' not in src       # a sonda não lê credenciais


def app_com_preflight(host_ok, probe):
    app = FastMCP("t")
    app.add_middleware(EnvelopeMiddleware())
    mw = P.PreflightMiddleware(host_ok, probe)
    app.add_middleware(mw)
    execs = []

    @app.tool
    def get_x(host: str):
        execs.append(host)
        return {"host": host, "v": 1}

    @app.tool
    def list_hosts(host: str | None = None):
        execs.append("list_hosts")
        return {"ok": True}

    @app.tool
    def sem_host(n: int = 1):
        execs.append("sem_host")
        return {"n": n}
    return app, mw, execs


def chama(app, nome, **args):
    async def go():
        async with Client(app) as c:
            return json.loads((await c.call_tool(nome, args)).content[0].text)
    return asyncio.run(go())


def sonda_fake(ok=True, **extra):
    chamadas = []

    def p(host):
        chamadas.append(host)
        base = {"host": host, "port": 5986, "ok": ok, "category": "ok" if ok else "rede_timeout", "layer": None if ok else "rede",
                "message": "ok" if ok else "A porta 5986 não abriu.", "steps": [{"step": "tcp", "ok": ok}], "auth_schemes": [],
                "alt_port": {"port": 5985, "open": True} if not ok else None}
        base.update(extra)
        return base
    p.chamadas = chamadas
    return p


class TestMiddleware:
    def test_conexao_ok_executa_a_tool_e_usa_cache(self):
        p = sonda_fake(True)
        app, mw, execs = app_com_preflight(lambda h: True, p)
        assert chama(app, "get_x", host=H)["success"] is True
        assert chama(app, "get_x", host=H)["success"] is True
        assert execs == [H, H] and p.chamadas == [H]                      # a sonda rodou UMA vez (cache)

    def test_falha_responde_na_hora_com_diagnostico_e_nao_executa_a_tool(self):
        p = sonda_fake(False)
        app, mw, execs = app_com_preflight(lambda h: True, p)
        r = chama(app, "get_x", host=H)
        assert r["success"] is False and execs == []
        assert "WinRM indisponível" in r["error"] and H in r["error"] and "rede" in r["error"]
        d = r["diagnosis"]
        assert d["category"] == "rede_timeout" and d["alt_port"] == {"port": 5985, "open": True} and d["next_checks"]

    def test_falha_tambem_fica_em_cache_curto(self):
        p = sonda_fake(False)
        app, mw, execs = app_com_preflight(lambda h: True, p)
        chama(app, "get_x", host=H)
        chama(app, "get_x", host=H)
        assert p.chamadas == [H]

    def test_ttl_zero_nao_guarda_cache(self, monkeypatch):
        monkeypatch.setenv("MCP_PREFLIGHT_TTL_OK", "0")
        p = sonda_fake(True)
        app, mw, execs = app_com_preflight(lambda h: True, p)
        chama(app, "get_x", host=H)
        chama(app, "get_x", host=H)
        assert p.chamadas == [H, H]

    def test_host_fora_da_allowlist_nao_e_sondado(self):
        p = sonda_fake(False)
        app, mw, execs = app_com_preflight(lambda h: False, p)
        r = chama(app, "get_x", host="externo.exemplo.com")
        assert p.chamadas == [] and execs == ["externo.exemplo.com"]        # a tool segue e aplica a própria validação
        assert r["success"] is True

    def test_tools_isentas_e_sem_host_nao_sondam(self):
        p = sonda_fake(False)
        app, mw, execs = app_com_preflight(lambda h: True, p)
        chama(app, "list_hosts", host=H)
        chama(app, "sem_host")
        assert p.chamadas == [] and execs == ["list_hosts", "sem_host"]

    def test_desligado_por_ambiente(self, monkeypatch):
        monkeypatch.setenv("MCP_PREFLIGHT", "off")
        p = sonda_fake(False)
        app, mw, execs = app_com_preflight(lambda h: True, p)
        assert chama(app, "get_x", host=H)["success"] is True and p.chamadas == []

    def test_servidores_diferentes_tem_cache_separado(self):
        p = sonda_fake(True)
        app, mw, execs = app_com_preflight(lambda h: True, p)
        chama(app, "get_x", host="a.familia.local")
        chama(app, "get_x", host="b.familia.local")
        assert p.chamadas == ["a.familia.local", "b.familia.local"]


class TestRegrasDoServidor:
    def test_so_sonda_host_valido_e_da_allowlist(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        assert S._preflight_host_ok("sql01.familia.local") is True
        assert S._preflight_host_ok("externo.exemplo.com") is False
        assert S._preflight_host_ok("a b") is False and S._preflight_host_ok("a;b.familia.local") is False
        monkeypatch.setattr(S, "ALLOWED", [])
        assert S._preflight_host_ok("sql01.familia.local") is False

    def test_middleware_do_servidor_esta_depois_do_envelope(self):
        nomes = [type(m).__name__ for m in S.mcp.middleware]
        assert nomes.index("EnvelopeMiddleware") < nomes.index("PreflightMiddleware")
        assert nomes.index("AuditMiddleware") < nomes.index("EnvelopeMiddleware")

    def test_instrucoes_mandam_avisar_na_hora(self):
        assert "PRIMEIRO PASSO" in S.INSTRUCTIONS and "IMEDIATAMENTE" in S.INSTRUCTIONS and "check_winrm" in S.INSTRUCTIONS

    def test_check_winrm_entra_no_run_on_hosts(self):
        assert "check_winrm" in S.FANOUT_TOOLS


class TestCheckWinrm:
    @pytest.fixture(autouse=True)
    def permitido(self, monkeypatch):
        monkeypatch.setattr(S, "ALLOWED", ["*"])

    def test_problema_na_sonda_avisa(self, monkeypatch):
        monkeypatch.setattr(S, "probe_winrm", lambda host: sonda_fake(False)(host))
        monkeypatch.setattr(S, "_ps", lambda *a, **k: pytest.fail("não deve executar comando com a sonda falhando"))
        r = S.check_winrm(H)
        assert r["ok"] is False and r["category"] == "rede_timeout" and r["warning"].startswith("ATENÇÃO") and r["next_checks"]

    def test_tudo_ok_confirma_a_autenticacao(self, monkeypatch):
        monkeypatch.setattr(S, "probe_winrm", lambda host: sonda_fake(True)(host))
        monkeypatch.setattr(S, "_ps", lambda host, script, timeout=60: {"Computer": "SQL01"})
        r = S.check_winrm(H)
        assert r["ok"] is True and r["computer"] == "SQL01" and "warning" not in r
        assert r["steps"][-1]["step"] == "autenticacao_comando" and r["steps"][-1]["ok"] is True

    def test_sem_testar_autenticacao_nao_executa_comando(self, monkeypatch):
        monkeypatch.setattr(S, "probe_winrm", lambda host: sonda_fake(True)(host))
        monkeypatch.setattr(S, "_ps", lambda *a, **k: pytest.fail("test_auth=False não executa comando"))
        assert S.check_winrm(H, test_auth=False)["ok"] is True

    def test_credencial_rejeitada_vira_autenticacao(self, monkeypatch):
        monkeypatch.setattr(S, "probe_winrm", lambda host: sonda_fake(True)(host))
        monkeypatch.setattr(S, "_ps", lambda *a, **k: S._conn_error(H, RuntimeError("the specified credentials were rejected by the server")))
        r = S.check_winrm(H)
        assert r["ok"] is False and r["category"] == "autenticacao" and r["layer"] == "autenticação"
        assert r["warning"].startswith("ATENÇÃO") and r["steps"][-1]["ok"] is False

    def test_host_invalido_ou_fora_da_allowlist(self, monkeypatch):
        with pytest.raises(ValueError):
            S.check_winrm("a;b")
        monkeypatch.setattr(S, "ALLOWED", ["*.familia.local"])
        with pytest.raises(ValueError, match="allowlist"):
            S.check_winrm("externo.exemplo.com")
        monkeypatch.setattr(S, "ALLOWED", [])
        with pytest.raises(ValueError, match="WINRM_ALLOWED_HOSTS"):
            S.check_winrm(H)
