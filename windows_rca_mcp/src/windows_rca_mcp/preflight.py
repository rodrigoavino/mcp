"""Primeiro passo de toda coleta: validar a conexão WinRM (HTTPS 5986) e AVISAR rápido se houver problema.

O que faz (só leitura, sem credenciais):
- ``probe_winrm``: DNS -> TCP na porta do WinRM -> TLS -> resposta do /wsman (sem autenticar: um listener WinRM responde 401 e
  informa os esquemas de autenticação). Em falha, diz EM QUE CAMADA parou (dns, rede, tls, serviço) e, se a porta HTTPS falhou,
  se a porta HTTP (5985) abre, que é um fato útil (listener HTTPS ausente).
- ``classify_error``: transforma o erro de uma chamada WinRM já feita (autenticação, certificado, Kerberos/domínio, prazo...)
  em categoria, camada e o que verificar.
- ``PreflightMiddleware``: antes de CADA tool que recebe 'host', roda a sonda leve (cache curto) e, se falhar, responde NA HORA
  com o diagnóstico em vez de esperar o prazo de 35 s. Só sonda hosts da allowlist (nunca abre conexão para host de fora dela).

Ajustes por ambiente: MCP_PREFLIGHT (on|off, padrão on), MCP_PREFLIGHT_TIMEOUT (s por tentativa, padrão 5),
MCP_PREFLIGHT_TTL_OK (s, padrão 60) e MCP_PREFLIGHT_TTL_FAIL (s, padrão 10). Usa WINRM_SSL, WINRM_PORT e WINRM_VALIDATE_CERT.
"""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import os
import socket
import ssl
import threading
import time

from fastmcp.server.middleware import Middleware
from fastmcp.tools.base import ToolResult
from mcp.types import TextContent

# Tools que não pedem um servidor único ou que já tratam a falha por servidor.
EXEMPT_TOOLS = frozenset({"check_winrm", "list_hosts", "list_jobs", "get_job", "run_on_hosts"})


def settings() -> dict:
    use_ssl = os.getenv("WINRM_SSL", "true").lower() == "true"
    try:
        port = int(os.getenv("WINRM_PORT") or (5986 if use_ssl else 5985))
    except ValueError:
        port = 5986 if use_ssl else 5985

    def num(name, default, lo, hi):
        try:
            return max(lo, min(float(os.getenv(name, default)), hi))
        except ValueError:
            return float(default)

    return {"use_ssl": use_ssl, "port": port, "verify": os.getenv("WINRM_VALIDATE_CERT", "validate").lower() != "ignore",
            "enabled": os.getenv("MCP_PREFLIGHT", "on").lower() != "off",
            "timeout": num("MCP_PREFLIGHT_TIMEOUT", 5, 1, 30), "ttl_ok": num("MCP_PREFLIGHT_TTL_OK", 60, 0, 600),
            "ttl_fail": num("MCP_PREFLIGHT_TTL_FAIL", 10, 0, 120)}


# ---------- somente endereços internos (OPCIONAL, desligado por padrão) ----------
# Por padrão o coletor NÃO bloqueia nada: conecta por nome ou IP em qualquer servidor que autentique. Quem quiser pode ligar
# WINRM_INTERNAL_ONLY=true: aí host que resolve para endereço público (ou IP literal público) é recusado. "Interno" = tudo que
# não é endereço global: privado (RFC 1918, fc00::/7), loopback, link-local, CGNAT e reservados. Se o nome não resolver, a
# checagem deixa passar: a falha de DNS é reportada pela própria sonda/conexão.
_ADDR_CACHE: dict = {}
_ADDR_LOCK = threading.Lock()
_ADDR_TTL = 60.0


def internal_only() -> bool:
    return os.getenv("WINRM_INTERNAL_ONLY", "false").lower() == "true"


def public_addresses(host: str, resolver=socket.getaddrinfo) -> list:
    """Endereços GLOBAIS (públicos) para os quais o nome resolve; vazio se todos são internos ou se o nome não resolve."""
    if not internal_only():
        return []
    try:                                                   # IP literal: não precisa de DNS
        ip = ipaddress.ip_address(host)
        return [str(ip)] if ip.is_global else []
    except ValueError:
        pass
    key = host.lower()
    now = time.monotonic()
    with _ADDR_LOCK:
        hit = _ADDR_CACHE.get(key)
        if hit and hit[0] > now:
            return list(hit[1])
    try:
        addrs = sorted({i[4][0] for i in resolver(host, None, type=socket.SOCK_STREAM)})
    except Exception:
        return []
    pub = []
    for a in addrs:
        try:
            if ipaddress.ip_address(a.split("%")[0]).is_global:
                pub.append(a)
        except ValueError:
            continue
    with _ADDR_LOCK:
        _ADDR_CACHE[key] = (now + _ADDR_TTL, list(pub))
    return pub


def clear_address_cache() -> None:
    with _ADDR_LOCK:
        _ADDR_CACHE.clear()


# ---------- classificação de erros ----------
# (categoria, camada, resumo, o que verificar). A ordem importa: o primeiro padrão que casar vence.
_RULES = (
    ("dns", "dns", "O nome do servidor não resolve no DNS usado pelo coletor.",
     ["Conferir o registro A do servidor e o DNS do host que roda o MCP.", "Testar com resolve_dns_name a partir de outro servidor."],
     ("nameresolutionerror", "getaddrinfo failed", "name or service not known", "nodename nor servname", "11001", "temporary failure in name resolution")),
    ("tls_certificado", "tls", "O certificado do WinRM HTTPS não foi aceito (não confiável, expirado ou o nome não confere).",
     ["Ver o certificado do listener HTTPS no servidor (winrm enumerate winrm/config/listener).",
      "WINRM_VALIDATE_CERT=ignore desliga a validação do certificado (usado no lab)."],
     ("certificate_verify_failed", "certificate verify failed", "sslcertverification", "hostname mismatch", "doesn't match", "self signed", "self-signed", "certificate has expired")),
    ("tls", "tls", "Falha no handshake TLS com a porta do WinRM.",
     ["Conferir se o listener HTTPS tem certificado válido e se a versão do TLS é aceita.", "Conferir se a porta não é de outro serviço."],
     ("sslerror", "ssl:", "wrong version number", "tlsv1 alert", "handshake")),
    ("conexao_recusada", "rede", "O servidor respondeu, mas recusou a conexão na porta do WinRM (sem listener nessa porta).",
     ["Conferir se o serviço WinRM está em execução e se há listener nessa porta.", "Conferir o firewall do servidor."],
     ("connection refused", "connectionrefusederror", "10061", "actively refused", "winerror 10061")),
    ("rede_inacessivel", "rede", "Não há rota até o servidor.",
     ["Conferir rota, VLAN e firewall entre o host do MCP e o servidor."],
     ("no route to host", "network is unreachable", "10065", "10051", "winerror 10051", "winerror 10065")),
    ("leitura_timeout", "rede", "A conexão abriu, mas a resposta demorou além do limite de leitura.",
     ["Conferir a carga do servidor e a latência da rede."],
     ("readtimeout", "read timed out")),
    ("rede_timeout", "rede", "Sem resposta na porta do WinRM (servidor desligado, porta bloqueada por firewall ou sem listener).",
     ["Conferir se o servidor está ligado e acessível na rede.", "Conferir firewall (rede e do Windows) e o listener da porta.",
      "Comparar com a porta HTTP 5985 (a sonda informa se ela abre)."],
     ("connecttimeout", "connect timeout", "timed out", "max retries exceeded")),
    ("autenticacao", "autenticação", "O servidor rejeitou as credenciais da coleta.",
     ["Conferir WINRM_USER/WINRM_PASSWORD, o formato do usuário (DOMINIO\\conta ou conta@dominio) e se a conta não está bloqueada/expirada.",
      "Conta local do servidor ou do domínio? Em servidor de domínio, conferir se o DC está acessível."],
     ("authenticationerror", "401", "credentials were rejected", "invalidcredentialserror", "logon failure", "access is denied", "unauthorized")),
    ("dominio", "domínio", "Problema ligado ao domínio ou ao Kerberos (KDC, SPN, relação de confiança ou DC inacessível).",
     ["Conferir se o servidor alcança um controlador de domínio e se o SPN WSMAN do servidor existe.", "Conferir o relógio (Kerberos tolera pouca diferença)."],
     ("kerberos", "kdc", "spn", "trust relationship", "domain controller", "krb_ap_err", "clock skew")),
    ("prazo_comando", "prazo", "A conexão funcionou, mas o comando passou do prazo e foi encerrado no servidor.",
     ["Usar start_job para coletas longas ou reduzir o escopo da consulta."],
     ("prazo de", "excedido; comando remoto", "operationtimeout")),
    ("servico_winrm", "serviço", "O servidor respondeu, mas o serviço WinRM não processou o pedido.",
     ["Conferir o estado do serviço WinRM e dos limites de memória/quotas do shell no servidor.", "Ver o log Microsoft-Windows-WinRM/Operational."],
     ("winrmtransporterror", "winrmerror", "bad http response", "wsmanfault", "service unavailable", "remote server has been paused", "code 500")),
    ("conexao_perdida", "rede", "A conexão foi encerrada no meio da chamada.",
     ["Conferir firewall/IPS entre o MCP e o servidor e se o serviço WinRM reiniciou."],
     ("connectionreseterror", "connection reset", "remotedisconnected", "connection aborted", "broken pipe")),
)


def classify_error(message: str) -> dict:
    """Erro de uma chamada WinRM -> {category, layer, summary, next_checks}. Texto desconhecido vira 'desconhecido'."""
    low = (message or "").lower()
    for cat, layer, summary, checks, needles in _RULES:
        if any(n in low for n in needles):
            return {"category": cat, "layer": layer, "summary": summary, "next_checks": list(checks)}
    return {"category": "desconhecido", "layer": "desconhecida", "summary": "Falha de conexão sem categoria conhecida.",
            "next_checks": ["Ver a mensagem de erro completa."]}


# ---------- sonda ----------
def _step(steps: list, name: str, ok: bool, t0: float, detail: str = "") -> None:
    steps.append({"step": name, "ok": ok, "ms": int((time.monotonic() - t0) * 1000), "detail": detail})


def _tcp_open(host: str, port: int, timeout: float, connector) -> tuple[bool, str]:
    try:
        s = connector((host, port), timeout)
        try:
            s.close()
        except Exception:
            pass
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def probe_winrm(host: str, port: int | None = None, *, use_ssl: bool | None = None, verify: bool | None = None,
                timeout: float | None = None, resolver=socket.getaddrinfo, connector=socket.create_connection,
                http_factory=None) -> dict:
    """Sonda leve, sem credenciais. Devolve {host, port, ok, category, layer, message, steps, auth_schemes, alt_port}.
    Etapas: dns -> tcp (2 tentativas se der timeout) -> tls+wsman (um POST /wsman sem corpo; listener WinRM responde 401)."""
    cfg = settings()
    use_ssl = cfg["use_ssl"] if use_ssl is None else use_ssl
    port = port or cfg["port"]
    verify = cfg["verify"] if verify is None else verify
    timeout = cfg["timeout"] if timeout is None else timeout
    steps: list = []
    res = {"host": host, "port": port, "ok": False, "category": None, "layer": None, "message": None, "steps": steps,
           "auth_schemes": [], "alt_port": None}

    def fail(category: str, layer: str, message: str):
        res.update(ok=False, category=category, layer=layer, message=message)
        return res

    # 1. DNS
    t0 = time.monotonic()
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        _step(steps, "dns", True, t0, ", ".join(addrs[:4]))
    except Exception as e:
        _step(steps, "dns", False, t0, f"{type(e).__name__}: {e}")
        return fail("dns", "dns", f"O nome '{host}' não resolve no DNS do host que roda o MCP.")

    # 2. TCP (uma segunda tentativa só para timeout: evita falso alarme em instabilidade curta)
    ok, detail, attempts = False, "", 0
    t0 = time.monotonic()
    for attempts in (1, 2):
        ok, detail = _tcp_open(host, port, timeout, connector)
        if ok or not ("timeout" in detail.lower() or "timed out" in detail.lower()):
            break
    _step(steps, "tcp", ok, t0, f"porta {port}" + (f" ({attempts} tentativas)" if attempts > 1 else "") + ("" if ok else f": {detail}"))
    if not ok:
        alt = 5985 if port == 5986 else 5986 if port == 5985 else None
        if alt:
            a_ok, _ = _tcp_open(host, alt, min(timeout, 2.0), connector)
            res["alt_port"] = {"port": alt, "open": a_ok}
        c = classify_error(detail)
        msg = f"A porta {port} não abriu em '{host}': {c['summary']}"
        if res["alt_port"] and res["alt_port"]["open"]:
            msg += f" A porta {alt} abre: o WinRM responde nela, mas não há listener na {port}."
        elif res["alt_port"]:
            msg += f" A porta {alt} também não abre."
        return fail(c["category"], c["layer"], msg)

    # 3. TLS + /wsman (sem autenticar)
    t0 = time.monotonic()
    try:
        if http_factory:
            conn = http_factory(host, port, timeout, use_ssl, verify)
        elif use_ssl:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("POST", "/wsman", body="", headers={"Content-Length": "0", "Content-Type": "application/soap+xml;charset=UTF-8"})
            r = conn.getresponse()
            status = r.status
            www = r.getheader("WWW-Authenticate") or ""
            r.read()
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception as e:
        txt = f"{type(e).__name__}: {e}"
        c = classify_error(txt)
        _step(steps, "tls_wsman", False, t0, txt)
        if c["category"] == "desconhecido":
            c = classify_error("sslerror") if isinstance(e, ssl.SSLError) else c
        return fail(c["category"], c["layer"], f"A porta {port} abriu, mas a conexão com o WinRM falhou: {c['summary']}")
    schemes = sorted({s.strip().split(" ")[0] for s in www.replace(",", " , ").split(",") if s.strip()} if www else set())
    schemes = [s for s in schemes if s and s.lower() in ("negotiate", "kerberos", "ntlm", "basic", "credssp")]
    res["auth_schemes"] = schemes
    if status in (401, 200, 405):
        _step(steps, "tls_wsman", True, t0, f"HTTP {status}; autenticação oferecida: {', '.join(schemes) or 'n/d'}")
        res.update(ok=True, category="ok", layer=None, message=f"WinRM respondeu em {host}:{port} (HTTP {status}).")
        return res
    _step(steps, "tls_wsman", False, t0, f"HTTP {status}")
    return fail("servico_winrm", "serviço", f"A porta {port} abriu, mas respondeu HTTP {status} em /wsman: pode não ser um listener WinRM.")


# ---------- cache e middleware ----------
class _Cache:
    def __init__(self):
        self._d: dict = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            v = self._d.get(key)
            if v and v[0] > time.monotonic():
                return v[1]
            self._d.pop(key, None)
            return None

    def put(self, key, value, ttl: float):
        if ttl <= 0:
            return
        with self._lock:
            self._d[key] = (time.monotonic() + ttl, value)

    def clear(self):
        with self._lock:
            self._d.clear()


class PreflightMiddleware(Middleware):
    """Sonda o WinRM antes de cada tool com 'host' e, se falhar, responde na hora com o diagnóstico (fail-fast).
    ``host_ok`` decide se o host pode ser sondado (nome válido e na allowlist); fora dela nada é aberto."""

    def __init__(self, host_ok, probe=probe_winrm):
        self.host_ok = host_ok
        self.probe = probe
        self.cache = _Cache()

    def check(self, host: str) -> dict:
        cfg = settings()
        key = (host.lower(), cfg["port"])
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        res = self.probe(host)
        self.cache.put(key, res, cfg["ttl_ok"] if res.get("ok") else cfg["ttl_fail"])
        return res

    async def on_call_tool(self, context, call_next):
        msg = getattr(context, "message", None)
        tool, args = getattr(msg, "name", ""), getattr(msg, "arguments", None) or {}
        host = args.get("host")
        if (not settings()["enabled"] or tool in EXEMPT_TOOLS or not isinstance(host, str) or not host or not self.host_ok(host)):
            return await call_next(context)
        res = await asyncio.to_thread(self.check, host)
        if res.get("ok"):
            return await call_next(context)
        raw = {"error": f"WinRM indisponível em {host}:{res.get('port')} ({res.get('layer')}): {res.get('message')}",
               "host": host, "diagnosis": diagnosis_from_probe(res)}
        return ToolResult(content=[TextContent(type="text", text=json.dumps(raw, ensure_ascii=False))], structured_content=raw)


def diagnosis_from_probe(res: dict) -> dict:
    """Resumo da sonda para o usuário: categoria, camada, porta, etapas, porta alternativa e o que verificar."""
    base = next((r for r in _RULES if r[0] == res.get("category")), None)
    return {"category": res.get("category"), "layer": res.get("layer"), "port": res.get("port"),
            "steps": res.get("steps"), "alt_port": res.get("alt_port"),
            "next_checks": list(base[3]) if base else ["Ver as etapas da sonda."]}
