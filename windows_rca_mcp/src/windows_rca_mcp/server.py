"""MCP (FastMCP) de OPS para Windows Server via WinRM (HTTPS/5986 por padrão).

Somente leitura: nenhuma tool executa comando arbitrário nem altera o servidor.

Variáveis de ambiente (podem vir de um arquivo .env no diretório de trabalho):
  WINRM_USER, WINRM_PASSWORD     credenciais (use conta de serviço com menor privilégio)
  WINRM_TRANSPORT                ntlm (padrão) | kerberos | credssp | basic
  WINRM_SSL                      true (padrão) -> HTTPS | false -> HTTP
  WINRM_PORT                     porta (padrão 5986 com SSL, 5985 sem SSL)
  WINRM_VALIDATE_CERT            validate (padrão) | ignore
  WINRM_ALLOWED_HOSTS            OBRIGATÓRIA: allowlist separada por vírgula; aceita curingas (*.dominio.local).
                                 '*' libera qualquer host (opt-in explícito, não recomendado).
  WINRM_ENV_FILE                 caminho explícito do .env (opcional; padrão: .env do diretório de trabalho)
"""
import base64
import fnmatch
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import winrm
from dotenv import find_dotenv, load_dotenv
from fastmcp import FastMCP

from .audit import AuditMiddleware
from .envelope import EnvelopeMiddleware

# O .env é procurado a partir do DIRETÓRIO DE TRABALHO (usecwd=True), e não da pasta do pacote, para funcionar
# também quando instalado via wheel em site-packages.
load_dotenv(os.getenv("WINRM_ENV_FILE") or find_dotenv(usecwd=True))

# Padrão de resposta decidido pelo usuário; o texto abaixo é entregue ao Claude quando ele conecta neste MCP.
INSTRUCTIONS = """windows-ops: COLETA somente leitura de servidores Windows. Padrão de resposta (decidido pelo usuário):
1. Responda SÓ o que foi perguntado, de forma enxuta (tabela curta). Em uma linha, SUGIRA o que mais pode ser obtido; só colete mais se o usuário autorizar. Não chame tools extras "por precaução" nem traga boot, uptime, disco, CPU, memória, serviços, usuários, eventos, volumes ou adaptadores se não foram pedidos, não são necessários à resposta e não são erro/diagnóstico relacionado.
2. Use a tool e o filtro mais estreitos (ex.: installed_since_days para "o que foi instalado hoje").
3. Toda tool responde {computerName, timestamp, success, data}; as datas saem em GMT-3 (-03:00). Análises completas acrescentam os e summary {status, findings}. moreAvailable é só uma sugestão.
4. Este MCP afirma só FATOS e sinais objetivos (existe, online, acima de X, diverge da baseline, falhou, corrompido). Nunca melhor prática, recomendação, "inadequado", "deve ser alterado" ou classificação de serviço: isso é do microsoft-docs, e só para pergunta de recomendação, suporte, compatibilidade ou boa prática. Inventário, configuração, serviços, usuários, grupos, discos, eventos, SIDs, RIDs e status nunca disparam consulta externa.
5. Nunca presuma a função do servidor (ex.: SQL Server) sem evidência (get_workload_evidence); sem evidência vale só o SO e a versão.
6. Data de instalação de software é fato LOCAL: registro, instalação por usuário, eventos MsiInstaller, Package Management, sistema de arquivos, com a confiança informada. Nunca internet.
7. Nada inventado: o que não foi coletado não é afirmado."""
mcp = FastMCP("windows-server-ops", instructions=INSTRUCTIONS)
mcp.add_middleware(AuditMiddleware())   # por fora do envelope: registra tool, host, resultado e duração (sem o conteúdo)
mcp.add_middleware(EnvelopeMiddleware())

ALLOWED = [h.strip().lower() for h in os.getenv("WINRM_ALLOWED_HOSTS", "").split(",") if h.strip()]
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
NAME_RE = re.compile(r"^[A-Za-z0-9 ._/-]{1,100}$")


def _host_allowed(host: str) -> bool:
    h = host.lower()
    return any(p == "*" or fnmatch.fnmatchcase(h, p) for p in ALLOWED)

# Funções PowerShell injetadas em todo script.
# Msg: normaliza espaços e trunca a mensagem do evento com segurança (eventos podem vir sem Message).
PS_HELPERS = r"""
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}
function Msg($m, $n) { if (-not $m) { return $null }; $t = ($m -replace '\s+', ' ').Trim(); $t.Substring(0, [math]::Min($n, $t.Length)) }
"""

# Leitor RÁPIDO de eventos (injetado só nas tools que leem muitos eventos). Get-WinEvent renderiza a mensagem de
# TODO evento (medido no lab: 7,7 s para 319 eventos do TaskScheduler); EventLogReader devolve o registro cru
# (28 ms) e a mensagem só é montada sob demanda, com Desc, para as amostras.
# Ev: mais recentes primeiro, no máximo $m registros. Log inexistente lança exceção: use try/catch.
PS_EV = r"""
function Ev($l, $x, $m = 20000) {
  $q = New-Object Diagnostics.Eventing.Reader.EventLogQuery($l, 'LogName', $x); $q.ReverseDirection = $true
  $r = New-Object Diagnostics.Eventing.Reader.EventLogReader($q); $n = 0
  while ($n -lt $m -and ($e = $r.ReadEvent())) { $n++; $e }
}
function Desc($e, $n = 300) {
  $d = try { $e.FormatDescription() } catch { $null }
  if (-not $d) { $d = '(sem descrição do provedor) ' + ((@($e.Properties) | % { "$($_.Value)" }) -join ' | ') }
  Msg $d $n
}
"""


def _xpath(levels=None, ids=None, provider: str | None = None, days: int | None = None) -> str:
    """Filtro XPath do Event Log (avaliado no serviço de log). Level 4 inclui 0 (LogAlways), como o Get-WinEvent."""
    c = []
    if levels:
        lv = sorted({int(x) for x in levels} | ({0} if 4 in {int(x) for x in levels} else set()))
        c.append("(" + " or ".join(f"Level={x}" for x in lv) + ")")
    if ids:
        c.append("(" + " or ".join(f"EventID={int(i)}" for i in ids) + ")")
    if provider:
        if not NAME_RE.match(provider):
            raise ValueError("provider inválido")
        c.append(f"Provider[@Name='{provider}']")
    if days:
        c.append(f"TimeCreated[timediff(@SystemTime) <= {int(days) * 86400000}]")
    return "*[System[" + " and ".join(c) + "]]" if c else "*"


# Só para as tools de DISM (não é injetado em todo script, para não inflar o tamanho dos comandos).
PS_DISM = r"""
function RunDism($a, $sec) {
  if (Get-Process dism -ErrorAction SilentlyContinue) {
    return [pscustomobject]@{ ExitCode=$null; Output='Outra instância do DISM já está em execução neste servidor; não foi iniciada uma nova.'; Busy=$true; TimedOut=$false } }
  $psi = New-Object Diagnostics.ProcessStartInfo "$env:SystemRoot\System32\dism.exe", $a
  $psi.RedirectStandardOutput = $true; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $p = [Diagnostics.Process]::Start($psi); $t = $p.StandardOutput.ReadToEndAsync()
  if (-not $p.WaitForExit($sec * 1000)) { try { $p.Kill() } catch {}
    return [pscustomobject]@{ ExitCode=$null; Output="DISM excedeu $sec s e foi encerrado."; Busy=$false; TimedOut=$true } }
  [pscustomobject]@{ ExitCode=$p.ExitCode; Output=$t.Result.Trim(); Busy=$false; TimedOut=$false }
}
"""


# ---------- infraestrutura WinRM ----------
def _session(host: str, timeout: int = 60) -> winrm.Session:
    if not HOST_RE.match(host):
        raise ValueError("Hostname inválido")
    # Fail-closed: credenciais só são enviadas a hosts explicitamente permitidos (evita que texto injetado em
    # logs/eventos leve o modelo a autenticar em um host do atacante).
    if not ALLOWED:
        raise ValueError("WINRM_ALLOWED_HOSTS não configurada: defina os servidores permitidos "
                         "(ex.: *.dominio.local,srv01) no .env. Use '*' apenas conscientemente.")
    if not _host_allowed(host):
        raise ValueError(f"Host '{host}' fora da allowlist WINRM_ALLOWED_HOSTS")
    user, pwd = os.getenv("WINRM_USER"), os.getenv("WINRM_PASSWORD")
    if not user or not pwd:
        raise ValueError("WINRM_USER/WINRM_PASSWORD não configurados (defina no .env ou no ambiente)")
    use_ssl = os.getenv("WINRM_SSL", "true").lower() == "true"
    scheme = "https" if use_ssl else "http"
    port = int(os.getenv("WINRM_PORT") or (5986 if use_ssl else 5985))
    return winrm.Session(
        f"{scheme}://{host}:{port}/wsman",
        auth=(user, pwd),
        transport=os.getenv("WINRM_TRANSPORT", "ntlm"),
        server_cert_validation=os.getenv("WINRM_VALIDATE_CERT", "validate"),
        # Cada Receive espera no máximo 20 s; o prazo TOTAL da tool é controlado em _run_ps.
        operation_timeout_sec=min(int(timeout), 20),
        read_timeout_sec=min(int(timeout), 20) + 15,
    )


class RemoteTimeout(Exception):
    pass


# Script grande: o corpo vai pelo STDIN do powershell.exe (sem limite de ~8 KB da linha de comando e sem arquivo
# temporário) e este stub curto, passado em -EncodedCommand, lê, decodifica e executa no mesmo processo.
_STDIN_STUB = ("$ErrorActionPreference='Stop';"
               "$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()));"
               "Invoke-Expression $c")
_STDIN_BLOCK = 32000


def _run_ps(host: str, script: str, timeout: int, via_stdin: bool = False) -> tuple[int, bytes, bytes]:
    """Executa PowerShell com PRAZO TOTAL real. O run_ps do pywinrm fica consultando a saída indefinidamente;
    aqui, se o prazo estourar, o shell remoto é fechado, o que encerra o powershell.exe e seus processos filhos
    no servidor (nada fica órfão). via_stdin=True envia o script pelo stdin (scripts grandes, 1 só processo)."""
    import time
    from winrm.exceptions import WinRMOperationTimeoutError

    proto = _session(host, timeout).protocol
    enc = base64.b64encode((_STDIN_STUB if via_stdin else script).encode("utf_16_le")).decode("ascii")
    shell = proto.open_shell()
    cmd = None
    try:
        cmd = proto.run_command(shell, "powershell", ["-NoProfile", "-NonInteractive", "-EncodedCommand", enc])
        if via_stdin:
            payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
            blocks = [payload[i:i + _STDIN_BLOCK] for i in range(0, len(payload), _STDIN_BLOCK)] or [""]
            for i, blk in enumerate(blocks):
                proto.send_command_input(shell, cmd, blk, end=i == len(blocks) - 1)
        deadline = time.monotonic() + int(timeout)
        out, err, code, done = [], [], 0, False
        while not done:
            if time.monotonic() > deadline:
                raise RemoteTimeout(f"Prazo de {timeout}s excedido; comando remoto encerrado.")
            try:
                o, e, code, done = proto.get_command_output_raw(shell, cmd)
                out.append(o)
                err.append(e)
            except WinRMOperationTimeoutError:
                continue
        return code, b"".join(out), b"".join(err)
    finally:
        try:
            if cmd:
                proto.cleanup_command(shell, cmd)
        except Exception:
            pass
        try:
            proto.close_shell(shell)
        except Exception:
            pass


DATE_RE = re.compile(r"\\/Date\((-?\d+)(?:[+-]\d+)?\)\\/")


def _fmt_date(ms: int) -> str:
    """/Date(ms)/ do PowerShell -> ISO UTC. Datas fora do intervalo do Windows (ex.: 1600-12-31 de 'sem data') não derrubam
    a resposta: viram null e o campo fica ausente de significado."""
    try:
        return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return "0001-01-01T00:00:00Z"


def _conn_error(host: str, e: Exception) -> dict:
    return {"error": f"{type(e).__name__}: {str(e)[:1000]}", "host": host}


CLIXML_ERR_RE = re.compile(r'<S S="Error">(.*?)</S>', re.S)


def _clean_err(raw: bytes) -> str:
    """Extrai só as mensagens de erro do stderr em CLIXML (descarta registros de progresso)."""
    txt = raw.decode(errors="replace")
    if txt.startswith("#< CLIXML"):
        parts = CLIXML_ERR_RE.findall(txt)
        txt = "".join(parts).replace("_x000D_", "").replace("_x000A_", "\n")
        for a, b in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&apos;", "'"), ("&amp;", "&")):
            txt = txt.replace(a, b)
    return txt.strip()[:2000]


def _flatten_dates(o):
    """PowerShell 5.1 serializa alguns DateTime como {"value": ..., "DateTime": "..."}; reduz para o valor."""
    if isinstance(o, list):
        return [_flatten_dates(x) for x in o]
    if isinstance(o, dict):
        if set(o) == {"value", "DateTime"}:
            return o["value"]
        return {k: _flatten_dates(v) for k, v in o.items()}
    return o


def _ps(host: str, script: str, timeout: int = 60):
    """Executa PowerShell e devolve JSON já parseado (datas convertidas para ISO 8601 UTC).
    O 'exit 0' final evita falso erro: o powershell.exe sai com 1 quando o último comando teve um erro
    suprimido (-ErrorAction SilentlyContinue). Erros reais (terminating) interrompem antes e saem com 1."""
    full = "$ErrorActionPreference='Stop'\n" + PS_HELPERS + script + "\nexit 0"
    # Linha de comando aceita ~8 KB e base64 de UTF-16 infla ~2,7x: acima disso o script vai pelo stdin.
    return _exec(host, full, timeout, via_stdin=len(full) * 8 // 3 > 7500)


def _exec(host: str, full: str, timeout: int, via_stdin: bool):
    try:
        code, so, se = _run_ps(host, full, timeout, via_stdin)
    except ValueError:
        raise
    except Exception as e:  # prazo excedido, timeout, autenticação, SSL, rede
        return _conn_error(host, e)
    if code != 0:
        return {"error": _clean_err(se) or f"exit code {code}", "host": host}
    out = so.decode(errors="replace").strip()
    out = DATE_RE.sub(lambda m: _fmt_date(int(m.group(1))), out)
    if not out:
        return []
    try:
        return _flatten_dates(json.loads(out))
    except json.JSONDecodeError:
        return {"raw": out[:20000]}


def _ps_long(host: str, script: str, timeout: int = 300):
    """Scripts grandes (ex.: scanner C# do get_disk_usage_tree): sempre via stdin, em UM processo e sem gravar
    nada no servidor. Mesmo tratamento de erro/JSON do _ps."""
    full = "$ErrorActionPreference='Stop'\n" + PS_HELPERS + script + "\nexit 0"
    return _exec(host, full, timeout, via_stdin=True)


def _ints(values) -> str:
    return ",".join(str(int(v)) for v in values)


MAX_LOG_DAYS = 90
MAX_LOG_HOURS = 24 * 30


def _hours(h) -> int:
    """Janela em horas, limitada a 1..720."""
    return max(1, min(int(h), MAX_LOG_HOURS))


def _days(d) -> int:
    """Período de coleta de logs: padrão 1 dia (análise rápida), ampliável até MAX_LOG_DAYS se pedido."""
    return max(1, min(int(d), MAX_LOG_DAYS))


# Relógio e fuso DO SERVIDOR (fatos). O UTC sai como 'aaaa-mm-dd hh:mm:ss UTC' (e não ISO com Z) de propósito: o envelope
# converte datas ISO UTC para GMT-3, e aqui o valor é justamente a leitura bruta do relógio do servidor.
PS_CLOCK = r"""([pscustomobject]@{
  TimeZoneId=(Get-TimeZone).Id; TimeZoneName=(Get-TimeZone).DisplayName; BaseUtcOffset="$((Get-TimeZone).BaseUtcOffset)"
  CurrentUtcOffset="$([TimeZoneInfo]::Local.GetUtcOffset((Get-Date)))"
  SupportsDaylightSaving=[bool](Get-TimeZone).SupportsDaylightSavingTime
  DaylightSavingNow=[TimeZoneInfo]::Local.IsDaylightSavingTime((Get-Date))
  ServerLocalTime=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
  ServerUtcTime=((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC') })"""


# ---------- tools ----------
@mcp.tool
def get_system_overview(host: str):
    """Versão do SO, uptime, último boot, CPU/RAM total, domínio e RELÓGIO do servidor (fuso, deslocamento UTC, hora
    local e hora UTC lidas no próprio servidor, em 'Clock')."""
    return _ps(host, r"""
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
[pscustomobject]@{
  Host=$env:COMPUTERNAME; OS=$os.Caption; Build=$os.BuildNumber
  LastBoot=$os.LastBootUpTime; UptimeHours=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours,1)
  Domain=$cs.Domain; Sockets=$cs.NumberOfProcessors; LogicalCPUs=$cs.NumberOfLogicalProcessors
  RAM_GB=[math]::Round($cs.TotalPhysicalMemory/1GB,1)
  FreeRAM_GB=[math]::Round($os.FreePhysicalMemory/1MB,1)
  Clock=__CLOCK__
} | ConvertTo-Json -Depth 3 -Compress
""".replace("__CLOCK__", PS_CLOCK))


PERF_MAX_SAMPLES = 10
PERF_MAX_INTERVAL = 10
PERF_MAX_PROCS = 30
PERF_PROC_RE = re.compile(r"^[A-Za-z0-9*?._#-]{1,100}$")


def _perf_args(samples, interval_sec) -> tuple[int, int]:
    return max(1, min(int(samples), PERF_MAX_SAMPLES)), max(1, min(int(interval_sec), PERF_MAX_INTERVAL))


def _perf_shape(res):
    """Lista de processos sempre lista (um único objeto do ConvertTo-Json vira lista)."""
    if isinstance(res, dict) and "Samples" in res:
        res["Processes"] = [p for p in _lst(res.get("Processes")) if isinstance(p, dict)]
    return res


@mcp.tool
def get_performance_snapshot(host: str, samples: int = 3, interval_sec: int = 2, process_filter: str | None = None):
    """Desempenho do servidor com MÉDIA de várias amostras (padrão 3 amostras, 2 s entre elas; samples 1-10,
    interval_sec 1-10; samples=1 devolve um instante): CPU (total, privilegiado, interrupções, fila, máximo da CPU),
    memória (disponível, comprometida, paginação, pool não paginado), disco (latência de leitura/escrita, fila e
    máximo da fila, IOPS, MB/s de leitura e escrita, % ocupado), rede (MB/s somando as interfaces e conexões TCP
    estabelecidas) e sistema (processos e threads). 'process_filter' (wildcard no nome do processo, ex.: 'sqlservr*')
    acrescenta por processo a média de CPU, memória privada, handles, threads e I/O (até 30). Usa classes CIM
    (independe do idioma do Windows, ao contrário do Get-Counter). Só fatos."""
    n, iv = _perf_args(samples, interval_sec)
    if process_filter is not None and not PERF_PROC_RE.match(process_filter):
        raise ValueError("process_filter inválido (letras, números, '*', '?', '.', '-', '_' e '#')")
    res = _ps(host, r"""
$n = __S__; $iv = __I__; $flt = '__F__'
$rows = @()
for ($i = 0; $i -lt $n; $i++) {
  if ($i -gt 0) { Start-Sleep -Seconds $iv }
  $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor | ? Name -eq '_Total'
  $mem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
  $sys = Get-CimInstance Win32_PerfFormattedData_PerfOS_System
  $dsk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk | ? Name -eq '_Total'
  $tcp = Get-CimInstance Win32_PerfFormattedData_Tcpip_TCPv4
  $net = @(Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface)
  $pr = @(); if ($flt) { $pr = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | ? { $_.Name -like $flt -and $_.Name -notin '_Total','Idle' }) }
  $rows += [pscustomobject]@{
    CpuPct=[double]$cpu.PercentProcessorTime; CpuPrivilegedPct=[double]$cpu.PercentPrivilegedTime
    CpuInterruptPct=[double]$cpu.PercentInterruptTime; ProcessorQueue=[double]$sys.ProcessorQueueLength
    ContextSwitchesSec=[double]$sys.ContextSwitchesPersec; Processes=[double]$sys.Processes; Threads=[double]$sys.Threads
    MemAvailableMB=[double]$mem.AvailableMBytes; MemCommittedPct=[double]$mem.PercentCommittedBytesInUse
    PagesPerSec=[double]$mem.PagesPersec; PoolNonpagedMB=[double]$mem.PoolNonpagedBytes/1MB
    DiskReadMs=[double]$dsk.AvgDisksecPerRead*1000; DiskWriteMs=[double]$dsk.AvgDisksecPerWrite*1000
    DiskQueue=[double]$dsk.CurrentDiskQueueLength; DiskIOPS=[double]$dsk.DiskTransfersPersec; DiskBusyPct=[double]$dsk.PercentDiskTime
    DiskReadMBs=[double]$dsk.DiskReadBytesPersec/1MB; DiskWriteMBs=[double]$dsk.DiskWriteBytesPersec/1MB
    NetworkMBs=[double](($net | measure BytesTotalPersec -Sum).Sum)/1MB; TcpEstablished=[double]$tcp.ConnectionsEstablished
    Procs=$pr }
}
function Avg($p) { [math]::Round((($rows | % { $_.$p }) | measure -Average).Average, 2) }
function Mx($p) { [math]::Round((($rows | % { $_.$p }) | measure -Maximum).Maximum, 2) }
$procs = @(); if ($flt) {
  $procs = @($rows.Procs | group Name | % { $g = $_.Group; [pscustomobject]@{
    Name=$_.Name; Pid=($g | select -First 1).IDProcess
    CpuPct=[math]::Round((($g | measure PercentProcessorTime -Average).Average),1)
    PrivateMB=[math]::Round((($g | measure WorkingSetPrivate -Average).Average)/1MB,1)
    Handles=[int](($g | measure HandleCount -Average).Average); Threads=[int](($g | measure ThreadCount -Average).Average)
    IoReadKBs=[math]::Round((($g | measure IOReadBytesPersec -Average).Average)/1KB,1)
    IoWriteKBs=[math]::Round((($g | measure IOWriteBytesPersec -Average).Average)/1KB,1) } } | sort CpuPct -Descending | select -First __P__)
}
[pscustomobject]@{
  Samples=$n; IntervalSec=$(if ($n -gt 1) { $iv } else { 0 })
  CpuPct=(Avg CpuPct); CpuPctMax=(Mx CpuPct); CpuPrivilegedPct=(Avg CpuPrivilegedPct); CpuInterruptPct=(Avg CpuInterruptPct)
  ProcessorQueue=(Avg ProcessorQueue); ContextSwitchesSec=(Avg ContextSwitchesSec)
  ProcessCount=[int](Avg Processes); Threads=[int](Avg Threads)
  MemAvailableMB=(Avg MemAvailableMB); MemCommittedPct=(Avg MemCommittedPct); PagesPerSec=(Avg PagesPerSec)
  PoolNonpagedMB=(Avg PoolNonpagedMB)
  DiskReadMs=(Avg DiskReadMs); DiskWriteMs=(Avg DiskWriteMs); DiskQueue=(Avg DiskQueue); DiskQueueMax=(Mx DiskQueue)
  DiskIOPS=(Avg DiskIOPS); DiskBusyPct=(Avg DiskBusyPct); DiskReadMBs=(Avg DiskReadMBs); DiskWriteMBs=(Avg DiskWriteMBs)
  NetworkMBs=(Avg NetworkMBs); TcpEstablished=[int](Avg TcpEstablished)
  Processes=$procs } | ConvertTo-Json -Depth 4 -Compress
""".replace("__S__", str(n)).replace("__I__", str(iv)).replace("__P__", str(PERF_MAX_PROCS))
       .replace("__F__", process_filter or ""), timeout=(n - 1) * iv + 90)
    return _perf_shape(res)


@mcp.tool
def get_top_processes(host: str, sort_by: str = "cpu", top: int = 15, name_filter: str | None = None):
    """Top processos por 'cpu' ou 'memory' (valores instantâneos). name_filter (wildcard no nome, ex.: 'sqlservr*',
    'w3wp*') limita aos processos que casam; as instâncias aparecem como 'nome#n' quando há várias."""
    if sort_by not in ("cpu", "memory"):
        raise ValueError("sort_by deve ser cpu ou memory")
    if name_filter is not None and not PERF_PROC_RE.match(name_filter):
        raise ValueError("name_filter inválido (letras, números, '*', '?', '.', '-', '_' e '#')")
    key = "PercentProcessorTime" if sort_by == "cpu" else "WorkingSetPrivate"
    flt = f" -and $_.Name -like '{name_filter}'" if name_filter else ""
    return _ps(host, rf"""
Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
  ? {{ $_.Name -notin '_Total','Idle'{flt} }} | sort {key} -desc | select -first {max(1, min(int(top), 100))} |
  select Name,IDProcess,PercentProcessorTime,
    @{{n='PrivateMB';e={{[math]::Round($_.WorkingSetPrivate/1MB,1)}}}},ThreadCount,HandleCount |
  ConvertTo-Json -Compress
""")


@mcp.tool
def get_events(
    host: str,
    log_name: str = "System",
    days: int = 1,
    levels: list[int] = [1, 2, 3],
    event_ids: list[int] | None = None,
    provider: str | None = None,
    max_events: int = 50,
    hours: int | None = None,
):
    """Eventos de PROBLEMA do Event Viewer: por padrão só Crítico(1), Erro(2) e Aviso(3) do último dia.
    days: período (padrão 1; aumente só se o usuário pedir análise de mais dias, máx. 90).
    hours: janela em HORAS (1 a 720), para "últimas 6 horas"; quando informado, substitui 'days'.
    levels: 1=Crítico, 2=Erro, 3=Aviso (4=Info só se pedido explicitamente)."""
    if not NAME_RE.match(log_name) or (provider and not NAME_RE.match(provider)):
        raise ValueError("log_name/provider inválido")
    if not levels or any(int(lv) not in (1, 2, 3, 4, 5) for lv in levels):
        raise ValueError("levels deve conter valores entre 1 e 5")
    start = f"AddHours(-{_hours(hours)})" if hours is not None else f"AddDays(-{_days(days)})"
    flt = f"LogName='{log_name}'; StartTime=(Get-Date).{start}; Level={_ints(levels)}"
    if event_ids:
        flt += f"; Id={_ints(event_ids)}"
    if provider:
        flt += f"; ProviderName='{provider}'"
    return _ps(host, rf"""
Get-WinEvent -FilterHashtable @{{{flt}}} -MaxEvents {min(int(max_events), 200)} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,LevelDisplayName,ProviderName,
    @{{n='Message';e={{Msg $_.Message 500}}}} |
  ConvertTo-Json -Compress
""")


EVENT_CAP = 20000          # máximo de eventos lidos por log em get_event_summary
LOGON_CAP = 5000           # máximo de eventos 4625 lidos em get_failed_logons
EVENT_LOGS_DEFAULT = ["System", "Application", "Setup"]
EVENT_LOGS_OPERATIONAL = [
    "Microsoft-Windows-GroupPolicy/Operational",
    "Microsoft-Windows-WindowsUpdateClient/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-SMBClient/Connectivity",
    "Microsoft-Windows-Time-Service/Operational",
    "Microsoft-Windows-FailoverClustering/Operational",
    "Microsoft-Windows-DNS-Client/Operational",
]


@mcp.tool
def get_event_summary(
    host: str,
    days: int = 1,
    levels: list[int] = [1, 2, 3],
    include_operational: bool = False,
    extra_logs: list[str] | None = None,
    top: int = 20,
):
    """PONTO DE PARTIDA da RCA: agrupa eventos de problema (Crítico/Erro/Aviso) por log + nível + provedor + ID,
    com contagem, primeira/última ocorrência e uma mensagem de exemplo. Padrão: último dia, logs System,
    Application e Setup. include_operational=True adiciona logs operacionais úteis (GroupPolicy, WindowsUpdate,
    TaskScheduler, RDS, SMB, Time, FailoverClustering, DNS-Client). days: aumente só se pedido (máx. 90)."""
    logs = list(EVENT_LOGS_DEFAULT) + (EVENT_LOGS_OPERATIONAL if include_operational else []) + list(extra_logs or [])
    for lg in logs:
        if not NAME_RE.match(lg):
            raise ValueError(f"log inválido: {lg}")
    if not levels or any(int(lv) not in (1, 2, 3, 4, 5) for lv in levels):
        raise ValueError("levels deve conter valores entre 1 e 5")
    res = _ps(host, PS_EV + r"""
$logs = @(__LOGS__); $xp = "__XP__"
$lvName = @{0='Information';1='Critical';2='Error';3='Warning';4='Information';5='Verbose'}
$totals = @(); $groups = @(); $capped = @(); $skipped = @()
# Rápido: filtro XPath avaliado no serviço de log + EventLogReader em streaming (sem renderizar mensagens);
# agregação em hashtable só com propriedades baratas (Level numérico, Id, ProviderName, TimeCreated).
# A mensagem é montada (Desc) só para a amostra (evento mais recente) de cada grupo devolvido.
foreach ($l in $logs) {
  try { $q = New-Object Diagnostics.Eventing.Reader.EventLogQuery($l, 'LogName', $xp); $q.ReverseDirection = $true
        $rd = New-Object Diagnostics.Eventing.Reader.EventLogReader($q) }
  catch { $skipped += $l; continue }   # log inexistente/desabilitado neste servidor
  $h = @{}; $byLv = @{}; $n = 0; $oldest = $null
  while ($n -lt __CAP__ -and ($e = $rd.ReadEvent())) {
    $n++; $lv = [int]$e.Level; $byLv[$lv] = 1 + [int]$byLv[$lv]; $t = $e.TimeCreated; $oldest = $t
    $k = "$($e.ProviderName)|$($e.Id)|$lv"; $g = $h[$k]
    # Leitura em ordem reversa: o 1o evento de cada grupo é o mais recente (amostra); os demais são liberados.
    if (-not $g) { $h[$k] = @{ C=1; F=$t; L=$t; R=$e; P=$e.ProviderName; I=$e.Id; V=$lv } }
    else { $g.C++; $g.F = $t; $e.Dispose() }
  }
  $rd.Dispose()
  if (-not $n) { continue }
  if ($n -ge __CAP__) { $capped += [pscustomobject]@{ Log=$l; CappedAt=__CAP__; OldestRead=$oldest } }
  $totals += @($byLv.GetEnumerator() | % { [pscustomobject]@{ Log=$l; Level=$lvName[[int]$_.Key]; Count=$_.Value } })
  $groups += @($h.Values | sort { $_.C } -desc | select -first __T__ | % {
      [pscustomobject]@{ Log=$l; Level=$lvName[$_.V]; Provider=$_.P; Id=$_.I; Count=$_.C
        First=$_.F; Last=$_.L; Sample=(Desc $_.R 300) } })
}
[pscustomobject]@{ Totals=$totals; Groups=$groups; Capped=$capped; Skipped=$skipped } | ConvertTo-Json -Depth 3 -Compress
""".replace("__XP__", _xpath(levels=levels, days=_days(days)))
       .replace("__T__", str(max(1, min(int(top), 100))))
       .replace("__LOGS__", ",".join(f"'{lg}'" for lg in logs))
       .replace("__CAP__", str(EVENT_CAP)), timeout=180)
    if not isinstance(res, dict) or "error" in res:
        return res
    totals = sorted(_lst(res.get("Totals")), key=lambda t: -t["Count"])
    groups = sorted(_lst(res.get("Groups")), key=lambda g: -g["Count"])
    capped = _lst(res.get("Capped"))
    out = {"period_days": _days(days), "logs": logs, "levels": levels,
           "total_events": sum(t["Count"] for t in totals),
           "truncated": bool(capped),
           "totals_by_log_level": totals,
           "groups": groups or "Nenhum evento de problema no período."}
    if _lst(res.get("Skipped")):
        out["skipped_logs"] = _lst(res.get("Skipped"))  # não existem/estão desabilitados neste servidor
    if capped:
        out["capped_logs"] = capped
        out["note"] = (f"Logs com mais de {EVENT_CAP} eventos no período foram cortados nos mais recentes: os totais "
                       "desses logs são um LIMITE INFERIOR e 'First' pode ser posterior ao início real. "
                       "Reduza 'days' ou filtre com get_events.")
    return out


@mcp.tool
def get_reboot_and_crash_history(host: str, days: int = 1):
    """Reboots, desligamentos inesperados e BSOD (IDs 41, 1001, 1074, 1076, 6005, 6006, 6008).
    days: padrão 1 (aumente se pedido, máx. 90)."""
    return _ps(host, rf"""
Get-WinEvent -FilterHashtable @{{LogName='System';StartTime=(Get-Date).AddDays(-{_days(days)});Id=41,1001,1074,1076,6005,6006,6008}} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,ProviderName,
    @{{n='Message';e={{Msg $_.Message 400}}}} |
  ConvertTo-Json -Compress
""")


# Serviços automáticos parados: só FATOS (estado, código de saída, início atrasado, gatilho). O coletor NÃO diz se o serviço
# "deveria" estar parado ou rodando: o estado esperado de cada serviço é interpretação e fica no RAG (microsoft-docs), com fonte.
PS_STOPPED_AUTO = r"""@(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | % {
  $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)"; $rp = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
  [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; State="$($_.State)"; ExitCode=$_.ExitCode
    SvcExitCode=$_.ServiceSpecificExitCode; StartName=$_.StartName; Delayed=[bool]$rp.DelayedAutostart
    Trigger=(Test-Path -LiteralPath "$k\TriggerInfo") } })"""
SVC_NEVER_STARTED = 1077   # ERROR_SERVICE_NEVER_STARTED: nenhuma tentativa de iniciar desde o boot; não é falha


def _service_facts(svcs: list) -> dict:
    """Função pura: acrescenta a cada serviço parado os sinais objetivos derivados dos fatos. Nada é classificado."""
    out, failed, trans = [], [], []
    for sv in svcs:
        code, state = sv.get("ExitCode"), sv.get("State")
        failed_code = code not in (0, None, SVC_NEVER_STARTED)
        transitional = state not in (None, "Stopped")
        out.append({**sv, "never_started_since_boot": code == SVC_NEVER_STARTED, "failed_exit_code": failed_code,
                    "transitional_state": transitional})
        if failed_code:
            failed.append(sv.get("Name"))
        if transitional:
            trans.append(sv.get("Name"))
    return {"services": out, "signals": {"failedExitCode": failed, "transitionalState": trans}}


@mcp.tool
def get_stopped_auto_services(host: str):
    """Serviços com início AUTOMÁTICO que não estão em execução, só fatos por serviço: estado, código de saída (e o
    específico do serviço), conta, início atrasado (Delayed), início por gatilho (Trigger) e se nunca iniciou desde o boot
    (código 1077, que não é falha). Sinais objetivos: failedExitCode (código diferente de 0 e de 1077) e
    transitionalState (estado diferente de Stopped, ex.: StartPending). NÃO classifica o serviço como esperado ou
    suspeito: qual é o estado esperado de cada serviço é interpretação do RAG (microsoft-docs), com fonte."""
    res = _ps(host, r"""
$up = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours, 1)
[pscustomobject]@{ Host=$env:COMPUTERNAME; UptimeHours=$up; Services=__SVC__ } | ConvertTo-Json -Depth 4 -Compress
""".replace("__SVC__", PS_STOPPED_AUTO))
    if not isinstance(res, dict) or "Services" not in res:
        return res
    f = _service_facts(_lst(res.get("Services")))
    return {"host": res.get("Host") or host, "uptime_hours": res.get("UptimeHours"),
            "total_stopped_auto": len(f["services"]), "services": f["services"], "signals": f["signals"]}


@mcp.tool
def get_disks(host: str):
    """Volumes: tamanho, livre e % livre."""
    return _ps(host, r"""
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
  select DeviceID,VolumeName,
    @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},
    @{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},
    @{n='FreePct';e={[math]::Round(100*$_.FreeSpace/$_.Size,1)}} | ConvertTo-Json -Compress
""")


@mcp.tool
def get_recent_hotfixes(host: str, top: int = 15):
    """Últimos patches instalados (útil para correlacionar com início do problema)."""
    return _ps(host, rf"""
Get-HotFix | sort InstalledOn -desc | select -first {int(top)} HotFixID,Description,InstalledOn,InstalledBy |
  ConvertTo-Json -Compress
""")


# ---------- patches ----------
@mcp.tool
def get_patch_status(host: str):
    """Situação de patches: último hotfix, dias sem patch, última detecção/instalação do WU,
    WSUS configurado, reboot pendente (CBS, WU, file rename) e estado do serviço wuauserv."""
    return _ps(host, r"""
function V($p,$n){ try{ (Get-ItemProperty $p -ErrorAction Stop).$n }catch{ $null } }
$os   = Get-CimInstance Win32_OperatingSystem
$last = Get-HotFix | sort InstalledOn -desc | select -first 1
$days = $null; if($last.InstalledOn){ $days = [int]((Get-Date)-$last.InstalledOn).TotalDays }
$au = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results'
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
[pscustomobject]@{
  OS=$os.Caption; Build=$os.BuildNumber
  UBR=(V 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR')
  LastHotfixId=$last.HotFixID; LastHotfixDate=$last.InstalledOn; DaysSinceLastPatch=$days
  WU_LastDetect=(V "$au\Detect" 'LastSuccessTime')
  WU_LastInstall=(V "$au\Install" 'LastSuccessTime')
  WsusServer=(V $wu 'WUServer'); UseWsus=(V "$wu\AU" 'UseWUServer')
  RebootPending_CBS=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
  RebootPending_WU=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
  RebootPending_FileRename=[bool](V 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')
  WuauservState=(Get-Service wuauserv).Status.ToString()
} | ConvertTo-Json -Compress
""")


@mcp.tool
def get_pending_updates(host: str, max_seconds: int = 300):
    """Updates pendentes (não instalados) segundo o agente do Windows Update / WSUS.
    A busca do WUA pode levar minutos (WSUS, primeira varredura); prazo padrão de 300 s (máx. 900).
    Obs.: a API COM do WUA pode retornar 'Access denied' em sessões remotas WinRM;
    nesse caso use get_patch_status + get_windows_update_history."""
    secs = max(60, min(int(max_seconds), 900))
    return _ps(host, timeout=secs, script=r"""
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
  @($r.Updates | select Title,
    @{n='KB';e={$_.KBArticleIDs -join ','}}, @{n='Severity';e={$_.MsrcSeverity}},
    @{n='RebootRequired';e={$_.RebootRequired}}, @{n='Downloaded';e={$_.IsDownloaded}}) |
    ConvertTo-Json -Compress
} catch { [pscustomobject]@{Error=$_.Exception.Message} | ConvertTo-Json -Compress }
""")


@mcp.tool
def get_windows_update_history(host: str, days: int = 1):
    """Histórico de instalação/falha de updates (WindowsUpdateClient: 19=sucesso, 20=falha, 21=reboot necessário).
    days: padrão 1 (aumente se pedido, máx. 90)."""
    return _ps(host, r"""
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';
  StartTime=(Get-Date).AddDays(-__D__);Id=19,20,21} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,
    @{n='Message';e={Msg $_.Message 400}} |
  ConvertTo-Json -Compress
""".replace("__D__", str(_days(days))))


# ---------- serviços ----------
SVC_RE = re.compile(r"^[A-Za-z0-9*._-]{1,100}$")


SERVICE_DETAIL_MAX = 50
FAILURE_ACTION_TYPES = {0: "None", 1: "Restart", 2: "Reboot", 3: "RunCommand"}   # SC_ACTION_TYPE (winsvc.h)


def _parse_failure_actions(hex_str):
    """Interpreta o valor binário FailureActions do registro do serviço (estrutura SERVICE_FAILURE_ACTIONS: período de
    reset, ponteiros de mensagem e comando, contagem e deslocamento das ações, e pares tipo/atraso em ms). Só fatos;
    binário ausente ou truncado devolve None (o serviço não tem ações de recuperação configuradas)."""
    if not isinstance(hex_str, str) or len(hex_str) < 40 or len(hex_str) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", hex_str):
        return None
    b = bytes.fromhex(hex_str)
    rd = lambda o: int.from_bytes(b[o:o + 4], "little")
    reset, msg, cmd, count, off = rd(0), rd(4), rd(8), rd(12), rd(16)
    if count > 16 or off < 20 or off + count * 8 > len(b):
        return None
    acts = [{"Action": FAILURE_ACTION_TYPES.get(rd(off + i * 8), str(rd(off + i * 8))), "DelaySeconds": rd(off + i * 8 + 4) // 1000}
            for i in range(count)]
    return {"ResetPeriodSeconds": None if reset == 0xFFFFFFFF else reset, "Actions": acts,
            "HasCommand": cmd != 0, "HasRebootMessage": msg != 0}


def _service_detail_shape(res):
    """Normaliza o modo detalhe: listas sempre listas e ações de recuperação interpretadas."""
    if not isinstance(res, dict) or "Services" not in res:
        return res
    svcs = [x for x in _lst(res.get("Services")) if isinstance(x, dict)]
    for s_ in svcs:
        s_["DependsOn"] = [str(x) for x in _lst(s_.get("DependsOn"))]
        s_["DependedBy"] = [str(x) for x in _lst(s_.get("DependedBy"))]
        s_["Recovery"] = _parse_failure_actions(s_.pop("FailureActionsHex", None))
    res["Services"] = svcs
    res["Truncated"] = (res.get("Total") or 0) > len(svcs)
    return res


@mcp.tool
def get_services(
    host: str,
    name_filter: str = "*",
    state: str | None = None,
    start_mode: str | None = None,
    detail: bool = False,
):
    """Lista serviços (wildcard em nome/display name). state: Running|Stopped; start_mode: Auto|Manual|Disabled.
    detail=True (use com name_filter; máximo 50 serviços) acrescenta, por serviço: descrição, início atrasado, memória
    do processo, código de saída específico do serviço, dependências (DependsOn) e dependentes (DependedBy) e as AÇÕES
    DE RECUPERAÇÃO configuradas (Recovery: período de reset e ações Restart/Reboot/RunCommand com atraso). Só fatos."""
    if not SVC_RE.match(name_filter):
        raise ValueError("name_filter inválido")
    if state not in (None, "Running", "Stopped") or start_mode not in (None, "Auto", "Manual", "Disabled"):
        raise ValueError("state/start_mode inválido")
    extra = (f" -and $_.State -eq '{state}'" if state else "") + (
        f" -and $_.StartMode -eq '{start_mode}'" if start_mode else ""
    )
    if detail:
        res = _ps(host, rf"""
$all = @(Get-CimInstance Win32_Service |
  ? {{ ($_.Name -like '{name_filter}' -or $_.DisplayName -like '{name_filter}'){extra} }} | sort Name)
$out = foreach ($w in ($all | select -First {SERVICE_DETAIL_MAX})) {{
  $reg = Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $w.Name) -ErrorAction SilentlyContinue
  $gs = Get-Service -Name $w.Name -ErrorAction SilentlyContinue
  $mem = if ($w.ProcessId) {{ (Get-Process -Id $w.ProcessId -ErrorAction SilentlyContinue).WorkingSet64 }} else {{ $null }}
  $fa = $reg.FailureActions
  [pscustomobject]@{{ Name=$w.Name; DisplayName=$w.DisplayName; State=$w.State; StartMode=$w.StartMode; StartName=$w.StartName
    ProcessId=$w.ProcessId; ExitCode=$w.ExitCode; ServiceSpecificExitCode=$w.ServiceSpecificExitCode; PathName=$w.PathName
    Description=$w.Description; DelayedAutoStart=[bool]($reg.DelayedAutostart -eq 1)
    MemoryMB=$(if ($mem) {{ [math]::Round($mem/1MB,1) }} else {{ $null }})
    DependsOn=@($gs.ServicesDependedOn | % {{ $_.Name }}); DependedBy=@($gs.DependentServices | % {{ $_.Name }})
    FailureActionsHex=$(if ($fa -is [byte[]]) {{ ($fa | % {{ $_.ToString('X2') }}) -join '' }} else {{ $null }}) }}
}}
[pscustomobject]@{{ Total=$all.Count; Services=@($out) }} | ConvertTo-Json -Depth 4 -Compress
""", timeout=120)
        return _service_detail_shape(res)
    return _ps(host, rf"""
Get-CimInstance Win32_Service |
  ? {{ ($_.Name -like '{name_filter}' -or $_.DisplayName -like '{name_filter}'){extra} }} |
  select Name,DisplayName,State,StartMode,StartName,ProcessId,ExitCode,PathName |
  ConvertTo-Json -Compress
""")


@mcp.tool
def get_service_failures(host: str, days: int = 1):
    """Falhas de serviços no SCM (7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7032, 7034).
    days: padrão 1 (aumente se pedido, máx. 90)."""
    return _ps(host, rf"""
Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='Service Control Manager';
  StartTime=(Get-Date).AddDays(-{_days(days)});Id=7000,7001,7009,7011,7022,7023,7024,7026,7031,7032,7034}} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,
    @{{n='Message';e={{Msg $_.Message 400}}}} |
  ConvertTo-Json -Compress
""")


# ---------- roles, features e software ----------
@mcp.tool
def get_roles_and_features(host: str, only_installed: bool = True):
    """Roles, role services e features do Windows Server (Get-WindowsFeature).
    Requer privilégio administrativo local."""
    flt = "| ? Installed" if only_installed else ""
    return _ps(host, rf"""
Get-WindowsFeature {flt} | select Name,DisplayName,FeatureType,InstallState,Installed |
  ConvertTo-Json -Compress
""")


def _more(what: str) -> str:
    """Resposta objetiva: o coletor responde só o perguntado e apenas SUGERE o que mais existe; nada é coletado sem pedido."""
    return f"Há mais dados disponíveis sob pedido ({what}). Nada além do perguntado foi coletado."


def _since_label(n: int) -> str:
    return "hoje" if n == 0 else f"hoje e os {n} dia(s) anteriores (dias de calendário do servidor)"


# Data de instalação = fato LOCAL do host. NUNCA se consulta internet, Microsoft Learn ou documentação para determiná-la.
# Ordem de evidências (regra do projeto): 1) registro Uninstall (InstallDate), 2) instalação por usuário (HKCU e HKEY_USERS
# carregados), 2b) MSI em Installer\UserData (InstallProperties\InstallDate; Win32_Product NUNCA: dispara reparo de MSI), 3) eventos MsiInstaller (1033 com status 0, 11707), 4) Package Management (só se o provedor expuser data),
# 5) sistema de arquivos (CreationTime da pasta do produto, senão do executável). O evento 11724 NÃO é usado: não confirmado
# localmente como instalação (pelo que se sabe, é remoção).
INSTALL_CONFIDENCE = {"Registry": "high", "MsiUserData": "high", "MsiInstaller": "medium", "PackageManagement": "medium", "FileSystem": "low"}


@mcp.tool
def get_installed_software(host: str, name_filter: str = "*", installed_since_days: int | None = None):
    """Software instalado, como o 'Adicionar ou remover programas' (registro de Uninstall 64/32 bits e instalações por
    usuário; sem componentes de sistema, entradas sem nome e atualizações). Cada item: name, version, installDate (data de
    calendário do servidor), confidence (high | medium | low) e source (Registry | MsiUserData | MsiInstaller |
    PackageManagement | FileSystem). A data vem SÓ de evidência local, em ordem: InstallDate do registro (high), InstallDate do
    MSI em Installer/UserData (high), eventos MsiInstaller 1033/11707
    (medium), Package Management (medium), CreationTime da pasta/executável (low). installed_since_days filtra por dias de
    calendário do servidor (0 = hoje, 1 = hoje e ontem...): com ele devolve SÓ os programas do período. Sem ele, o inventário.
    Não traz nada além do perguntado; só sugere o que mais pode ser obtido."""
    if not SVC_RE.match(name_filter):
        raise ValueError("name_filter inválido")
    since = -1 if installed_since_days is None else max(0, min(int(installed_since_days), 3650))
    res = _ps(host, PS_EV + r"""
$today = (Get-Date).Date
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$roots = @(
  @{ P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; S=$null },
  @{ P='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; S=$null },
  @{ P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; S="user:$sid" })
foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ? { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
  $roots += @{ P="Registry::HKEY_USERS\$($h.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"; S="user:$($h.PSChildName)" } }
$seen = @{}; $items = @()
foreach ($r in $roots) { foreach ($sub in @(Get-ChildItem $r.P -ErrorAction SilentlyContinue)) {
  $p = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue
  if (-not $p.DisplayName -or $p.SystemComponent -eq 1 -or $p.ParentKeyName -or $p.DisplayName -notlike '__F__') { continue }
  $k = "$($p.DisplayName)|$($p.DisplayVersion)|$($r.S)"; if ($seen[$k]) { continue }; $seen[$k] = 1
  $items += [pscustomobject]@{ Name=$p.DisplayName; Version=$p.DisplayVersion; ID="$($p.InstallDate)"; Loc=$p.InstallLocation
    Icon=$p.DisplayIcon; Uninst=$p.UninstallString; Scope=$r.S; Date=$null; Source=$null } } }
function D($d) { $d.ToString('yyyy-MM-dd') }
# 1 e 2) InstallDate no registro (HKLM, HKCU e HKEY_USERS carregados)
foreach ($i in $items) { if ($i.ID -match '^\d{8}$') { try { $i.Date = D ([datetime]::ParseExact($i.ID, 'yyyyMMdd', $null)); $i.Source = 'Registry' } catch {} } }
# 2b) MSI: Installer\UserData\<SID>\Products\<guid>\InstallProperties (InstallDate), só para item ainda sem data
$need = @($items | ? { -not $_.Date })
if ($need.Count) {
  $ud = @{}
  try { foreach ($ip in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData' -Recurse -ErrorAction SilentlyContinue | ? { $_.PSChildName -eq 'InstallProperties' })) {
      $q = Get-ItemProperty $ip.PSPath -ErrorAction SilentlyContinue
      if ($q.DisplayName -and "$($q.InstallDate)" -match '^\d{8}$') { try { $ud[$q.DisplayName.ToLower()] = D ([datetime]::ParseExact("$($q.InstallDate)", 'yyyyMMdd', $null)) } catch {} } } } catch {}
  foreach ($i in $need) { $n = $i.Name.ToLower(); $t = $ud[$n]
    # só igualdade, ignorando sufixo de arquitetura e de versão no FIM do nome (mesma regra dos eventos)
    if (-not $t) { $nn = $n -replace '\s*\((x64|x86|64-bit|32-bit)\)\s*$', '' -replace '\s+v?\d+(\.\d+)+\s*$', ''
      $key = $ud.Keys | ? { ($_ -replace '\s*\((x64|x86|64-bit|32-bit)\)\s*$', '' -replace '\s+v?\d+(\.\d+)+\s*$', '') -eq $nn } | select -first 1
      if ($key) { $t = $ud[$key] } }
    if ($t) { $i.Date = $t; $i.Source = 'MsiUserData' } }
  $need = @($items | ? { -not $_.Date })
}
# 3) eventos MsiInstaller (1033 com status 0; 11707): só se ainda houver item sem data
if ($need.Count) {
  $msi = @{}
  try { foreach ($e in @(Ev 'Application' '__XP__' 4000)) { $n = $null
      if ($e.Id -eq 1033 -and "$($e.Properties[3].Value)" -eq '0') { $n = "$($e.Properties[0].Value)" }
      elseif ($e.Id -eq 11707 -and "$($e.Properties[0].Value)" -match '^Product: (.+?) -- Installation completed successfully') { $n = $Matches[1] }
      if ($n) { $k = $n.ToLower(); if (-not $msi.ContainsKey($k)) { $msi[$k] = $e.TimeCreated } } } } catch {}
  foreach ($i in $need) { $n = $i.Name.ToLower(); $t = $msi[$n]
    # só igualdade, ignorando sufixo de arquitetura e de versão no FIM do nome; nada de prefixo (Git não pode herdar a data do GitHub CLI)
    if (-not $t) { $nn = $n -replace '\s*\((x64|x86|64-bit|32-bit)\)\s*$', '' -replace '\s+v?\d+(\.\d+)+\s*$', ''
      $key = $msi.Keys | ? { ($_ -replace '\s*\((x64|x86|64-bit|32-bit)\)\s*$', '' -replace '\s+v?\d+(\.\d+)+\s*$', '') -eq $nn } | select -first 1
      if ($key) { $t = $msi[$key] } }
    if ($t) { $i.Date = D $t; $i.Source = 'MsiInstaller' } }
  $need = @($items | ? { -not $_.Date })
}
# 4) Package Management: só vale se o provedor expuser uma chave de data
if ($need.Count) {
  try { $pk = @(Get-Package -ProviderName Programs -ErrorAction Stop)
    foreach ($i in $need) { $m = $pk | ? { $_.Name -eq $i.Name } | select -first 1
      if ($m) { $dk = @($m.Metadata.Keys | ? { $_ -match '^(InstallDate|InstalledOn|InstallationDate)$' })[0]
        if ($dk -and "$($m.Metadata[$dk])" -match '(\d{4})-?(\d{2})-?(\d{2})') { $i.Date = "$($Matches[1])-$($Matches[2])-$($Matches[3])"; $i.Source = 'PackageManagement' } } } } catch {}
  $need = @($items | ? { -not $_.Date })
}
# 5) sistema de arquivos (baixa confiança): pasta do produto, senão o executável principal
if ($need.Count) {
  $skip = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemRoot\System32") | % { "$_".TrimEnd('\').ToLower() }
  foreach ($i in $need) { $dir = $null; $exe = $null
    $loc = "$($i.Loc)".Trim('"').TrimEnd('\')
    if ($loc -and (Test-Path -LiteralPath $loc -PathType Container)) { $dir = $loc }
    foreach ($s in "$($i.Icon)", "$($i.Uninst)") { if (-not $exe -and $s -match '"?([A-Za-z]:\\[^",]+?\.exe)') { $f = $Matches[1]
        if (Test-Path -LiteralPath $f) { $exe = $f; if (-not $dir) { $dir = Split-Path $f -Parent } } } }
    if ($dir -and (($skip -contains $dir.TrimEnd('\').ToLower()) -or $dir -match '^[A-Za-z]:\\?$')) { $dir = $null }
    if ($dir) { $i.Date = D (Get-Item -LiteralPath $dir).CreationTime; $i.Source = 'FileSystem' }
    elseif ($exe) { $i.Date = D (Get-Item -LiteralPath $exe).CreationTime; $i.Source = 'FileSystem' } } }
[pscustomobject]@{ ServerDate=$today.ToString('yyyy-MM-dd'); UtcOffset=[TimeZoneInfo]::Local.BaseUtcOffset.ToString()
  Items=@($items | sort Name | select Name,Version,Date,Source,Scope) } | ConvertTo-Json -Depth 4 -Compress
""".replace("__F__", name_filter).replace("__XP__", _xpath(ids=[1033, 11707], provider="MsiInstaller").replace("'", "''")),  # aspas do XPath dentro de string '...' do PowerShell
        timeout=120)
    if not isinstance(res, dict) or "Items" not in res:
        return res
    rows = [{"name": x.get("Name"), "version": x.get("Version"), "installDate": x.get("Date"),
             "confidence": INSTALL_CONFIDENCE.get(x.get("Source")), "source": x.get("Source"),
             **({"scope": x["Scope"]} if x.get("Scope") else {})} for x in _lst(res.get("Items"))]
    out = {"host": host, "serverDate": res.get("ServerDate"), "serverUtcOffset": res.get("UtcOffset")}
    if installed_since_days is None:
        out.update({"count": len(rows), "software": rows})
    else:
        cutoff = (datetime.strptime(res["ServerDate"], "%Y-%m-%d") - timedelta(days=since)).strftime("%Y-%m-%d")
        sel = [r for r in rows if r["installDate"] and r["installDate"] >= cutoff]
        out.update({"window": _since_label(since), "count": len(sel), "installed": sel})
        unknown = sum(1 for r in rows if not r["installDate"])
        if unknown:
            out["dateUnknown"] = unknown   # só aparece se houver itens sem data: afeta a confiança da resposta
    out["more_available"] = _more("inventário completo, editora e local de instalação, patches do período, reinicializações, eventos de erro")
    return out


# ---------- licenciamento do Windows (só fatos) ----------
# Fatos do SoftwareLicensingProduct/Service e eventos do Security-SPP e do wlms. O significado do LicenseStatus, dos HRESULTs
# e do período de carência é interpretação: fica no RAG (microsoft-docs), com fonte. Aqui só há números, textos e contagens.
SPP_EVENT_IDS = [1014, 8198, 8200, 16398]


def _real_date(v):
    """Datas sentinela do Windows (ano < 1700, ex.: 1600-12-31) significam 'sem data': viram None."""
    return None if not v or str(v)[:4] < "1700" else v


@mcp.tool
def get_license_status(host: str, days: int = 1):
    """Licenciamento do Windows (ativação), só fatos: produto, canal da chave (ex.: Volume:GVLK, Retail, OEM), LicenseStatus
    (número da enumeração do WMI), HRESULT do motivo, carência restante (minutos), fim de avaliação (null se não há),
    contagens de rearme, servidor KMS configurado e descoberto, e, no período (days, padrão 1), as contagens dos eventos
    Security-SPP 1014/8198/8200/16398 e os desligamentos iniciados pelo wlms.exe (evento 1074). Não interpreta o status,
    não diz se a licença é válida e não recomenda: o significado dos códigos é do RAG (microsoft-docs)."""
    res = _ps(host, PS_EV + r"""
$ErrorActionPreference = 'Continue'
$p = @(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" |
  select Name,Description,LicenseFamily,ProductKeyChannel,LicenseStatus,LicenseStatusReason,GracePeriodRemaining,
    @{n='EvalEnd';e={ if ($_.EvaluationEndDate -and $_.EvaluationEndDate.Year -gt 1700) { $_.EvaluationEndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }},
    RemainingAppReArmCount,RemainingSkuReArmCount,KeyManagementServiceMachine,KeyManagementServicePort,
    DiscoveredKeyManagementServiceMachineName,DiscoveredKeyManagementServiceMachinePort,VLActivationType)
$s = Get-CimInstance SoftwareLicensingService | select Version,RemainingWindowsReArmCount,IsKeyManagementServiceMachine
$os = Get-CimInstance Win32_OperatingSystem
$spp = @(Ev 'Application' '__XS__' 3000)
$w = @(Ev 'System' '__XW__' 500 | ? { "$($_.Properties[0].Value)" -like '*wlms.exe*' })  # 1074: Properties[0] = processo que iniciou o desligamento
$wl = Get-Service wlms -ErrorAction SilentlyContinue
[pscustomobject]@{
  Products=$p; Service=$s
  OsInstall=$os.InstallDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  WlmsService=$(if ($wl) { [pscustomobject]@{ Status="$($wl.Status)"; StartType="$($wl.StartType)" } } else { $null })
  SppEvents=@($spp | group Id | % { [pscustomobject]@{ Id=$_.Name; Count=$_.Count
    Last=($_.Group | sort TimeCreated -desc | select -first 1).TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } })
  WlmsShutdowns=@($w | sort TimeCreated -desc | select -first 10 | % { [pscustomobject]@{
    Time=$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); Message=(Desc $_ 300) } })
  WlmsShutdownCount=$w.Count
} | ConvertTo-Json -Depth 5 -Compress
""".replace("__XS__", _xpath(ids=SPP_EVENT_IDS, provider="Microsoft-Windows-Security-SPP", days=_days(days)).replace("'", "''"))
       .replace("__XW__", _xpath(ids=[1074], days=_days(days)).replace("'", "''")), timeout=120)
    if not isinstance(res, dict) or "Products" not in res:
        return res
    prods = []
    for x in _lst(res.get("Products")):
        reason = x.get("LicenseStatusReason")
        kms_cfg = (x.get("KeyManagementServiceMachine") or "").strip()
        kms_disc = (x.get("DiscoveredKeyManagementServiceMachineName") or "").strip()
        prods.append({
            "name": x.get("Name"), "description": x.get("Description"), "license_family": x.get("LicenseFamily"),
            "product_key_channel": x.get("ProductKeyChannel"),
            "license_status": x.get("LicenseStatus"),
            "license_status_reason": ("0x%08X" % (int(reason) & 0xFFFFFFFF)) if reason is not None else None,
            "grace_period_remaining_min": x.get("GracePeriodRemaining"),
            "evaluation_end": _real_date(x.get("EvalEnd")),
            "rearm_remaining": {"app": x.get("RemainingAppReArmCount"), "sku": x.get("RemainingSkuReArmCount")},
            "kms": {"configured_host": kms_cfg or None, "configured_port": x.get("KeyManagementServicePort"),
                    "discovered_host": kms_disc or None, "discovered_port": x.get("DiscoveredKeyManagementServiceMachinePort") or None},
            "signals": {"gracePeriodRemainingIsZero": x.get("GracePeriodRemaining") == 0,
                        "kmsHostConfigured": bool(kms_cfg), "kmsHostDiscovered": bool(kms_disc),
                        "evaluationEndDatePresent": bool(_real_date(x.get("EvalEnd")))}})
    spp = {str(e.get("Id")): {"count": e.get("Count"), "last": e.get("Last")} for e in _lst(res.get("SppEvents"))}
    wl = _lst(res.get("WlmsShutdowns"))
    return {"host": host, "period_days": _days(days), "products": prods,
            "os_install_date": res.get("OsInstall"),
            "licensing_service": {"version": (res.get("Service") or {}).get("Version"),
                                  "windows_rearm_remaining": (res.get("Service") or {}).get("RemainingWindowsReArmCount"),
                                  "is_kms_host": bool((res.get("Service") or {}).get("IsKeyManagementServiceMachine"))},
            "wlms_service": res.get("WlmsService"),
            "events": {"security_spp": spp,
                       "wlms_shutdowns": {"count": res.get("WlmsShutdownCount") or 0, "recent": wl}},
            "more_available": _more("eventos de licenciamento de mais dias, logs de ativação, estado do serviço de licença")}


# ---------- camada de armazenamento (discos, partições, volumes, BitLocker) ----------
# Regra do projeto: só fatos observáveis e sinais objetivos com o limiar à vista. Sem "melhor prática" nem recomendação:
# isso é do RAG (microsoft-docs). Tipo de mídia (SSD/HDD) e barramento (NVMe/SAS/SATA/...) são campos SEPARADOS: não se
# presume SSD por causa do barramento nem o contrário. BitLocker indisponível é "indeterminado", nunca "desligado".
LDM_GPT = {"5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "LDM Metadata", "af9b60a0-1431-4f62-bc68-3311714a69ad": "LDM Data"}
MBR_LDM = 0x42   # tipo MBR 0x42 = partição LDM (disco dinâmico). GUIDs e 0x42 confirmados em learn.microsoft.com (set id).
MBR_LIMIT_BYTES = 2 * 1024**4   # 2 TiB: limiar do projeto para o sinal mbrDiskAbove2TiB
LOW_FREE_PCT = 15               # baseline do projeto para o sinal freeSpaceBelowBaseline


def _gb(b):
    return round(b / 1024**3, 2) if isinstance(b, (int, float)) else None


def _sector_format(logical, physical):
    if logical == 512 and physical == 512:
        return "512n"
    if logical == 512 and physical == 4096:
        return "512e"
    if logical == 4096 and physical == 4096:
        return "4Kn"
    return None


def _disk_type_text(media, bus):
    m = media if media and media != "Unspecified" else None
    if m and bus:
        return f"{m} via {bus}"
    return f"tipo de mídia não informado pelo sistema (barramento {bus})" if bus else "indeterminado"


def _is_dynamic(disk: dict) -> tuple[bool, list[str]]:
    why = []
    for pt in _lst(disk.get("PartTypes")):
        g = str(pt.get("GptType") or "").strip("{}").lower()
        if g in LDM_GPT:
            why.append(f"partição GPT {LDM_GPT[g]}")
        if pt.get("MbrType") == MBR_LDM:
            why.append("partição MBR tipo 0x42 (LDM)")
    for t in _lst(disk.get("Win32Types")):
        if "logical disk manager" in str(t).lower():
            why.append("Win32_DiskPartition: Logical Disk Manager")
    return bool(why), list(dict.fromkeys(why))


def _normalize_disks(raw: dict) -> dict:
    disks = []
    for d in _lst(raw.get("Disks")):
        dyn, basis = _is_dynamic(d)
        size = d.get("SizeBytes") or 0
        disks.append({
            "number": d.get("Number"), "model": d.get("Model"), "size_bytes": size, "size_gb": _gb(size),
            "allocated_gb": _gb(d.get("AllocatedBytes")), "bus_type": d.get("BusType") or None,
            "media_type": d.get("MediaType") or None, "spindle_speed_rpm": d.get("SpindleSpeed"),
            "type_text": _disk_type_text(d.get("MediaType"), d.get("BusType")),
            "partition_style": d.get("PartitionStyle"), "dynamic": dyn, "dynamic_basis": basis,
            "volume_kind": "Dinâmico" if dyn else "Básico",
            "online": not d.get("IsOffline"), "offline_reason": d.get("OfflineReason") if d.get("IsOffline") else None,
            "read_only": bool(d.get("IsReadOnly")), "is_boot": bool(d.get("IsBoot")), "is_system": bool(d.get("IsSystem")),
            "is_clustered": bool(d.get("IsClustered")), "health_status": d.get("HealthStatus"),
            "operational_status": d.get("OperationalStatus"),
            "logical_sector_bytes": d.get("LogicalSectorSize"), "physical_sector_bytes": d.get("PhysicalSectorSize"),
            "sector_format": _sector_format(d.get("LogicalSectorSize"), d.get("PhysicalSectorSize")),
            "partition_count": d.get("PartitionCount"), "location": d.get("Location"),
            "firmware": d.get("FirmwareVersion") or None,
            "_ids": {"serial": (d.get("SerialNumber") or "").strip() or None, "disk_guid": d.get("DiskGuid") or None}})
    ids = [{"disk": x["number"], **{k: v for k, v in x.pop("_ids").items() if v}} for x in disks]
    mbr_big = [x["number"] for x in disks if x["partition_style"] == "MBR" and x["size_bytes"] > MBR_LIMIT_BYTES]
    sig = {"diskOffline": any(not x["online"] for x in disks), "diskReadOnly": any(x["read_only"] for x in disks),
           "diskNotHealthy": any((x["health_status"] or "Healthy") != "Healthy" for x in disks),
           "dynamicDiskPresent": any(x["dynamic"] for x in disks), "mbrDiskAbove2TiB": bool(mbr_big)}
    by = lambda k: {v: sum(1 for x in disks if x[k] == v) for v in sorted({str(x[k]) for x in disks})}
    return {"disk_count": len(disks), "total_gb": _gb(sum(x["size_bytes"] for x in disks)),
            "by_bus_type": by("bus_type"), "by_media_type": by("media_type"), "by_partition_style": by("partition_style"),
            "disks": disks, "signals": sig,
            "signal_details": {"mbrDiskAbove2TiB": {"threshold_tib": 2, "disks": mbr_big, "source": "limiar do projeto"}},
            "identifiers": ids}


@mcp.tool
def get_storage_overview(host: str):
    """Discos do servidor, só fatos: quantidade, modelo, tamanho, barramento (NVMe/SAS/SATA/SCSI/iSCSI/Virtual...) e tipo de
    mídia (SSD/HDD/SCM; 'Unspecified' quando o sistema não informa, ex.: discos virtuais) em campos SEPARADOS, estilo de
    partição (GPT/MBR), básico ou dinâmico (com a base da detecção), online/offline (+ motivo), somente leitura, saúde,
    bytes por setor lógico e físico (512n/512e/4Kn), partições, boot/sistema. Sinais objetivos: diskOffline,
    diskReadOnly, diskNotHealthy, dynamicDiskPresent, mbrDiskAbove2TiB (limiar do projeto). Serial e GUID do disco ficam
    em 'identifiers' (sensíveis: não vão ao RAG). Sem recomendação: interpretação é do RAG (microsoft-docs)."""
    raw = _ps(host, r"""
$wdp = @(Get-CimInstance Win32_DiskPartition | select DiskIndex,Type)
$rows = foreach ($d in @(Get-Disk | sort Number)) {
  $pd = $d | Get-PhysicalDisk -ErrorAction SilentlyContinue | select -first 1
  $parts = @(try { Get-Partition -DiskNumber $d.Number -ErrorAction Stop } catch { })
  [pscustomobject]@{ Number=$d.Number; Model=$d.FriendlyName; SizeBytes=[int64]$d.Size; AllocatedBytes=[int64]$d.AllocatedSize
    BusType="$($d.BusType)"; MediaType="$($pd.MediaType)"; SpindleSpeed=$pd.SpindleSpeed; PartitionStyle="$($d.PartitionStyle)"
    IsOffline=[bool]$d.IsOffline; OfflineReason="$($d.OfflineReason)"; IsReadOnly=[bool]$d.IsReadOnly
    IsBoot=[bool]$d.IsBoot; IsSystem=[bool]$d.IsSystem; IsClustered=[bool]$d.IsClustered
    HealthStatus="$($d.HealthStatus)"; OperationalStatus=(@($d.OperationalStatus) -join ',')
    LogicalSectorSize=$d.LogicalSectorSize; PhysicalSectorSize=$d.PhysicalSectorSize; PartitionCount=$d.NumberOfPartitions
    Location=$d.Location; FirmwareVersion=$d.FirmwareVersion; SerialNumber=$d.SerialNumber; DiskGuid="$($d.Guid)"
    PartTypes=@($parts | % { [pscustomobject]@{ GptType="$($_.GptType)"; MbrType=$(if ($null -ne $_.MbrType) { [int]$_.MbrType } else { $null }) } })
    Win32Types=@($wdp | ? { $_.DiskIndex -eq $d.Number } | % { "$($_.Type)" }) }
}
[pscustomobject]@{ Disks=@($rows) } | ConvertTo-Json -Depth 5 -Compress
""", timeout=90)
    if not isinstance(raw, dict) or "Disks" not in raw:
        return raw
    out = _normalize_disks(raw)
    out["host"] = host
    return out


def _bitlocker_for(vol: dict, bl: dict) -> dict:
    """BitLocker de um volume. Sem o recurso: 'indeterminado' (nunca 'desligado')."""
    if not bl.get("Available"):
        return {"status": "indeterminate", "reason": bl.get("Reason") or "BitLocker indisponível neste servidor"}
    letter = (vol.get("DriveLetter") or "")
    if not letter:
        return {"status": "indeterminate", "reason": "volume sem letra: não mapeado ao BitLocker"}
    m = next((x for x in _lst(bl.get("Volumes")) if str(x.get("MountPoint", "")).upper().rstrip("\\") == f"{letter.upper()}:"), None)
    if not m:
        return {"status": "indeterminate", "reason": "volume não listado pelo BitLocker"}
    return {"status": "reported", "protection": m.get("ProtectionStatus"), "volume_status": m.get("VolumeStatus"),
            "lock_status": m.get("LockStatus"), "encryption_percent": m.get("EncryptionPercentage"),
            "encryption_method": m.get("EncryptionMethod"), "volume_type": m.get("VolumeType"),
            "key_protector_types": _lst(m.get("KeyProtectorTypes"))}   # só os TIPOS: nunca senha/chave de recuperação


def _normalize_volumes(raw: dict, low_free_pct: int) -> dict:
    parts = {}
    for pt in _lst(raw.get("Partitions")):
        for path in _lst(pt.get("AccessPaths")):
            parts[str(path).lower()] = pt
    w32 = {str(x.get("DeviceID", "")).lower(): x for x in _lst(raw.get("Win32Volumes"))}
    bl = raw.get("BitLocker") or {}
    vols, low = [], []
    for v in _lst(raw.get("Volumes")):
        path = v.get("Path") or ""
        pt = parts.get(path.lower()) or {}
        w = w32.get(path.lower()) or {}
        size, free = v.get("Size"), v.get("SizeRemaining")
        pct = round(100 * free / size, 1) if size and free is not None else None
        guid = re.search(r"Volume\{([0-9a-fA-F-]{36})\}", path)
        cluster = v.get("AllocationUnitSize") or w.get("BlockSize") or None
        letter = v.get("DriveLetter") or None
        folders = [a for a in _lst(pt.get("AccessPaths")) if a and not str(a).lower().startswith("\\\\?\\volume") and len(str(a)) > 3]
        row = {"drive_letter": f"{letter}:" if letter else None, "mount_folders": folders,
               "volume_guid": guid.group(1) if guid else None, "volume_path": path or None, "label": v.get("FileSystemLabel") or None,
               "filesystem": v.get("FileSystem") or None, "drive_type": v.get("DriveType"),
               "cluster_size_bytes": cluster, "size_bytes": size, "size_gb": _gb(size), "free_bytes": free, "free_gb": _gb(free),
               "free_percent": pct, "health_status": v.get("HealthStatus"), "operational_status": v.get("OperationalStatus"),
               "disk_number": pt.get("DiskNumber"), "partition_number": pt.get("PartitionNumber"),
               "partition_offset_bytes": pt.get("Offset"), "partition_size_bytes": pt.get("Size"), "partition_size_gb": _gb(pt.get("Size")),
               "partition_type": pt.get("Type"), "partition_read_only": bool(pt.get("IsReadOnly")) if pt else None,
               "partition_hidden": bool(pt.get("IsHidden")) if pt else None, "partition_active": bool(pt.get("IsActive")) if pt else None,
               "bitlocker": _bitlocker_for(v, bl)}
        row["signals"] = {"freeSpaceBelowBaseline": pct is not None and pct < low_free_pct,
                          "notHealthy": (v.get("HealthStatus") or "Healthy") != "Healthy",
                          "readOnly": bool(pt.get("IsReadOnly"))}
        if row["signals"]["freeSpaceBelowBaseline"]:
            low.append(row["drive_letter"] or row["volume_guid"])
        vols.append(row)
    return {"volume_count": len(vols), "volumes": vols,
            "bitlocker": {"available": bool(bl.get("Available")), "source": bl.get("Source"), "reason": bl.get("Reason")},
            "signals": {"freeSpaceBelowBaseline": low, "volumeNotHealthy": [x["drive_letter"] or x["volume_guid"] for x in vols if x["signals"]["notHealthy"]],
                        "bitLockerIndeterminate": not bl.get("Available")},
            "baseline": {"low_free_pct": low_free_pct, "source": "limiar do projeto"}}


@mcp.tool
def get_volumes(host: str, low_free_pct: int = LOW_FREE_PCT):
    """Partições e volumes, só fatos, ligados ao disco: letra e pontos de montagem (pastas), GUID do volume, rótulo, sistema
    de arquivos, tamanho do cluster (unidade de alocação) em bytes, tamanho do volume e da partição, espaço livre
    (bytes e %), saúde, disco/partição/offset, tipo de partição, somente leitura/oculta/ativa e BitLocker (proteção,
    estado, bloqueio, % criptografado, método, TIPOS de protetor; nunca senha nem chave de recuperação).
    BitLocker indisponível => 'indeterminate' (nunca 'desligado'). Sinais: freeSpaceBelowBaseline (limiar do projeto
    low_free_pct, padrão 15), notHealthy, readOnly, bitLockerIndeterminate. Sem recomendação (isso é do RAG)."""
    low_free_pct = max(1, min(int(low_free_pct), 99))
    raw = _ps(host, r"""
$parts = @(Get-Partition -ErrorAction SilentlyContinue | % {
  [pscustomobject]@{ DiskNumber=$_.DiskNumber; PartitionNumber=$_.PartitionNumber; Offset=[int64]$_.Offset; Size=[int64]$_.Size
    Type="$($_.Type)"; IsReadOnly=[bool]$_.IsReadOnly; IsHidden=[bool]$_.IsHidden; IsActive=[bool]$_.IsActive; AccessPaths=@($_.AccessPaths) } })
$vols = @(Get-Volume | % {
  [pscustomobject]@{ DriveLetter="$($_.DriveLetter)"; Path=$_.Path; FileSystemLabel=$_.FileSystemLabel; FileSystem="$($_.FileSystem)"
    DriveType="$($_.DriveType)"; AllocationUnitSize=$_.AllocationUnitSize; Size=[int64]$_.Size; SizeRemaining=[int64]$_.SizeRemaining
    HealthStatus="$($_.HealthStatus)"; OperationalStatus=(@($_.OperationalStatus) -join ',') } })
$w32 = @(Get-CimInstance Win32_Volume | select DeviceID,BlockSize)
$bl = [pscustomobject]@{ Available=$false; Source=$null; Reason=$null; Volumes=@() }
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
  try {
    $bl.Volumes = @(Get-BitLockerVolume -ErrorAction Stop | % {
      [pscustomobject]@{ MountPoint=$_.MountPoint; VolumeType="$($_.VolumeType)"; VolumeStatus="$($_.VolumeStatus)"
        ProtectionStatus="$($_.ProtectionStatus)"; LockStatus="$($_.LockStatus)"; EncryptionPercentage=$_.EncryptionPercentage
        EncryptionMethod="$($_.EncryptionMethod)"; KeyProtectorTypes=@($_.KeyProtector | % { "$($_.KeyProtectorType)" }) } })
    $bl.Available = $true; $bl.Source = 'Get-BitLockerVolume'
  } catch { $bl.Reason = "Get-BitLockerVolume falhou: " + (("$($_.Exception.Message)" -split "`n")[0]) }
} else {
  $f = try { (Get-WindowsFeature -Name BitLocker -ErrorAction Stop).InstallState } catch { $null }
  $bl.Reason = "cmdlet Get-BitLockerVolume ausente" + $(if ($f) { " (recurso BitLocker: $f)" } else { "" })
}
[pscustomobject]@{ Partitions=$parts; Volumes=$vols; Win32Volumes=$w32; BitLocker=$bl } | ConvertTo-Json -Depth 5 -Compress
""", timeout=120)
    if not isinstance(raw, dict) or "Volumes" not in raw:
        return raw
    out = _normalize_volumes(raw, low_free_pct)
    out["host"] = host
    return out


# ---------- plataforma: físico, virtual ou nuvem ----------
# Regra do projeto: só fatos e evidência. A plataforma é deduzida por ASSINATURAS do catálogo do projeto (cadeias SMBIOS
# e agentes de guest); strings SMBIOS podem ser alteradas na configuração da VM, então o resultado traz a evidência
# usada e 'indeterminado' quando nada casa. Serviço de metadados da nuvem (IMDS) só é consultado quando o SMBIOS
# indica uma nuvem possível, só em campos de uma lista fixa, NUNCA credenciais, user-data ou custom-data.
CHASSIS = {1: "Other", 2: "Unknown", 3: "Desktop", 4: "Low Profile Desktop", 5: "Pizza Box", 6: "Mini Tower", 7: "Tower",
           8: "Portable", 9: "Laptop", 10: "Notebook", 13: "All in One", 17: "Main System Chassis", 23: "Rack Mount Chassis",
           28: "Blade", 29: "Blade Enclosure", 30: "Tablet", 31: "Convertible", 35: "Mini PC", 36: "Stick PC"}
GUEST_SERVICES = ["VMTools", "VGAuthService", "QEMU-GA", "qemu-ga", "AmazonSSMAgent", "AWSLiteAgent", "EC2Launch",
                  "WindowsAzureGuestAgent", "RdAgent", "GCEAgent", "vmicheartbeat", "vmicshutdown", "vmictimesync", "vmms"]


def _s(x) -> str:
    return str(x or "").strip()


def _classify_platform(raw: dict, probes: dict | None = None) -> dict:
    """Função pura: SMBIOS + serviços (+ metadados da nuvem, se houver) -> plataforma com a evidência usada."""
    cs, bios, csp = raw.get("ComputerSystem") or {}, raw.get("Bios") or {}, raw.get("Product") or {}
    man, model = _s(cs.get("Manufacturer")), _s(cs.get("Model"))
    bver, bman = _s(bios.get("Version")) + " " + _s(bios.get("SMBIOSBIOSVersion")), _s(bios.get("Manufacturer"))
    running = {_s(x.get("Name")).lower() for x in _lst(raw.get("Services")) if _s(x.get("Status")) == "Running"}
    probes = probes or {}
    hits: list[dict] = []

    def hit(key, label, kind, why):
        hits.append({"key": key, "label": label, "kind": kind, "evidence": why})

    if re.match(r"VMware", man, re.I) or re.match(r"VMware", model, re.I) or re.search(r"VMW|VMware", bver):
        hit("vmware", "VMware", "hypervisor", f"SMBIOS: fabricante '{man}', modelo '{model}', BIOS '{bver.strip()}'")
    if man == "Microsoft Corporation" and model == "Virtual Machine":
        hit("hyperv", "Microsoft Hyper-V", "hypervisor", "SMBIOS: fabricante 'Microsoft Corporation', modelo 'Virtual Machine'")
    if re.match(r"Amazon EC2", man, re.I) or re.match(r"Amazon EC2", bman, re.I) or re.search(r"amazon", bver, re.I):
        hit("aws", "Amazon Web Services (EC2)", "cloud", f"SMBIOS: fabricante '{man}', modelo '{model}', BIOS '{bver.strip()}'")
    if re.match(r"Google", man, re.I) and re.search(r"Google Compute Engine", model, re.I):
        hit("gcp", "Google Cloud (Compute Engine)", "cloud", f"SMBIOS: fabricante '{man}', modelo '{model}'")
    if re.match(r"Xen", man, re.I) or model == "HVM domU":
        hit("xen", "Xen", "hypervisor", f"SMBIOS: fabricante '{man}', modelo '{model}'")
    if re.match(r"(QEMU|Red Hat)", man, re.I) or re.search(r"\b(KVM|QEMU)\b|Standard PC", model):
        hit("kvm_qemu", "KVM/QEMU", "hypervisor", f"SMBIOS: fabricante '{man}', modelo '{model}', BIOS '{bman}'")
    if re.search(r"innotek|VirtualBox", man + " " + model, re.I):
        hit("virtualbox", "Oracle VirtualBox", "hypervisor", f"SMBIOS: fabricante '{man}', modelo '{model}'")
    # Azure: só com evidência além do Hyper-V genérico (agente de guest em execução ou metadados da própria Azure).
    az = probes.get("azure") or {}
    if az.get("Reachable") or ({"windowsazureguestagent", "rdagent"} & running):
        if any(h["key"] == "hyperv" for h in hits) or az.get("Reachable"):
            why = "serviço de metadados da Azure respondeu" if az.get("Reachable") else "agente de guest da Azure em execução (WindowsAzureGuestAgent/RdAgent)"
            hit("azure", "Microsoft Azure", "cloud", why)
    for key, label, svcs in (("aws", "Amazon Web Services (EC2)", {"amazonssmagent", "awslitagent", "ec2launch"}),
                             ("gcp", "Google Cloud (Compute Engine)", {"gceagent"})):
        if (probes.get(key) or {}).get("Reachable") and not any(h["key"] == key for h in hits):
            hit(key, label, "cloud", "serviço de metadados respondeu")
    guest = [n for n in ("vmtools", "vgauthservice", "qemu-ga", "amazonssmagent", "awslitagent", "windowsazureguestagent",
                         "rdagent", "gceagent") if n in running]
    hyperv_host = "vmms" in running and not any(h["key"] == "hyperv" for h in hits)

    hv = [h for h in hits if h["kind"] == "hypervisor"]
    cloud = [h for h in hits if h["kind"] == "cloud"]
    if hits:
        ptype = "virtual"
    elif not cs:
        ptype = "indeterminate"   # sem dados do ComputerSystem não há evidência: nunca afirmar "físico"
    elif not cs.get("HypervisorPresent"):
        ptype = "physical"
    elif hyperv_host:
        ptype = "physical"   # tem hypervisor porque ele É o host Hyper-V (serviço vmms em execução)
    else:
        ptype = "indeterminate"
    chassis = [CHASSIS.get(int(c), f"código {c}") for c in _lst((raw.get("Enclosure") or {}).get("ChassisTypes")) if str(c).isdigit()]
    cpus = _lst(raw.get("Processors"))
    mem_gb = round((cs.get("TotalPhysicalMemory") or 0) / 1024**3, 1)
    hardware = {"manufacturer": man or None, "model": model or None, "system_type": cs.get("SystemType"),
                "bios": {"vendor": bman or None, "version": _s(bios.get("SMBIOSBIOSVersion")) or None, "date": bios.get("ReleaseDate")},
                "board": {"manufacturer": _s((raw.get("BaseBoard") or {}).get("Manufacturer")) or None,
                          "product": _s((raw.get("BaseBoard") or {}).get("Product")) or None},
                "chassis": chassis, "sockets": cs.get("NumberOfProcessors"), "logical_processors": cs.get("NumberOfLogicalProcessors"),
                "cpu_model": _s(cpus[0].get("Name")) if cpus else None, "cores": sum(int(c.get("NumberOfCores") or 0) for c in cpus),
                "memory_gb": mem_gb}
    out = {"platform": ptype, "hypervisor_present": bool(cs.get("HypervisorPresent")),
           "virtualization": [h["label"] for h in hv], "cloud_provider": [h["label"] for h in cloud],
           "detected_by": hits, "guest_agents_running": guest, "hyper_v_host_role": hyperv_host,
           "hardware": hardware, "signature_source": "catálogo do projeto (cadeias SMBIOS e agentes de guest)"}
    if ptype == "indeterminate":
        out["note"] = ("Hypervisor presente, mas nenhuma assinatura do catálogo casou: pode ser servidor físico com VBS/Hyper-V "
                       "ou VM de plataforma fora do catálogo. Os fatos de hardware estão em 'hardware'.")
    # Identificadores: servem a suporte/inventário, NÃO a consulta externa (nunca envie ao RAG).
    out["identifiers"] = {k: v for k, v in {
        "bios_serial": _s(bios.get("SerialNumber")) or None, "system_uuid": _s(csp.get("UUID")) or None,
        "identifying_number": _s(csp.get("IdentifyingNumber")) or None,
        "asset_tag": _s((raw.get("Enclosure") or {}).get("SMBIOSAssetTag")) or None,
        "note": "sensíveis: não incluir em consultas externas"}.items() if v}
    # Metadados da nuvem (campos de uma lista fixa)
    meta = {}
    for key in ("aws", "azure", "gcp"):
        pr = probes.get(key)
        if pr and pr.get("Reachable"):
            meta[key] = {k: v for k, v in pr.items() if k not in ("Reachable", "InstanceId", "VmId")}
            ids = out["identifiers"]
            if pr.get("InstanceId") or pr.get("VmId"):
                ids["cloud_instance_id"] = pr.get("InstanceId") or pr.get("VmId")
        elif pr:
            meta[key] = {"Reachable": False, "Error": pr.get("Error")}
    if meta:
        out["cloud_metadata"] = meta
    # Contexto genérico para o RAG: sem serial, UUID, asset tag, id de instância, host, IP ou assinatura/conta.
    ctx: list[str] = []
    if ptype == "physical":
        ctx += ["physical server"] + ([f"{man} {model}"] if man and model else [])
    elif ptype == "virtual":
        ctx += [f"virtual machine on {h['label']}" for h in hv] or [f"virtual machine on {cloud[0]['label']}"]
        for h in cloud:
            ctx.append(h["label"])
        m = meta.get("aws") or {}
        if m.get("InstanceType"):
            ctx.append(f"EC2 instance type {m['InstanceType']}")
        elif any(h["key"] == "aws" for h in hits) and re.fullmatch(r"[a-z0-9]+\.[a-z0-9]+", model or ""):
            ctx.append(f"EC2 instance type {model}")
        m = meta.get("azure") or {}
        if m.get("VmSize"):
            ctx.append(f"Azure VM size {m['VmSize']}")
        m = meta.get("gcp") or {}
        if m.get("MachineType"):
            ctx.append(f"Compute Engine machine type {m['MachineType']}")
    out["docs_context"] = list(dict.fromkeys(ctx))
    return out


PS_PROBES = {
    "aws": r"""
try { $t = Invoke-RestMethod -Method Put -Uri 'http://169.254.169.254/latest/api/token' -Headers @{'X-aws-ec2-metadata-token-ttl-seconds'='60'} -TimeoutSec 2
  $h = @{'X-aws-ec2-metadata-token'=$t}
  function G($p) { try { Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/$p" -Headers $h -TimeoutSec 2 } catch { $null } }
  $pr['aws'] = [pscustomobject]@{ Reachable=$true; InstanceType=(G 'instance-type'); AvailabilityZone=(G 'placement/availability-zone')
    Region=(G 'placement/region'); LifeCycle=(G 'instance-life-cycle'); InstanceId=(G 'instance-id') }
} catch { $pr['aws'] = [pscustomobject]@{ Reachable=$false; Error=("$($_.Exception.Message)" -split "`n")[0] } }
""",
    "azure": r"""
try { $m = Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -Headers @{Metadata='true'} -TimeoutSec 2
  $pr['azure'] = [pscustomobject]@{ Reachable=$true; VmSize=$m.vmSize; Location=$m.location; Zone=$m.zone; OsType=$m.osType
    Offer=$m.offer; Sku=$m.sku; Priority=$m.priority; AzEnvironment=$m.azEnvironment; VmId=$m.vmId
    OsDiskGB=$m.storageProfile.osDisk.diskSizeGB; OsDiskType=$m.storageProfile.osDisk.managedDisk.storageAccountType
    DataDisks=@($m.storageProfile.dataDisks | % { [pscustomobject]@{ Lun=$_.lun; SizeGB=$_.diskSizeGB; Type=$_.managedDisk.storageAccountType; Caching=$_.caching } }) }
} catch { $pr['azure'] = [pscustomobject]@{ Reachable=$false; Error=("$($_.Exception.Message)" -split "`n")[0] } }
""",
    "gcp": r"""
try { $h = @{'Metadata-Flavor'='Google'}
  $mt = Invoke-RestMethod -Uri 'http://169.254.169.254/computeMetadata/v1/instance/machine-type' -Headers $h -TimeoutSec 2
  $zn = Invoke-RestMethod -Uri 'http://169.254.169.254/computeMetadata/v1/instance/zone' -Headers $h -TimeoutSec 2
  $pr['gcp'] = [pscustomobject]@{ Reachable=$true; MachineType=(("$mt") -split '/')[-1]; Zone=(("$zn") -split '/')[-1] }
} catch { $pr['gcp'] = [pscustomobject]@{ Reachable=$false; Error=("$($_.Exception.Message)" -split "`n")[0] } }
""",
}


@mcp.tool
def get_platform_info(host: str, probe_cloud: str = "auto"):
    """Plataforma do servidor: FÍSICO, VIRTUAL (VMware, Hyper-V, KVM/QEMU, Xen, VirtualBox) ou NUVEM (AWS, Azure, GCP),
    com a evidência usada (cadeias SMBIOS, agentes de guest, metadados). Servidor físico: fabricante, modelo, BIOS,
    placa, chassi, CPU, sockets, núcleos e memória. 'indeterminate' quando nenhuma assinatura casa (nunca chuta).
    probe_cloud: 'auto' (padrão) consulta o serviço de metadados da instância só se o SMBIOS indicar nuvem possível
    (AWS/GCP, ou Hyper-V para Azure); 'no' nunca consulta; 'aws', 'azure', 'gcp' ou 'all' força. Só campos de lista
    fixa (tipo/tamanho da instância, região, zona, discos): nunca credenciais nem user-data. 'docs_context' traz rótulos
    genéricos para consultar o RAG (microsoft-docs); 'identifiers' (serial, UUID, asset tag, id da instância) são
    sensíveis e NÃO devem ir ao RAG."""
    if probe_cloud not in ("auto", "no", "aws", "azure", "gcp", "all"):
        raise ValueError("probe_cloud deve ser auto, no, aws, azure, gcp ou all")
    raw = _ps(host, r"""
$cs = Get-CimInstance Win32_ComputerSystem | select Manufacturer,Model,SystemType,HypervisorPresent,TotalPhysicalMemory,NumberOfProcessors,NumberOfLogicalProcessors
$bios = Get-CimInstance Win32_BIOS | select Manufacturer,Version,SMBIOSBIOSVersion,ReleaseDate,SerialNumber
$prod = Get-CimInstance Win32_ComputerSystemProduct | select UUID,IdentifyingNumber
$bb = Get-CimInstance Win32_BaseBoard | select Manufacturer,Product
$enc = Get-CimInstance Win32_SystemEnclosure | select ChassisTypes,SMBIOSAssetTag
$cpu = @(Get-CimInstance Win32_Processor | select Name,NumberOfCores)
$svc = @(Get-Service -Name __SVC__ -ErrorAction SilentlyContinue | select Name,@{n='Status';e={"$($_.Status)"}})
[pscustomobject]@{ ComputerSystem=$cs; Bios=$bios; Product=$prod; BaseBoard=$bb; Enclosure=$enc; Processors=$cpu; Services=$svc } | ConvertTo-Json -Depth 4 -Compress
""".replace("__SVC__", ",".join(GUEST_SERVICES)), timeout=60)
    if not isinstance(raw, dict) or "ComputerSystem" not in raw:
        return raw
    first = _classify_platform(raw)
    keys = {h["key"] for h in first["detected_by"]}
    if probe_cloud == "all":
        want = ["aws", "azure", "gcp"]
    elif probe_cloud in ("aws", "azure", "gcp"):
        want = [probe_cloud]
    elif probe_cloud == "auto":
        want = [k for k in ("aws", "gcp") if k in keys] + (["azure"] if "hyperv" in keys else [])
    else:
        want = []
    probes = {}
    if want:
        pr = _ps(host, "$pr = @{}\n[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy\n"
                 + "\n".join(PS_PROBES[k] for k in want) + "\n$pr | ConvertTo-Json -Depth 4 -Compress", timeout=40)
        if isinstance(pr, dict) and "error" not in pr:
            probes = pr
    out = _classify_platform(raw, probes)
    out["host"] = host
    out["cloud_probed"] = want
    return out


# ---------- evidência de carga (o que o servidor realmente executa) ----------
# Regra do projeto: o coletor NÃO presume a função do servidor. Uma carga só é declarada quando há evidência
# identificadora (serviço, instância no registro, software de servidor, recurso do Windows ou processo).
# Sem evidência, vale só o sistema operacional e a versão. Ferramentas CLIENTES (SSMS, drivers ODBC) não contam.
WORKLOADS = {
    "sql_server_engine": {
        "label": "SQL Server",
        "services": ["MSSQLSERVER", "MSSQL$*", "SQLSERVERAGENT", "SQLAgent$*"],
        "processes": ["sqlservr"],
        "software": [r"^(Microsoft )?SQL Server \d{4}( R2)?( \(\d+-bit\)| Database Engine Services)"],
    },
    "iis": {"label": "IIS", "services": ["W3SVC"], "processes": ["w3wp"], "features": ["Web-Server"]},
    "hyper_v": {"label": "Hyper-V", "services": ["vmms"], "features": ["Hyper-V"]},
    "active_directory_domain_services": {"label": "Active Directory Domain Services", "services": ["NTDS"],
                                         "features": ["AD-Domain-Services"]},
    "dns_server": {"label": "DNS Server", "services": ["DNS"], "features": ["DNS"]},
    "dhcp_server": {"label": "DHCP Server", "services": ["DHCPServer"], "features": ["DHCP"]},
    "failover_cluster": {"label": "Failover Cluster", "services": ["ClusSvc"], "features": ["Failover-Clustering"]},
}
# Ferramentas de cliente do SQL Server: informativas, NUNCA identificam um servidor SQL.
SQL_CLIENT_TOOLS = [r"SQL Server Management Studio", r"^Microsoft ODBC Driver .* for SQL Server",
                    r"^Microsoft OLE DB Driver .* for SQL Server", r"SQL Server Native Client",
                    r"Microsoft .* Command Line Utilities .* for SQL Server", r"SQL Server Data Tools"]


def _classify_workloads(raw: dict) -> dict:
    """Função pura: transforma a coleta bruta em evidências por carga. Nada é inferido além do catálogo."""
    svc = {x["Name"].lower(): x for x in _lst(raw.get("Services")) if x.get("Name")}
    procs = {str(x).lower() for x in _lst(raw.get("Processes"))}
    feats = {x["Name"]: x for x in _lst(raw.get("Features")) if isinstance(x, dict) and x.get("Name")}
    sw = [x for x in _lst(raw.get("Software")) if x.get("DisplayName")]
    found, absent = {}, []
    for key, w in WORKLOADS.items():
        ev = []
        for pat in w.get("services", []):
            for name, x in svc.items():
                if fnmatch.fnmatchcase(name, pat.lower()):
                    ev.append({"type": "service", "name": x["Name"], "state": x.get("State"), "start_mode": x.get("StartMode")})
        for name in w.get("processes", []):
            if name.lower() in procs:
                ev.append({"type": "process", "name": name, "state": "Running"})
        for name in w.get("features", []):
            f = feats.get(name)
            if f and str(f.get("InstallState")) in ("Installed", "1"):
                ev.append({"type": "windows_feature", "name": name, "state": "Installed"})
        for rx in w.get("software", []):
            for x in sw:
                if re.search(rx, x["DisplayName"]) and not any(re.search(c, x["DisplayName"]) for c in SQL_CLIENT_TOOLS):
                    ev.append({"type": "software", "name": x["DisplayName"], "version": x.get("DisplayVersion")})
        if key == "sql_server_engine":
            for inst in _lst(raw.get("SqlInstances")):
                ev.append({"type": "registry_instance", "name": inst.get("Instance"), "instance_id": inst.get("InstanceId"),
                           "edition": inst.get("Edition"), "version": inst.get("Version"), "patch_level": inst.get("PatchLevel")})
        if key == "active_directory_domain_services" and (raw.get("DomainRole") or 0) >= 4:
            ev.append({"type": "domain_role", "name": "controlador de domínio (DomainRole >= 4)", "state": "Active"})
        if ev:
            running = any(e.get("state") in ("Running", "Active") for e in ev)
            found[key] = {"label": w["label"], "present": True, "running": running, "evidence": ev}
        else:
            absent.append(key)
    clients = [{"name": x["DisplayName"], "version": x.get("DisplayVersion")} for x in sw
               if any(re.search(c, x["DisplayName"]) for c in SQL_CLIENT_TOOLS)]
    return {"workloads": found, "not_identified": absent, "sql_client_tools_only": bool(clients) and "sql_server_engine" not in found,
            "client_tools": clients}


@mcp.tool
def get_workload_evidence(host: str, include_all_software: bool = False):
    """EVIDÊNCIA do que o servidor executa, sem presumir função. Devolve sistema operacional e versão, e para cada
    carga do catálogo (SQL Server, IIS, Hyper-V, AD DS, DNS, DHCP, Failover Cluster) a evidência que a identifica:
    serviço, processo, recurso do Windows, instância do SQL Server no registro (edição, versão, patch) ou software
    de servidor. Ferramentas CLIENTES (SSMS, drivers ODBC/OLE DB) NÃO identificam um servidor SQL (vão em
    client_tools). 'docs_context' lista só rótulos com evidência e é o único valor aceitável como 'context' ao
    consultar o RAG (microsoft-docs). Sem evidência, 'docs_context' fica vazio: considere apenas SO e versão.
    include_all_software=True devolve também todo o software instalado (até 400 itens)."""
    raw = _ps(host, r"""
$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$sw = @(Get-ItemProperty $reg -ErrorAction SilentlyContinue | ? DisplayName | sort DisplayName | select DisplayName,DisplayVersion,Publisher)
$svc = @(Get-CimInstance Win32_Service | select Name,DisplayName,State,StartMode)
$procs = @(Get-Process | select -ExpandProperty ProcessName -Unique)
$names = '__FEATURES__'.Split(',')
$feat = $null; $featErr = $null
try { $feat = @(Get-WindowsFeature -Name $names -ErrorAction Stop | select Name,@{n='InstallState';e={"$($_.InstallState)"}}) } catch { $featErr = $_.Exception.Message }
$sql = @(); $k = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
if (Test-Path $k) {
  $ip = Get-ItemProperty $k
  foreach ($pr in @($ip.PSObject.Properties | ? { $_.Name -notlike 'PS*' })) {
    $st = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($pr.Value)\Setup" -ErrorAction SilentlyContinue
    $sql += [pscustomobject]@{ Instance=$pr.Name; InstanceId="$($pr.Value)"; Edition=$st.Edition; Version=$st.Version; PatchLevel=$st.PatchLevel }
  }
}
[pscustomobject]@{
  Host=$env:COMPUTERNAME; Caption=$os.Caption; Version=$os.Version; Build=$os.BuildNumber; UBR=$cv.UBR
  InstallationType=$cv.InstallationType; DomainRole=[int]$cs.DomainRole; Software=$sw; SoftwareCount=$sw.Count
  Services=$svc; Processes=$procs; Features=$feat; FeaturesError=$featErr; SqlInstances=$sql
} | ConvertTo-Json -Depth 4 -Compress
""".replace("__FEATURES__", ",".join(sorted({f for w in WORKLOADS.values() for f in w.get("features", [])}))), timeout=90)
    if not isinstance(raw, dict) or "Caption" not in raw:
        return raw
    c = _classify_workloads(raw)
    ctx = [w["label"] for w in c["workloads"].values()]
    out = {
        "host": raw.get("Host") or host,
        "os": {"caption": raw.get("Caption"), "version": raw.get("Version"), "build": raw.get("Build"), "ubr": raw.get("UBR"),
               "installation_type": raw.get("InstallationType"), "domain_role": raw.get("DomainRole")},
        "workloads": c["workloads"], "not_identified": c["not_identified"],
        "client_tools": c["client_tools"], "sql_client_tools_only": c["sql_client_tools_only"],
        "docs_context": ctx,
        "windows_features_checked": raw.get("FeaturesError") is None,
        "software_total": raw.get("SoftwareCount"),
        "rule": ("Carga só é declarada com evidência identificadora. "
                 + ("Evidência encontrada para: " + ", ".join(ctx) + "." if ctx else
                    "Nenhuma carga identificada: considerar apenas o sistema operacional e a versão.")),
    }
    if raw.get("FeaturesError"):
        out["windows_features_note"] = "Recursos do Windows indisponíveis nesta edição/permissão: evidência por recurso é indeterminada."
    if include_all_software:
        out["software"] = _lst(raw.get("Software"))[:400]
    return out


# ---------- postura operacional / segurança ----------
@mcp.tool
def get_security_posture(host: str):
    """Defender (status e idade das assinaturas), perfis do firewall e RDP habilitado."""
    return _ps(host, r"""
$mp = try { Get-MpComputerStatus | select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,
        AntivirusSignatureLastUpdated,AntivirusSignatureAge,QuickScanEndTime,FullScanEndTime } catch { $null }
$fw = Get-NetFirewallProfile | select Name,Enabled,DefaultInboundAction,DefaultOutboundAction
$rdp = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0)
[pscustomobject]@{Defender=$mp;Firewall=$fw;RdpEnabled=$rdp} | ConvertTo-Json -Depth 4 -Compress
""")




CERT_LOCATIONS = ("LocalMachine", "CurrentUser")
CERT_STORES = ("My", "WebHosting", "Root", "CA", "AuthRoot", "TrustedPeople", "TrustedPublisher", "Remote Desktop")


@mcp.tool
def get_expiring_certificates(host: str, days_threshold: int = 60, location: str = "LocalMachine", store: str = "My"):
    """Certificados vencidos ou que vencem em até N dias. Por padrão o repositório LocalMachine\\My. location:
    LocalMachine | CurrentUser (este é o da conta usada pela coleta). store: My, WebHosting, Root, CA, AuthRoot,
    TrustedPeople, TrustedPublisher ou 'Remote Desktop'."""
    if location not in CERT_LOCATIONS:
        raise ValueError("location deve ser LocalMachine ou CurrentUser")
    if store not in CERT_STORES:
        raise ValueError("store inválido. Válidos: " + ", ".join(CERT_STORES))
    return _ps(host, r"""
Get-ChildItem 'Cert:\__L__\__S__' -ErrorAction SilentlyContinue |
  select Subject,Issuer,Thumbprint,NotAfter,HasPrivateKey,
    @{n='DaysLeft';e={[int]($_.NotAfter-(Get-Date)).TotalDays}} |
  ? { $_.DaysLeft -le __D__ } | sort DaysLeft | ConvertTo-Json -Compress
""".replace("__D__", str(int(days_threshold))).replace("__L__", location).replace("__S__", store))


# ---------- saúde do CBS e do Windows Update (erros escondidos na aplicação de patches) ----------
HEX_RE = re.compile(r"0x[0-9A-Fa-f]{8}")
PATH_RE = re.compile(r"^[A-Za-z]:\\[^'\"`$;|&<>*?\r\n]{0,240}$")


def _lst(x):
    return x if isinstance(x, list) else ([] if not x else [x])


def _path(p: str) -> str:
    if not PATH_RE.match(p):
        raise ValueError(r"Caminho inválido (use o formato C:\pasta)")
    return p


@mcp.tool
def get_cbs_health(host: str):
    """Saúde do CBS (Component Based Servicing): DISM /CheckHealth (rápido, só leitura), pending.xml,
    flags de reboot/pacotes/sessões pendentes, TrustedInstaller e tamanho dos logs do CBS."""
    res = _ps(host, PS_DISM + r"""
$ErrorActionPreference='Continue'
$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
$d = RunDism '/Online /Cleanup-Image /CheckHealth' 90
$cbs = Get-ChildItem "$env:SystemRoot\Logs\CBS" -Force -ErrorAction SilentlyContinue
[pscustomobject]@{
  DismCheckHealth=$d.Output; DismExitCode=$d.ExitCode; DismBusy=$d.Busy; DismTimedOut=$d.TimedOut
  PendingXmlExists=(Test-Path "$env:SystemRoot\WinSxS\pending.xml")
  RebootPending=(Test-Path "$k\RebootPending"); RebootInProgress=(Test-Path "$k\RebootInProgress")
  PackagesPending=(Test-Path "$k\PackagesPending"); SessionsPending=(Test-Path "$k\SessionsPending")
  TrustedInstaller=(Get-Service TrustedInstaller | select @{n='Status';e={"$($_.Status)"}},@{n='StartType';e={"$($_.StartType)"}})
  CbsLogDir_MB=[math]::Round((($cbs | measure Length -Sum).Sum)/1MB,1)
  CbsLog_LastWrite=($cbs | ? Name -eq 'CBS.log' | select -first 1).LastWriteTime
} | ConvertTo-Json -Depth 3 -Compress
""", timeout=120)
    if isinstance(res, dict) and "DismCheckHealth" in res:
        txt = res["DismCheckHealth"] or ""
        res["Heuristic_StoreRepairable"] = bool(re.search(r"repairable|repar[aá]vel", txt, re.I))
    return res


@mcp.tool
def get_component_store_analysis(host: str, max_seconds: int = 300):
    """DISM /AnalyzeComponentStore: tamanho real do WinSxS, espaço recuperável e o que o próprio DISM informa sobre limpeza.
    Somente leitura, mas pode levar de 1 a 5 minutos. Não inicia se já houver um DISM rodando; se exceder
    'max_seconds' o DISM é encerrado (nada fica pendurado no servidor)."""
    return _ps(host, PS_DISM + r"""
$ErrorActionPreference='Continue'
RunDism '/Online /Cleanup-Image /AnalyzeComponentStore' __S__ | ConvertTo-Json -Compress
""".replace("__S__", str(max(60, min(int(max_seconds), 900)))), timeout=max(60, min(int(max_seconds), 900)) + 60)




# Busca nos logs CBS/DISM em 2 estágios:
#  1) PRÉ-FILTRO: palavras-chave procuradas com String.IndexOf ordinal em blocos de 16 MB (centenas de MB/s);
#     só as linhas que contêm alguma palavra são montadas; o resto do arquivo nunca vira string por linha.
#  2) CLASSIFICAÇÃO precisa (regex) só nessas linhas candidatas, descartando ruído conhecido (medido no lab):
#     'Error' solto casa com o pacote IIS-HttpErrors; 'Corrupt' com componentes CorruptedFileRepair;
#     'Missing' com linhas 'Appl: DetectUpdate'; 'CSI' com toda linha CSI (falha de CSI é marcada com '(F)').
# Modo 'rapida' = só sinais de ERRO, últimos 128 MB de cada arquivo, até 20 s.
# Modo 'detalhada' = também Warning/Failed/Missing/0x800..., período inteiro, até 300 s.
_CBS_NEEDLES_FAST = [", Error ", "HRESULT = 0x8", "Cannot repair", "(F)", "Fatal", "orrupt"]
CBS_SCAN_MODES = {
    "rapida": {
        "seconds": 20, "mb": 128, "needles": _CBS_NEEDLES_FAST,
        "sev": r"HRESULT = 0x8|\(F\)|Cannot repair|Fatal|[Cc]orrupt",
        "scope": "Só sinais de ERRO (nível Error, HRESULT 0x8..., Cannot repair, (F) do CSI, Fatal, corrupt).",
    },
    "detalhada": {
        "seconds": 300, "mb": 4096,
        "needles": _CBS_NEEDLES_FAST + [", Warning ", "0x800", "Failed", "failed", "Cannot ", "Missing", "MISSING"],
        "sev": (r"HRESULT = 0x8|\(F\)|Cannot |Fatal|[Cc]orrupt|0x800|[Ff]ailed|STATUS_\w*MISSING"
                r"|(?<![\w-])[Mm]issing(?![\w-])"),
        "scope": "Erros + avisos (nível Warning, Failed, Missing, 0x800..., Cannot ...).",
    },
}
_CBS_MODE_ALIASES = {"rapida": "rapida", "rápida": "rapida", "rapido": "rapida", "rápido": "rapida",
                     "quick": "rapida", "fast": "rapida", "detalhada": "detalhada", "detalhado": "detalhada",
                     "completa": "detalhada", "completo": "detalhada", "full": "detalhada", "deep": "detalhada"}
# Ruído: linhas Info que contêm a palavra-chave mas não são falha.
_CBS_NOISE = (r"[Nn]o (component store )?corruption|Microsoft-Windows-[\w.-]*Corrupt|Staging component"
              r"|^Appl: |Warning: Component architecture")


def _cbs_mode(mode: str) -> str:
    m = _CBS_MODE_ALIASES.get(str(mode).strip().lower())
    if not m:
        raise ValueError("mode deve ser 'rapida' ou 'detalhada'")
    return m


@mcp.tool
def get_cbs_log_errors(
    host: str,
    days: int = 1,
    mode: str = "rapida",
    include_dism: bool = True,
    top: int = 25,
    max_seconds: int | None = None,
    max_mb_per_file: int | None = None,
):
    """Problemas nos logs de servicing (CBS.log + CbsPersist_*.log e, se include_dism, dism.log) do ÚLTIMO DIA
    (days ampliável até 90 se pedido). Busca otimizada: pré-filtro por palavras-chave (IndexOf, sem processar o
    arquivo linha a linha), salto direto para o início do período (busca binária por data) e classificação só
    das linhas candidatas, descartando ruído conhecido. Agrupa mensagens repetidas, conta por fonte/nível e lista
    os HRESULTs mais frequentes com dica.
    mode='rapida' (padrão): só sinais de ERRO, últimos 128 MB de cada arquivo, até 20 s; responde em segundos.
    mode='detalhada': também warnings/Failed/Missing/0x800, período inteiro (até 4 GB/arquivo), até 300 s.
    max_seconds / max_mb_per_file sobrepõem os limites do modo. Se a leitura não cobrir tudo, devolve
    Coverage='parcial' + Recommendation com o tempo estimado da busca detalhada. Arquivos .cab são ignorados."""
    m = _cbs_mode(mode)
    cfg = CBS_SCAN_MODES[m]
    budget = max(5, min(int(max_seconds if max_seconds is not None else cfg["seconds"]), 600))
    max_mb = max(8, min(int(max_mb_per_file if max_mb_per_file is not None else cfg["mb"]), 4096))
    needles = ",".join("'" + n + "'" for n in cfg["needles"])
    res = _ps(host, timeout=budget + 90, script=r"""
$cutDate = (Get-Date).AddDays(-__D__); $cut = $cutDate.ToString('yyyy-MM-dd HH:mm:ss')
$budget = __B__; $maxBytes = [int64]__MB__ * 1MB; $O = [StringComparison]::Ordinal
$needles = @(__NEEDLES__); $sev = '__SEV__'; $noise = '__NOISE__'
$cbsDir = "$env:SystemRoot\Logs\CBS"
$files = @(Get-ChildItem $cbsDir -Filter 'CBS.log' -File -ErrorAction SilentlyContinue)
$files += @(Get-ChildItem $cbsDir -Filter 'CbsPersist_*.log' -File -ErrorAction SilentlyContinue | ? { $_.LastWriteTime -ge $cutDate } | sort LastWriteTime -desc)
if (__DISM__) { $files += @(Get-ChildItem "$env:SystemRoot\Logs\DISM" -Filter 'dism*.log' -File -ErrorAction SilentlyContinue | ? { $_.LastWriteTime -ge $cutDate }) }
$cabs = @(Get-ChildItem $cbsDir -Filter 'CbsPersist_*.cab' -File -ErrorAction SilentlyContinue | ? { $_.LastWriteTime -ge $cutDate }).Count
$pat = '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d), (\w+)\s+(\S+)\s+(.*)$'
$tsRx = [regex]'(?m)^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),'
# Timestamp da 1a linha datada a partir de $pos (lê só 64 KB).
function TsAt($fs, [int64]$pos) {
  [void]$fs.Seek($pos, 'Begin'); $b = New-Object byte[] 65536; $k = $fs.Read($b, 0, $b.Length)
  $mm = $tsRx.Match([Text.Encoding]::UTF8.GetString($b, 0, $k)); if ($mm.Success) { $mm.Groups[1].Value } else { $null }
}
# Offset aproximado da 1a linha >= $cut (busca binária; log é cronológico). Sem data no trecho => conservador.
function CutOffset($fs) {
  $first = TsAt $fs 0; if (-not $first -or $first -ge $cut) { return [int64]0 }
  $lo = [int64]0; $hi = [int64]$fs.Length
  while ($hi - $lo -gt 1MB) { $mid = [int64][math]::Floor(($lo + $hi) / 2); $t = TsAt $fs $mid
    if ($t -and $t -lt $cut) { $lo = $mid } else { $hi = $mid } }
  return $lo
}
$groups = @{}; $byLevel = @{}; $hr = @{}; $stats = @(); $cr = 0; $co = 0; $total = 0; $cand = 0
$partial = $false; $notRead = @(); $notReadMB = 0
$sw = [Diagnostics.Stopwatch]::StartNew()
$buf = New-Object char[] (16MB)
foreach ($f in $files) {
  if ($sw.Elapsed.TotalSeconds -ge $budget) { $partial = $true; $notRead += $f.Name; $notReadMB += $f.Length / 1MB; continue }
  $src = if ($f.Name -like 'dism*') { 'DISM' } else { 'CBS' }; $n = 0; $stopped = $false
  $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite, Delete')
  $len = $fs.Length; $dateStart = CutOffset $fs
  $start = [math]::Max($dateStart, $len - $maxBytes); $tailOnly = $start -gt $dateStart
  [void]$fs.Seek($start, 'Begin'); $sr = New-Object IO.StreamReader($fs); $carry = ''; $readChars = [int64]0
  if ($start -gt 0) { [void]$sr.ReadLine() }
  while ($true) {
    $read = $sr.Read($buf, 0, $buf.Length)
    if ($read -le 0) { $s = $carry; $carry = '' }
    else { $readChars += $read; $s = $carry + [string]::new($buf, 0, $read); $e = $s.LastIndexOf("`n")
      if ($e -lt 0) { $carry = $s; continue }; $carry = $s.Substring($e + 1); $s = $s.Substring(0, $e + 1) }
    # Estágio 1: pré-filtro por palavra-chave (só monta as linhas que casam).
    $seen = New-Object 'Collections.Generic.HashSet[int]'; $lines = New-Object 'Collections.Generic.List[string]'
    foreach ($nd in $needles) { $p = $s.IndexOf($nd, $O)
      while ($p -ge 0) { $ls = $s.LastIndexOf("`n", $p) + 1
        if ($seen.Add($ls)) { $le = $s.IndexOf("`n", $p); if ($le -lt 0) { $le = $s.Length }; $lines.Add($s.Substring($ls, $le - $ls)) }
        $p = $s.IndexOf($nd, $p + 1, $O) } }
    $cand += $lines.Count
    # Estágio 2: classificação precisa só das candidatas.
    foreach ($l in $lines) {
      $l = $l.TrimEnd("`r")
      if ($l.Length -lt 19 -or $l.Substring(0,19) -lt $cut) { continue }
      if ($l -notmatch $pat) { continue }
      $ts = $matches[1]; $lv = $matches[2]; $comp = $matches[3]; $msg = $matches[4].Trim()
      if ($lv -ne 'Error' -and $lv -ne 'Warning') {
        if ($msg -notmatch $sev -or $msg -match $noise) { continue }
        if ($lv -eq 'Info') { $lv = 'Info(falha)' } }
      $n++
      if ($msg -match 'Cannot repair') { $cr++ }
      if ($msg -match '[Cc]orrupt' -and $msg -notmatch $noise) { $co++ }
      if ($msg -match 'HRESULT = (0x[0-9A-Fa-f]{8})(?: - (\w+))?') { $c = $matches[1].ToLower(); if (-not $hr[$c]) { $hr[$c] = @(0, $matches[2]) }; $hr[$c][0]++ }
      $bk = "$src|$lv"; $byLevel[$bk] = 1 + [int]$byLevel[$bk]
      $norm = ($msg -replace '\{[0-9A-Fa-f-]{36}\}', '{GUID}' -replace '(?<!0x[0-9A-Fa-f]{0,7})\d+', '#')
      $key = "$src|$lv|" + $norm.Substring(0, [math]::Min(250, $norm.Length))
      $g = $groups[$key]
      if (-not $g) { $g = [pscustomobject]@{ Source=$src; Level=$lv; Component=$comp; Count=0; First=$ts; Last=$ts
          Sample=$msg.Substring(0,[math]::Min(300,$msg.Length)) }; $groups[$key] = $g }
      $g.Count++; if ($ts -lt $g.First) { $g.First = $ts }
      if ($ts -gt $g.Last) { $g.Last = $ts; $g.Sample = $msg.Substring(0,[math]::Min(300,$msg.Length)) }
    }
    if ($read -le 0) { break }
    if ($sw.Elapsed.TotalSeconds -ge $budget) { $partial = $true; $stopped = $true; break }
  }
  $sr.Close()
  $stats += [pscustomobject]@{ File=$f.Name; SizeMB=[math]::Round($len/1MB,1)
    InWindowMB=[math]::Round(($len - $dateStart)/1MB,1); DateSkippedMB=[math]::Round($dateStart/1MB,1)
    ReadMB=[math]::Round([math]::Min($len - $start, $readChars)/1MB,1)
    ProblemLines=$n; TailOnly=$tailOnly; StoppedByTime=$stopped }
  $total += $n
}
[pscustomobject]@{
  Mode='__MODE__'; PeriodDays=__D__; Since=$cut; ScanSeconds=[math]::Round($sw.Elapsed.TotalSeconds,1)
  Partial=$partial; FilesNotRead=$notRead; NotReadMB=[math]::Round($notReadMB,1); TimeBudgetSeconds=$budget; MaxMBPerFile=__MB__
  FilesScanned=$stats; CompressedCabsSkipped=$cabs; CandidateLines=$cand
  TotalProblemLines=$total; DistinctProblems=$groups.Count; CannotRepairCount=$cr; CorruptCount=$co
  ByLevel=@($byLevel.GetEnumerator() | sort Value -desc | % { [pscustomobject]@{ Source=$_.Key.Split('|')[0]; Level=$_.Key.Split('|')[1]; Count=$_.Value } })
  TopHResults=@($hr.GetEnumerator() | sort { $_.Value[0] } -desc | select -first 15 | % { [pscustomobject]@{ Code=$_.Key; Name=$_.Value[1]; Count=$_.Value[0] } })
  TopProblems=@($groups.Values | sort Count -desc | select -first __T__)
} | ConvertTo-Json -Depth 4 -Compress
""".replace("__NEEDLES__", needles).replace("__SEV__", cfg["sev"]).replace("__NOISE__", _CBS_NOISE)
       .replace("__MODE__", m).replace("__D__", str(_days(days)))
       .replace("__DISM__", "$true" if include_dism else "$false")
       .replace("__T__", str(max(1, min(int(top), 100)))).replace("__B__", str(budget))
       .replace("__MB__", str(max_mb)))
    if isinstance(res, dict) and "FilesScanned" in res:
        res["Scope"] = cfg["scope"]
        files = _lst(res.get("FilesScanned"))
        read_mb = sum(f.get("ReadMB") or 0 for f in files)
        pending_mb = sum(max(0, (f.get("InWindowMB") or 0) - (f.get("ReadMB") or 0)) for f in files) \
            + (res.get("NotReadMB") or 0)
        if res.get("Partial") or pending_mb > 1:
            secs = res.get("ScanSeconds") or 0
            thr = read_mb / secs if secs > 0.5 and read_mb > 0 else 50.0  # MB/s medido nesta execução
            est = int(round(pending_mb / thr + secs)) + 5
            res["Coverage"] = "parcial"
            res["Note"] = (f"Leitura parcial: {round(pending_mb, 1)} MB do período não foram lidos; "
                           "contagens são um limite inferior.")
            res["Recommendation"] = (f"Para cobertura total rode get_cbs_log_errors(mode='detalhada'"
                                     f"{', days=' + str(_days(days)) if _days(days) != 1 else ''}) "
                                     f"(estimativa ~{est} s; limite de 300 s).")
        else:
            res["Coverage"] = "completa"
            if m == "rapida":
                res["Recommendation"] = ("Busca rápida cobriu todo o período, mas só sinais de erro; "
                                         "mode='detalhada' inclui warnings/Failed/Missing.")
    return res


@mcp.tool
def get_windows_update_health(host: str):
    """Saúde do Windows Update: serviços (wuauserv, bits, cryptsvc, TrustedInstaller, msiserver),
    tamanho do SoftwareDistribution/DataStore/catroot2, proxy WinHTTP e espaço livre no disco do sistema."""
    return _ps(host, r"""
function SZ($p,$u){ if(Test-Path -LiteralPath $p){ [math]::Round(((Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | measure Length -Sum).Sum)/$u,2) } }
$sd = "$env:SystemRoot\SoftwareDistribution"
$ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
[pscustomobject]@{
  Services=@(Get-Service wuauserv,bits,cryptsvc,TrustedInstaller,msiserver -ErrorAction SilentlyContinue | select Name,Status,StartType)
  SoftwareDistributionDownload_GB=(SZ "$sd\Download" 1GB)
  SoftwareDistributionTotal_GB=(SZ $sd 1GB)
  DataStoreEdb_GB=[math]::Round(((Get-Item "$sd\DataStore\DataStore.edb" -ErrorAction SilentlyContinue).Length)/1GB,2)
  Catroot2_MB=(SZ "$env:SystemRoot\System32\catroot2" 1MB)
  WinHttpProxy=((netsh winhttp show proxy | Out-String).Trim())
  SystemDrive_FreeGB=[math]::Round($ld.FreeSpace/1GB,1)
} | ConvertTo-Json -Depth 4 -Compress
""", timeout=180)


@mcp.tool
def get_update_error_analysis(host: str, days: int = 1):
    """Falhas de instalação/download de updates agrupadas por código de erro (HRESULT). O significado do código é do RAG (microsoft-docs).
    days: padrão 1 (aumente se pedido, máx. 90)."""
    ev = _ps(host, r"""
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';
  StartTime=(Get-Date).AddDays(-__D__);Id=20,31} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,
    @{n='Message';e={Msg $_.Message 500}} |
  ConvertTo-Json -Compress
""".replace("__D__", str(_days(days))), timeout=120)
    if isinstance(ev, dict) and "Id" not in ev:
        return ev  # erro ou saída crua
    events = _lst(ev)
    agg = {}
    for e in events:
        for code in {c.lower() for c in HEX_RE.findall(e.get("Message") or "")}:
            a = agg.setdefault(code, {"error_code": code, "count": 0, "last_seen": None})
            a["count"] += 1
            a["last_seen"] = max(filter(None, [a["last_seen"], e.get("TimeCreated")]), default=None)
    return {"failure_events": len(events),
            "by_error_code": sorted(agg.values(), key=lambda a: -a["count"]),
            "recent_events": events[:20]}


# ---------- disco: espaço, ofensores e alocação sem uso ----------
@mcp.tool
def get_disk_usage_tree(
    host: str,
    path: str = "C:\\",
    depth: int = 3,
    top_children: int = 10,
    top_files: int = 25,
    min_file_size_mb: int = 100,
    threads: int = 8,
    scan_timeout_s: int = 300,
    old_days: int = 365,
    measure: str = "logical",
    dedupe_hardlinks: bool = False,
):
    """Análise de espaço estilo TreeSize, em uma única passada rápida (API nativa FindFirstFileEx + paralelismo).
    Retorna: árvore de pastas até 'depth' níveis (maiores filhos, % do total, contagem de arquivos e pastas, item
    'others' agrupando os menores), maiores arquivos, uso por extensão, volume de dados sem modificação há 'old_days'
    dias, contagem de acessos negados e o tempo do scan. Cada item traz DOIS tamanhos: size_gb (LÓGICO, como o Explorer)
    e disk_gb (EM DISCO: arredondado ao cluster do volume; compactados/esparsos pelo tamanho alocado; arquivos só-nuvem
    como OneDrive = 0, e 'cloud_only' informa quantos são). 'measure' escolhe qual deles ordena e calcula os
    percentuais: 'logical' (padrão) ou 'disk'. dedupe_hardlinks=true conta cada arquivo com vários links físicos
    (ex.: WinSxS) UMA vez só, na primeira ocorrência encontrada ('hardlinks' informa quantos foram pulados); é mais
    lento, pois abre cada arquivo. Se estourar scan_timeout_s devolve resultado parcial (partial=true).
    Exige Add-Type (C#) liberado no servidor."""
    p = _path(path)
    if measure not in ("logical", "disk"):
        raise ValueError("measure deve ser logical ou disk")
    depth = max(1, min(int(depth), 6))
    args = (f"'{p}', {depth}, {max(3, min(int(top_children), 30))}, {max(5, min(int(top_files), 100))}, "
            f"{max(1, int(min_file_size_mb)) * 1048576}, {max(1, min(int(threads), 16))}, "
            f"{max(30, min(int(scan_timeout_s), 1500))}, {max(1, int(old_days))}, "
            f"{'$true' if measure == 'disk' else '$false'}, {'$true' if dedupe_hardlinks else '$false'}")
    src = (Path(__file__).parent / "diskscan.cs").read_text(encoding="utf-8")
    script = f"$src = @'\n{src}\n'@\nAdd-Type -TypeDefinition $src\n[DiskScan]::Run({args})\n"
    res = _ps_long(host, script, timeout=max(30, min(int(scan_timeout_s), 1500)) + 60)
    if isinstance(res, dict) and "error" in res:
        res["hint"] = ("Falha ao compilar/executar o scanner (Add-Type bloqueado por AppLocker/WDAC/Constrained "
                       "Language?). Use get_largest_folders/get_largest_files como alternativa mais lenta.")
    return res


@mcp.tool
def get_largest_folders(host: str, path: str = "C:\\", top: int = 15):
    """Alternativa lenta (PowerShell puro) a get_disk_usage_tree: maiores itens de 'path', 1 nível."""
    p = _path(path)
    return _ps(host, r"""
Get-ChildItem -LiteralPath '__P__' -Force -ErrorAction SilentlyContinue | % {
  if($_.Attributes -band [IO.FileAttributes]::ReparsePoint){ $t='Link (ignorado)'; $s=0 }
  elseif($_.PSIsContainer){ $t='Pasta'; $s=(Get-ChildItem -LiteralPath $_.FullName -Recurse -Force -File -ErrorAction SilentlyContinue | measure Length -Sum).Sum }
  else { $t='Arquivo'; $s=$_.Length }
  [pscustomobject]@{Path=$_.FullName; Type=$t; SizeGB=[math]::Round($s/1GB,2)}
} | sort SizeGB -desc | select -first __N__ | ConvertTo-Json -Compress
""".replace("__P__", p).replace("__N__", str(min(int(top), 50))), timeout=600)


@mcp.tool
def get_largest_files(host: str, path: str = "C:\\", top: int = 20, min_size_mb: int = 500):
    """Alternativa lenta (PowerShell puro) a get_disk_usage_tree: maiores arquivos acima de min_size_mb."""
    p = _path(path)
    return _ps(host, r"""
Get-ChildItem -LiteralPath '__P__' -Recurse -Force -File -ErrorAction SilentlyContinue |
  ? { $_.Length -ge __MIN__ } | sort Length -desc | select -first __N__ |
  select FullName,@{n='SizeGB';e={[math]::Round($_.Length/1GB,2)}},LastWriteTime,Extension |
  ConvertTo-Json -Compress
""".replace("__P__", p).replace("__N__", str(min(int(top), 100))).replace("__MIN__", str(int(min_size_mb) * 1048576)),
        timeout=900)


@mcp.tool
def get_common_space_offenders(host: str):
    """Verifica rapidamente os ofensores clássicos de espaço: Temp, cache do WU, CBS logs, Installer, dumps
    (MEMORY.DMP/Minidump/LiveKernelReports), WER, logs do IIS, lixeira, pagefile/hiberfil, temp de usuários
    e armazenamento de Shadow Copies (VSS)."""
    return _ps(host, r"""
function SZ($p){ if(Test-Path -Path $p){ [math]::Round(((Get-ChildItem -Path $p -Recurse -Force -File -ErrorAction SilentlyContinue | measure Length -Sum).Sum)/1GB,2) } }
$sr=$env:SystemRoot; $sd=$env:SystemDrive
$dirs = [ordered]@{
 'Windows\Temp'="$sr\Temp"; 'WU download cache'="$sr\SoftwareDistribution\Download"
 'CBS logs'="$sr\Logs\CBS"; 'Windows\Installer'="$sr\Installer"; 'Minidump'="$sr\Minidump"
 'LiveKernelReports'="$sr\LiveKernelReports"; 'WER'="$env:ProgramData\Microsoft\Windows\WER"
 'IIS logs'="$sd\inetpub\logs"; 'Lixeira'=($sd+'\$Recycle.Bin'); 'Temp de usuários'="$sd\Users\*\AppData\Local\Temp"
 'SCCM cache'="$sr\ccmcache"
}
$items = foreach($k in $dirs.Keys){ [pscustomobject]@{Item=$k; Path=$dirs[$k]; SizeGB=(SZ $dirs[$k])} }
$files = foreach($f in "$sr\MEMORY.DMP","$sd\pagefile.sys","$sd\hiberfil.sys","$sd\swapfile.sys"){
  $i = Get-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
  if($i){ [pscustomobject]@{File=$f; SizeGB=[math]::Round($i.Length/1GB,2); LastWrite=$i.LastWriteTime} } }
$vss = try { Get-CimInstance Win32_ShadowStorage | select @{n='Volume';e={$_.Volume.DeviceID}},
  @{n='UsedGB';e={[math]::Round($_.UsedSpace/1GB,2)}},@{n='AllocatedGB';e={[math]::Round($_.AllocatedSpace/1GB,2)}},
  @{n='MaxGB';e={[math]::Round($_.MaxSpace/1GB,2)}} } catch { $null }
[pscustomobject]@{Folders=@($items | ? SizeGB | sort SizeGB -desc); Files=@($files); ShadowStorage=@($vss)} |
  ConvertTo-Json -Depth 4 -Compress
""", timeout=600)


@mcp.tool
def get_disk_allocation_analysis(host: str):
    """Discos físicos/virtuais alocados à VM/servidor mas sem uso: discos OFFLINE, RAW (não inicializados),
    espaço não alocado, partições sem letra/ponto de montagem e volumes com muito espaço livre (limiar à vista)."""
    data = _ps(host, r"""
$disks = @(Get-Disk | % { [pscustomobject]@{
  Number=$_.Number; Name=$_.FriendlyName; BusType=$_.BusType.ToString(); Partitioning=$_.PartitionStyle.ToString()
  SizeGB=[math]::Round($_.Size/1GB,1); AllocatedGB=[math]::Round($_.AllocatedSize/1GB,1)
  UnallocatedGB=[math]::Round(($_.Size-$_.AllocatedSize)/1GB,1)
  Operational=($_.OperationalStatus | Out-String).Trim(); Health=$_.HealthStatus.ToString()
  Offline=$_.IsOffline; ReadOnly=$_.IsReadOnly; Partitions=$_.NumberOfPartitions } })
$parts = @(Get-Partition -ErrorAction SilentlyContinue | select DiskNumber,PartitionNumber,
  @{n='Type';e={$_.Type.ToString()}},
  @{n='DriveLetter';e={ if($_.DriveLetter){ [string]$_.DriveLetter } else { $null } }},
  @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},
  @{n='MountPaths';e={ @($_.AccessPaths | ? { $_ -and $_ -notlike '\\?\*' }) }})
$vols = @(Get-Volume | ? { $_.DriveType -eq 'Fixed' } | select DriveLetter,FileSystemLabel,FileSystem,
  @{n='Health';e={$_.HealthStatus.ToString()}},
  @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}},
  @{n='FreePct';e={ if($_.Size){ [math]::Round(100*$_.SizeRemaining/$_.Size,1) } }})
[pscustomobject]@{Disks=$disks;Partitions=$parts;Volumes=$vols} | ConvertTo-Json -Depth 4 -Compress
""", timeout=120)
    if not isinstance(data, dict) or "Disks" not in data:
        return data
    findings = []
    for d in _lst(data["Disks"]):
        tag = f"Disco {d['Number']} ({d['Name']}, {d['SizeGB']} GB, {d['BusType']})"
        if d["Offline"]:
            findings.append(f"{tag}: OFFLINE – capacidade alocada sem uso.")
        elif d["Partitioning"] == "RAW":
            findings.append(f"{tag}: não inicializado (RAW) – alocado e nunca utilizado.")
        elif d["UnallocatedGB"] >= 1:
            findings.append(f"{tag}: {d['UnallocatedGB']} GB não alocados.")
        if d["Health"] != "Healthy":
            findings.append(f"{tag}: HealthStatus = {d['Health']}.")
    for p in _lst(data["Partitions"]):
        if p["Type"] == "Basic" and not p["DriveLetter"] and not _lst(p["MountPaths"]):
            findings.append(f"Disco {p['DiskNumber']} partição {p['PartitionNumber']} ({p['SizeGB']} GB): "
                            "sem letra nem ponto de montagem.")
    for v in _lst(data["Volumes"]):
        if v["SizeGB"] and v["SizeGB"] >= 100 and (v["FreePct"] or 0) >= 90:
            findings.append(f"Volume {v['DriveLetter'] or v['FileSystemLabel']}: {v['SizeGB']} GB com "
                            f"{v['FreePct']}% livre (limiar do projeto: volume >= 100 GB com >= 90% livre).")
    data["Findings"] = findings or ["Nenhum sinal encontrado."]
    return data


# ---------- uptime, últimos patches e validação do CBS ----------
@mcp.tool
def get_uptime(host: str):
    """Uptime: último boot, dias/horas ligado, quem/por que reiniciou por último (evento 1074) e se o
    último boot veio de desligamento inesperado (eventos 41/6008), além da contagem em 30 dias."""
    return _ps(host, r"""
$os = Get-CimInstance Win32_OperatingSystem
$boot = $os.LastBootUpTime; $up = (Get-Date) - $boot
$sd = Get-WinEvent -FilterHashtable @{LogName='System';Id=1074} -MaxEvents 1 -ErrorAction SilentlyContinue
$last = $null
if ($sd) { $p = $sd.Properties; $last = [pscustomobject]@{
  Time=$sd.TimeCreated; Process=$p[0].Value; Reason=$p[2].Value; Type=$p[4].Value; Comment=$p[5].Value; User=$p[6].Value } }
$unexpBoot = @(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,6008;StartTime=$boot.AddMinutes(-5)} -ErrorAction SilentlyContinue | ? { $_.Id -eq 6008 -or $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' })
$unexp30 = @(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,6008;StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | ? { $_.Id -eq 6008 -or $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' })
[pscustomobject]@{
  Host=$env:COMPUTERNAME; LastBoot=$boot
  UptimeDays=[math]::Round($up.TotalDays,2); UptimeText=('{0}d {1}h {2}m' -f $up.Days,$up.Hours,$up.Minutes)
  LastPlannedShutdown=$last
  LastBootWasUnexpected=($unexpBoot.Count -gt 0)
  UnexpectedShutdowns30d=$unexp30.Count
} | ConvertTo-Json -Depth 3 -Compress
""")


@mcp.tool
def get_last_patches(host: str, top: int = 10, installed_since_days: int | None = None):
    """Últimos patches aplicados: Get-HotFix (KB, data, dias atrás) + instalações com sucesso do Windows
    Update (evento 19), build/UBR atual e dias desde o último patch. installed_since_days (0 = hoje, 1 = hoje e ontem, dias de
    calendário do servidor) devolve SÓ os patches do período (KB, descrição e data), sem build nem outros dados; o Get-HotFix
    informa só a DATA, não a hora. Só sugere o que mais pode ser obtido."""
    if installed_since_days is not None:
        n = max(0, min(int(installed_since_days), 3650))
        res = _ps(host, r"""
$today = (Get-Date).Date; $since = $today.AddDays(-__S__)
$hf = @(Get-HotFix | ? { $_.InstalledOn -and $_.InstalledOn.Date -ge $since } | sort InstalledOn -desc |
  select @{n='Kb';e={$_.HotFixID}}, Description, @{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}})
$wu = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';Id=19;StartTime=$since} -ErrorAction SilentlyContinue |
  select @{n='Time';e={$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')}}, @{n='Update';e={$_.Properties[0].Value}})
[pscustomobject]@{ ServerDate=$today.ToString('yyyy-MM-dd'); UtcOffset=[TimeZoneInfo]::Local.BaseUtcOffset.ToString(); HotFixes=$hf; WuInstalls=$wu } | ConvertTo-Json -Depth 4 -Compress
""".replace("__S__", str(n)), timeout=90)
        if not isinstance(res, dict) or "HotFixes" not in res:
            return res
        hf = [{"kb": x.get("Kb"), "description": x.get("Description"), "installedOn": x.get("InstalledOn")} for x in _lst(res.get("HotFixes"))]
        out = {"host": host, "serverDate": res.get("ServerDate"), "serverUtcOffset": res.get("UtcOffset"),
               "window": _since_label(n), "count": len(hf), "patches": hf,
               "note": "Get-HotFix informa só a data da instalação, não a hora."}
        wu = _lst(res.get("WuInstalls"))
        if wu:
            out["windowsUpdateInstallEvents"] = wu   # só aparece se houver eventos de instalação no período
        out["more_available"] = _more("build atual, histórico de falhas do Windows Update, reinicializações, software instalado no período")
        return out
    return _ps(host, r"""
$now = Get-Date
$nt = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$hf = @(Get-HotFix | ? InstalledOn | sort InstalledOn -desc | select -first __N__ HotFixID,Description,InstalledOn,InstalledBy,
  @{n='DaysAgo';e={[int]($now-$_.InstalledOn).TotalDays}})
$wu = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';Id=19} -MaxEvents __N__ -ErrorAction SilentlyContinue |
  select TimeCreated,@{n='Update';e={$_.Properties[0].Value}},@{n='DaysAgo';e={[int]($now-$_.TimeCreated).TotalDays}})
$lastDays = $null; if ($hf.Count) { $lastDays = $hf[0].DaysAgo }
[pscustomobject]@{
  OS=$nt.ProductName; DisplayVersion=$nt.DisplayVersion; Build="$($nt.CurrentBuild).$($nt.UBR)"
  DaysSinceLastPatch=$lastDays; HotFixes=$hf; WindowsUpdateInstalls=$wu
} | ConvertTo-Json -Depth 4 -Compress
""".replace("__N__", str(max(1, min(int(top), 50)))), timeout=120)


CBS_CODES = {"0x80073712", "0x80073701", "0x800f081f", "0x800f0831", "0x800f0922", "0x800f0982", "0x800f0988"}
SEM, SIG, INC = "sem_sinais", "sinais_presentes", "verificacao_incompleta"
_RANK = {SEM: 0, SIG: 1, INC: 2}  # só fatos: nada de severidade (OK/Atenção/Crítico é interpretação do RAG)


def _worst(*st: str) -> str:
    return max(st, key=lambda s: _RANK[s]) if st else SEM


@mcp.tool
def validate_cbs(host: str, days: int = 1, log_mode: str = "rapida"):
    """Verificação objetiva do CBS: combina DISM /CheckHealth, flags de pending/reboot, contagens de
    'Cannot repair'/'corrupt' nos logs CBS/DISM e falhas de update com códigos HRESULT do CBS.
    As três coletas rodam EM PARALELO. Período dos logs: último dia por padrão (days ampliável até 90 se pedido).
    log_mode='rapida' (padrão, segundos) ou 'detalhada' (cobertura total dos logs, pode levar minutos).
    Retorna status (sem_sinais | sinais_presentes | verificacao_incompleta) e as evidências coletadas. Não recomenda
    ação nem classifica gravidade: isso é do RAG (microsoft-docs)."""
    lm = _cbs_mode(log_mode)
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_health = pool.submit(get_cbs_health, host)
        f_log = pool.submit(get_cbs_log_errors, host, days=days, mode=lm, top=10)
        f_upd = pool.submit(get_update_error_analysis, host, days=days)
        health, log, upd = f_health.result(), f_log.result(), f_upd.result()
    if not isinstance(health, dict) or "error" in health:
        return {"status": "Desconhecido", "error": health}

    status, evid = SEM, []
    dism = health.get("DismCheckHealth") or ""
    if re.search(r"cannot be repaired|não pode ser reparad", dism, re.I):
        status = _worst(status, SIG)
        evid.append("DISM: component store reportado como NÃO reparável.")
    elif health.get("Heuristic_StoreRepairable"):
        status = _worst(status, SIG)
        evid.append("DISM /CheckHealth: component store corrompido (reparável).")
    elif health.get("DismBusy") or health.get("DismTimedOut"):
        status = _worst(status, SIG)
        evid.append("DISM /CheckHealth não concluiu: " + (health.get("DismCheckHealth") or ""))
    elif health.get("DismExitCode") not in (0, None):
        status = _worst(status, SIG)
        evid.append(f"DISM retornou código {health.get('DismExitCode')}.")

    if health.get("PendingXmlExists") or health.get("RebootPending") or health.get("RebootInProgress"):
        status = _worst(status, SIG)
        evid.append("Operações de servicing pendentes (pending.xml/RebootPending/RebootInProgress).")
    if health.get("SessionsPending") or health.get("PackagesPending"):
        status = _worst(status, SIG)
        evid.append("Sessões/pacotes CBS pendentes.")

    ti = health.get("TrustedInstaller") or {}
    if str(ti.get("StartType")) in ("4", "Disabled"):
        status = _worst(status, SIG)
        evid.append("Serviço TrustedInstaller com início desabilitado.")

    # Uma verificação que falhou NÃO pode contar como limpa: eleva para Atenção e registra o motivo.
    incomplete = []
    if isinstance(log, dict) and "TotalProblemLines" in log:
        if (log.get("CannotRepairCount") or 0) > 0:
            status = _worst(status, SIG)
            evid.append(f"CBS.log: {log['CannotRepairCount']} ocorrência(s) de 'Cannot repair'.")
        if (log.get("CorruptCount") or 0) > 0:
            status = _worst(status, SIG)
            evid.append(f"CBS.log: {log['CorruptCount']} menção(ões) a 'corrupt'.")
        if log.get("Partial"):
            incomplete.append("leitura dos logs CBS/DISM foi parcial (limite de tempo); contagens são mínimas")
        elif log.get("Coverage") == "parcial":
            # Limite de tamanho do modo rápido: sinaliza sem rebaixar o status (não é falha de verificação).
            evid.append(f"Logs CBS: busca {log.get('Mode')} leu o trecho mais recente; {log.get('Note')}")
    else:
        incomplete.append(f"não foi possível ler os logs CBS/DISM: {log.get('error') if isinstance(log, dict) else log}")

    if not (isinstance(upd, dict) and "by_error_code" in upd):
        incomplete.append("não foi possível ler as falhas do Windows Update: "
                          f"{upd.get('error') if isinstance(upd, dict) else upd}")
    for msg in incomplete:
        status = _worst(status, INC)
        evid.append(f"Verificação incompleta: {msg}.")

    if isinstance(upd, dict) and "by_error_code" in upd:
        bad = [c for c in upd["by_error_code"] if c["error_code"] in CBS_CODES]
        if bad:
            status = _worst(status, SIG)
            for c in bad:
                evid.append(f"Windows Update: {c['error_code']} x{c['count']} (último {c['last_seen']}).")

    if (health.get("CbsLogDir_MB") or 0) > 2048:
        evid.append(f"Pasta de logs do CBS com {health['CbsLogDir_MB']} MB.")
    return {
        "host": host, "status": status,
        "verdict": {SEM: "Nenhum sinal encontrado nas verificações executadas.",
                    SIG: "Há sinais nas verificações executadas (ver evidence); a interpretação é do RAG.",
                    INC: "Há verificação incompleta (ver evidence); o resultado não cobre tudo."}[status],
        "complete": not incomplete,
        "evidence": evid or ["Nenhum sinal encontrado."],
        "details": {"cbs_health": health, "cbs_log": log,
                    "update_errors": (upd.get("by_error_code") if isinstance(upd, dict) and "by_error_code" in upd
                                      else upd)},
    }


# ---------- rede ----------
@mcp.tool
def get_network_config(host: str):
    """Configuração de rede dos adaptadores ativos: IPv4/IPv6, gateway, DNS, sufixo DNS, DHCP, MAC e velocidade."""
    return _ps(host, r"""
$out = foreach ($c in @(Get-NetIPConfiguration | ? { $_.NetAdapter.Status -eq 'Up' })) {
  $ipif = Get-NetIPInterface -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
  $dc = Get-DnsClient -InterfaceIndex $c.InterfaceIndex -ErrorAction SilentlyContinue
  [pscustomobject]@{
    Interface=$c.InterfaceAlias; Description=$c.InterfaceDescription
    MAC=$c.NetAdapter.MacAddress; LinkSpeed=$c.NetAdapter.LinkSpeed
    Dhcp=if ($ipif) { $ipif.Dhcp.ToString() } else { $null }
    IPv4=@($c.IPv4Address | % { "$($_.IPAddress)/$($_.PrefixLength)" })
    IPv6=@($c.IPv6Address | % { $_.IPAddress })
    Gateway=@($c.IPv4DefaultGateway | % { $_.NextHop })
    DnsServers=@($c.DNSServer | ? AddressFamily -eq 2 | % { $_.ServerAddresses })
    DnsSuffix=$dc.ConnectionSpecificSuffix
    RegisterInDns=$dc.RegisterThisConnectionsAddress
  }
}
[pscustomobject]@{
  Host=$env:COMPUTERNAME; Adapters=@($out)
  DnsSearchList=@((Get-DnsClientGlobalSetting).SuffixSearchList)
} | ConvertTo-Json -Depth 4 -Compress
""")


@mcp.tool
def get_listening_ports(host: str, include_udp: bool = False, port: int | None = None):
    """Portas TCP em escuta (e opcionalmente UDP) com o processo e os serviços donos de cada porta.
    port (1-65535) limita a essa porta local."""
    udp = "$true" if include_udp else "$false"
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError("port deve estar entre 1 e 65535")
    return _ps(host, r"""
$proc = @{}; Get-Process | % { $proc[[int]$_.Id] = $_.ProcessName }
$svc = @{}; Get-CimInstance Win32_Service | ? { $_.ProcessId } | % { $k=[int]$_.ProcessId; $svc[$k] = @($svc[$k]) + $_.Name }
function Row($proto, $e) { $k=[int]$e.OwningProcess
  [pscustomobject]@{ Protocol=$proto; LocalAddress=$e.LocalAddress; LocalPort=$e.LocalPort; PID=$k
    Process=$proc[$k]; Services=(@($svc[$k] | ? { $_ }) -join ',') } }
$rows = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | % { Row 'TCP' $_ })
if (__UDP__) { $rows += @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ? { $_.LocalPort -lt 49152 } | % { Row 'UDP' $_ }) }
$rows | ? { -not __PORT__ -or $_.LocalPort -eq __PORT__ } | sort Protocol,LocalPort,LocalAddress | ConvertTo-Json -Compress
""".replace("__UDP__", udp).replace("__PORT__", str(int(port)) if port is not None else "0"))


@mcp.tool
def test_connectivity(host: str, target: str, port: int | None = None):
    """Testa, A PARTIR do servidor 'host', resolução de nome, ping e (se 'port' for informado) conexão TCP
    até 'target'. Útil para diagnosticar dependências (AD, SQL, file server, proxy)."""
    if not HOST_RE.match(target):
        raise ValueError("target inválido")
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError("port deve estar entre 1 e 65535")
    port_arg = f"-Port {int(port)}" if port is not None else ""
    return _ps(host, rf"""
$ProgressPreference='SilentlyContinue'
try {{
  $r = Test-NetConnection -ComputerName '{target}' {port_arg} -WarningAction SilentlyContinue
  [pscustomobject]@{{
    Source=$env:COMPUTERNAME; Target='{target}'; Port={int(port) if port is not None else '$null'}
    NameResolved=[bool]$r.RemoteAddress; RemoteAddress="$($r.RemoteAddress)"
    PingSucceeded=$r.PingSucceeded; PingRttMs=$r.PingReplyDetails.RoundtripTime
    TcpTestSucceeded=$r.TcpTestSucceeded
    SourceAddress="$($r.SourceAddress.IPAddress)"; InterfaceAlias=$r.InterfaceAlias
  }} | ConvertTo-Json -Compress
}} catch {{ [pscustomobject]@{{Target='{target}'; Error=$_.Exception.Message}} | ConvertTo-Json -Compress }}
""", timeout=90)


@mcp.tool
def get_network_adapters(host: str):
    """Configuração detalhada das placas de rede: status, velocidade, duplex, MTU, VLAN, driver (versão/data),
    RSS, IPv6 habilitado, contadores de erros/descartes, propriedades avançadas (offloads, jumbo, buffers)
    e NIC Teaming (LBFO) / SET quando existir."""
    return _ps(host, r"""
$ad = foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
  $st = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
  $rss = Get-NetAdapterRss -Name $a.Name -ErrorAction SilentlyContinue
  $v6 = Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
  [pscustomobject]@{
    Name=$a.Name; Description=$a.InterfaceDescription; Status="$($a.Status)"; LinkSpeed=$a.LinkSpeed
    FullDuplex=$a.FullDuplex; MAC=$a.MacAddress; MtuBytes=$a.MtuSize; VlanID=$a.VlanID; Virtual=$a.Virtual
    DriverProvider=$a.DriverProvider; DriverVersion=$a.DriverVersionString; DriverDate=$a.DriverDate
    RssEnabled=$rss.Enabled; IPv6Enabled=$v6.Enabled
    RxGB=$(if ($st) { [math]::Round($st.ReceivedBytes/1GB,2) }); TxGB=$(if ($st) { [math]::Round($st.SentBytes/1GB,2) })
    RxErrors=$st.ReceivedPacketErrors; RxDiscarded=$st.ReceivedDiscardedPackets
    TxErrors=$st.OutboundPacketErrors; TxDiscarded=$st.OutboundDiscardedPackets
    Advanced=@(Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue | ? DisplayValue |
      select -first 40 DisplayName,DisplayValue)
  }
}
$teams = @(try { @(Get-NetLbfoTeam -ErrorAction Stop | select Name,@{n='Mode';e={"$($_.TeamingMode)"}},
  @{n='LB';e={"$($_.LoadBalancingAlgorithm)"}},@{n='Members';e={$_.Members -join ','}},@{n='Status';e={"$($_.Status)"}}) } catch { @() })
$set = @(try { @(Get-VMSwitch -ErrorAction Stop | ? EmbeddedTeamingEnabled | select Name,@{n='Members';e={$_.NetAdapterInterfaceDescriptions -join ','}}) } catch { @() })
[pscustomobject]@{ Host=$env:COMPUTERNAME; Adapters=@($ad); LbfoTeams=$teams; SetSwitches=$set } | ConvertTo-Json -Depth 5 -Compress
""", timeout=120)


@mcp.tool
def get_routes(host: str, include_ipv6: bool = False):
    """Tabela de rotas (ativa) e rotas persistentes: destino, next hop, interface, métricas e origem.
    Ignora rotas de multicast/broadcast. Útil para rotas estáticas erradas, gateway duplicado, assimetria."""
    fam = "" if include_ipv6 else "-AddressFamily IPv4"
    return _ps(host, rf"""
$skip = '^(224\.0\.0\.0/4|255\.255\.255\.255/32|ff00::/8)$'
$act = @(Get-NetRoute {fam} -ErrorAction SilentlyContinue | ? {{ $_.DestinationPrefix -notmatch $skip }} |
  sort DestinationPrefix | select DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,
  @{{n='InterfaceMetric';e={{$_.InterfaceMetric}}}},@{{n='Protocol';e={{"$($_.Protocol)"}}}})
$per = @(Get-NetRoute {fam} -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
  select DestinationPrefix,NextHop,InterfaceAlias,RouteMetric)
[pscustomobject]@{{
  DefaultGateways=@($act | ? {{ $_.DestinationPrefix -in '0.0.0.0/0','::/0' }})
  PersistentRoutes=$per; ActiveRoutes=$act
}} | ConvertTo-Json -Depth 4 -Compress
""")


@mcp.tool
def get_network_connections(host: str, state: str | None = None, top: int = 30, port: int | None = None):
    """Equivalente ao 'netstat -ano' com análise: contagem por estado TCP, maiores destinos remotos, processos com
    mais conexões, uso de portas efêmeras e alerta de TIME_WAIT/CLOSE_WAIT excessivos.
    state (opcional): Established|Listen|TimeWait|CloseWait|SynSent|... para listar as conexões nesse estado.
    port (opcional, 1-65535): lista as conexões cuja porta local OU remota é essa (qualquer estado, ou o de 'state')
    e informa em 'PortMatches' quantas existem."""
    if state is not None and not re.match(r"^[A-Za-z]{3,15}$", state):
        raise ValueError("state inválido")
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError("port deve estar entre 1 e 65535")
    n = max(1, min(int(top), 200))
    res = _ps(host, r"""
$proc = @{}; Get-Process | % { $proc[[int]$_.Id] = $_.ProcessName }
$c = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
$dyn = (netsh int ipv4 show dynamicport tcp | Out-String) -split "`n" | % { if ($_ -match ':\s*(\d+)') { [int]$matches[1] } }
$start = $dyn[0]; $count = $dyn[1]
$eph = @($c | ? { $_.LocalPort -ge $start -and $_.LocalPort -lt ($start + $count) -and "$($_.State)" -ne 'Listen' }).Count
$est = @($c | ? { "$($_.State)" -eq 'Established' })
[pscustomobject]@{
  Total=$c.Count
  ByState=@($c | group { "$($_.State)" } | sort Count -desc | select @{n='State';e={$_.Name}},Count)
  DynamicPortRange="$start-$($start+$count-1)"; EphemeralInUse=$eph; EphemeralCapacity=$count
  TopRemoteAddresses=@($est | ? { $_.RemoteAddress -notin '127.0.0.1','::1' } | group RemoteAddress | sort Count -desc | select -first __N__ @{n='RemoteAddress';e={$_.Name}},Count,
    @{n='Ports';e={(@($_.Group.RemotePort | select -unique | select -first 10) -join ',')}})
  TopProcesses=@($c | group OwningProcess | sort Count -desc | select -first __N__ @{n='PID';e={[int]$_.Name}},
    @{n='Process';e={$proc[[int]$_.Name]}},Count,@{n='States';e={(@($_.Group | group { "$($_.State)" } | % { "$($_.Name)=$($_.Count)" }) -join ' ')}})
  PortMatches=$(if (__PORT__) { @($c | ? { $_.LocalPort -eq __PORT__ -or $_.RemotePort -eq __PORT__ }).Count } else { $null })
  Connections=@(if ('__S__' -or __PORT__) { $c | ? { (-not '__S__' -or "$($_.State)" -eq '__S__') -and (-not __PORT__ -or $_.LocalPort -eq __PORT__ -or $_.RemotePort -eq __PORT__) } | select -first __N__ LocalAddress,LocalPort,RemoteAddress,RemotePort,
    @{n='State';e={"$($_.State)"}},@{n='PID';e={$_.OwningProcess}},@{n='Process';e={$proc[[int]$_.OwningProcess]}} })
} | ConvertTo-Json -Depth 4 -Compress
""".replace("__N__", str(n)).replace("__S__", state or "").replace("__PORT__", str(int(port)) if port is not None else "0"), timeout=120)
    if isinstance(res, dict) and "ByState" in res:
        st = {s["State"]: s["Count"] for s in _lst(res["ByState"])}
        alerts = []
        if st.get("TimeWait", 0) > 5000:
            alerts.append(f"{st['TimeWait']} conexões em TIME_WAIT (limiar do projeto: 5000).")
        if st.get("CloseWait", 0) > 100:
            alerts.append(f"{st['CloseWait']} em CLOSE_WAIT (limiar do projeto: 100; ver TopProcesses).")
        cap = res.get("EphemeralCapacity") or 0
        if cap and res.get("EphemeralInUse", 0) > 0.7 * cap:
            alerts.append(f"Portas efêmeras {res['EphemeralInUse']}/{cap} em uso (limiar do projeto: 70%).")
        res["Alerts"] = alerts or ["Nenhum sinal encontrado."]
    return res


@mcp.tool
def get_applied_gpos(host: str, days: int = 1):
    """GPOs aplicadas ao computador e aos usuários com perfil carregado (lidas do estado do Group Policy no
    registro, sem gerar arquivos): nome, GUID, link (OU/site/domínio), versão, OU do computador, site, DC usado,
    último processamento e erros/avisos do Group Policy no último dia (days ampliável até 90 se pedido)."""
    return _ps(host, r"""
$root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State'
function GpoList($k) { @(Get-ChildItem "$k\GPO-List" -ErrorAction SilentlyContinue | % { $p = Get-ItemProperty $_.PSPath
  [pscustomobject]@{ Name=$p.DisplayName; Guid=$p.GPOID; Link=$p.SOM; Version=$p.Version; AccessDenied=[bool]$p.AccessDenied; Disabled=[bool]$p.'GPO-Disabled'; WmiFilterPass=[bool]$p.WQLFilterPass } }) }
function GpTime($p) { try { if ($p.EndTimeHi -ne $null) { [DateTime]::FromFileTimeUtc(([int64][uint32]$p.EndTimeHi -shl 32) -bor [uint32]$p.EndTimeLo) } } catch { $null } }
$m = Get-ItemProperty "$root\Machine" -ErrorAction SilentlyContinue
$ext = Get-ItemProperty "$root\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}" -ErrorAction SilentlyContinue
$users = @(Get-ChildItem $root -ErrorAction SilentlyContinue | ? { $_.PSChildName -like 'S-1-5-21-*' } | % {
  $sid = $_.PSChildName; $n = try { (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { $sid }
  $u = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
  [pscustomobject]@{ User=$n; DistinguishedName=$u.'Distinguished-Name'; GPOs=@(GpoList $_.PSPath) } })
$since = (Get-Date).AddDays(-__H__)
$log = 'Microsoft-Windows-GroupPolicy/Operational'
$last = Get-WinEvent -FilterHashtable @{LogName=$log;Id=8000,8001,8002,8003,8004,8005,8006,8007} -MaxEvents 1 -ErrorAction SilentlyContinue
[pscustomobject]@{
  Computer=[pscustomobject]@{ DistinguishedName=$m.'Distinguished-Name'; Site=$m.'Site-Name'; DomainController=$m.DC
    LastPolicyProcessing=(GpTime $ext); GPOs=@(GpoList "$root\Machine") }
  Users=$users
  LastProcessingEvent=$(if ($last) { [pscustomobject]@{ Time=$last.TimeCreated; Id=$last.Id; Message=(Msg $last.Message 300) } })
  ErrorsAndWarnings=@(Get-WinEvent -FilterHashtable @{LogName=$log;Level=1,2,3;StartTime=$since} -MaxEvents 30 -ErrorAction SilentlyContinue |
    select TimeCreated,Id,LevelDisplayName,@{n='Message';e={Msg $_.Message 400}})
  SystemGpErrors=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-GroupPolicy';Level=1,2,3;StartTime=$since} -MaxEvents 20 -ErrorAction SilentlyContinue |
    select TimeCreated,Id,@{n='Message';e={Msg $_.Message 400}})
} | ConvertTo-Json -Depth 5 -Compress
""".replace("__H__", str(_days(days))), timeout=120)


@mcp.tool
def get_top_resource_consumers(host: str, sample_seconds: int = 5, top: int = 10, by: str = "both"):
    """Processos que mais consomem CPU e memória, MEDIDOS por amostragem (delta de tempo de CPU em
    'sample_seconds', normalizado pelo nº de CPUs lógicas: mais preciso que leitura instantânea).
    Para cada processo: CPU%, memória privada, working set, handles, threads, dono, início, serviços hospedados
    e linha de comando. Inclui o total de CPU e memória do servidor. O processo do próprio PowerShell da coleta é
    excluído das listas. 'by': cpu | memory | both (padrão). Pergunta só de CPU ou só de memória: passe 'cpu' ou 'memory'."""
    if by not in ("cpu", "memory", "both"):
        raise ValueError("by deve ser cpu, memory ou both")
    secs = max(1, min(int(sample_seconds), 30))
    res = _ps(host, r"""
$n = __N__; $secs = __S__
$cores = [Environment]::ProcessorCount
$t1 = @{}; Get-Process | % { try { $t1[$_.Id] = $_.TotalProcessorTime.TotalMilliseconds } catch {} }
$sw = [Diagnostics.Stopwatch]::StartNew(); Start-Sleep -Seconds $secs; $el = $sw.Elapsed.TotalMilliseconds
$wp = @{}; Get-CimInstance Win32_Process | % { $wp[[int]$_.ProcessId] = $_ }
$svc = @{}; Get-CimInstance Win32_Service | ? { $_.ProcessId } | % { $k=[int]$_.ProcessId; $svc[$k] = @($svc[$k]) + $_.Name }
$rows = @(Get-Process | ? { $_.Id -ne 0 -and $_.Id -ne $PID } | % {
  $cpu = 0; try { if ($t1.ContainsKey($_.Id)) { $cpu = [math]::Round(100*($_.TotalProcessorTime.TotalMilliseconds - $t1[$_.Id])/($el*$cores),1) } } catch {}
  [pscustomobject]@{ Name=$_.ProcessName; PID=$_.Id; CpuPct=$cpu
    PrivateMB=[math]::Round($_.PrivateMemorySize64/1MB,1); WorkingSetMB=[math]::Round($_.WorkingSet64/1MB,1)
    Handles=$_.HandleCount; Threads=$_.Threads.Count } })
function Enrich($r) { $w = $wp[[int]$r.PID]
  $o = try { $x = Invoke-CimMethod -InputObject $w -MethodName GetOwner -ErrorAction Stop; if ($x.User) { "$($x.Domain)\$($x.User)" } } catch { $null }
  $r | Add-Member -NotePropertyMembers @{ Owner=$o; Started=$w.CreationDate; Services=(@($svc[[int]$r.PID] | ? { $_ }) -join ',')
    CommandLine=$(if ($w.CommandLine) { $w.CommandLine.Substring(0,[math]::Min(300,$w.CommandLine.Length)) } else { $null }) } -Force -PassThru }
$os = Get-CimInstance Win32_OperatingSystem
[pscustomobject]@{
  Host=$env:COMPUTERNAME; SampleSeconds=$secs; LogicalCPUs=$cores
  TotalCpuPct=[math]::Min(100,[math]::Round(($rows | measure CpuPct -Sum).Sum,1))
  MemTotalGB=[math]::Round($os.TotalVisibleMemorySize/1MB,1)
  MemUsedPct=[math]::Round(100-100*$os.FreePhysicalMemory/$os.TotalVisibleMemorySize,1)
  ProcessCount=$rows.Count
  TopCpu=$(if ('__B__' -ne 'memory') { @($rows | sort CpuPct -desc | select -first $n | % { Enrich $_ }) } else { $null })
  TopMemory=$(if ('__B__' -ne 'cpu') { @($rows | sort PrivateMB -desc | select -first $n | % { Enrich $_ }) } else { $null })
} | ConvertTo-Json -Depth 4 -Compress
""".replace("__N__", str(max(1, min(int(top), 30)))).replace("__S__", str(secs)).replace("__B__", by), timeout=secs + 120)
    if isinstance(res, dict):
        for k in ("TopCpu", "TopMemory"):
            if res.get(k) is None:
                res.pop(k, None)   # lista não pedida: não aparece
    return res


@mcp.tool
def get_nic_teaming(host: str):
    """Configuração DETALHADA de NIC Teaming: LBFO (modo, algoritmo de balanceamento, membros ativos/standby,
    status e motivo de falha por membro, velocidade, team NICs/VLANs) e SET - Switch Embedded Teaming do
    Hyper-V (membros, algoritmo, vNICs de host e VLANs). Gera alertas de membro caído, velocidades
    diferentes e team degradado."""
    d = _ps(host, r"""
$lbfo = @(try { foreach ($t in @(Get-NetLbfoTeam -ErrorAction Stop)) {
  [pscustomobject]@{
    Name=$t.Name; Status="$($t.Status)"; TeamingMode="$($t.TeamingMode)"; LoadBalancing="$($t.LoadBalancingAlgorithm)"
    LacpTimer="$($t.LacpTimer)"
    Members=@(Get-NetLbfoTeamMember -Team $t.Name -ErrorAction SilentlyContinue | % { [pscustomobject]@{
      Name=$_.Name; Description=$_.InterfaceDescription; AdministrativeMode="$($_.AdministrativeMode)"
      OperationalStatus="$($_.OperationalStatus)"; FailureReason="$($_.FailureReason)"
      LinkSpeedGbps=[math]::Round($_.TransmitLinkSpeed/1e9,2) } })
    TeamNics=@(Get-NetLbfoTeamNic -Team $t.Name -ErrorAction SilentlyContinue | % { [pscustomobject]@{
      Name=$_.Name; VlanID=$_.VlanID; Primary=$_.Primary; Default=$_.Default } })
  } } } catch { })
$set = @(try { foreach ($s in @(Get-VMSwitch -ErrorAction Stop | ? EmbeddedTeamingEnabled)) {
  $tm = Get-VMSwitchTeam -Name $s.Name -ErrorAction SilentlyContinue
  [pscustomobject]@{
    Name=$s.Name; SwitchType="$($s.SwitchType)"; AllowManagementOS=$s.AllowManagementOS
    TeamingMode="$($tm.TeamingMode)"; LoadBalancing="$($tm.LoadBalancingAlgorithm)"
    Members=@($tm.NetAdapterInterfaceDescription | % { $d = $_; $a = Get-NetAdapter -InterfaceDescription $d -ErrorAction SilentlyContinue
      [pscustomobject]@{ Description=$d; Name=$a.Name; Status="$($a.Status)"; LinkSpeed=$a.LinkSpeed } })
    HostVNics=@(Get-VMNetworkAdapter -ManagementOS -SwitchName $s.Name -ErrorAction SilentlyContinue | % {
      $v = Get-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName $_.Name -ErrorAction SilentlyContinue
      [pscustomobject]@{ Name=$_.Name; Mac=$_.MacAddress; VlanMode="$($v.OperationMode)"; VlanID=$v.AccessVlanId } })
  } } } catch { })
[pscustomobject]@{ Host=$env:COMPUTERNAME; Lbfo=$lbfo; Set=$set } | ConvertTo-Json -Depth 6 -Compress
""", timeout=120)
    if not isinstance(d, dict) or "Host" not in d:
        return d
    alerts = []
    for t in _lst(d.get("Lbfo")):
        if t.get("Status") != "Up":
            alerts.append(f"Team LBFO '{t['Name']}' com status {t.get('Status')}.")
        mem = _lst(t.get("Members"))
        for m in mem:
            if m.get("OperationalStatus") != "Active" and m.get("AdministrativeMode") != "Standby":
                alerts.append(f"Team '{t['Name']}': membro {m['Name']} {m.get('OperationalStatus')} "
                              f"(motivo: {m.get('FailureReason')}).")
            if m.get("AdministrativeMode") == "Standby":
                alerts.append(f"Team '{t['Name']}': membro {m['Name']} em Standby.")
        speeds = {m.get("LinkSpeedGbps") for m in mem}
        if len(speeds) > 1:
            alerts.append(f"Team '{t['Name']}': membros com velocidades diferentes {sorted(speeds)} Gbps.")
        if len(mem) < 2:
            alerts.append(f"Team '{t['Name']}' com {len(mem)} membro(s).")
    for s in _lst(d.get("Set")):
        mem = _lst(s.get("Members"))
        for m in mem:
            if m.get("Status") != "Up":
                alerts.append(f"SET '{s['Name']}': membro {m.get('Name') or m['Description']} {m.get('Status')}.")
        if len({m.get("LinkSpeed") for m in mem}) > 1:
            alerts.append(f"SET '{s['Name']}': membros com velocidades diferentes.")
        if len(mem) < 2:
            alerts.append(f"SET '{s['Name']}' com {len(mem)} membro(s).")
    d["Configured"] = bool(_lst(d.get("Lbfo")) or _lst(d.get("Set")))
    d["Alerts"] = alerts or (["Nenhum sinal encontrado."] if d["Configured"] else
                             ["Nenhum NIC Teaming (LBFO/SET) configurado neste servidor."])
    return d


@mcp.tool
def get_time_config(host: str):
    """Configuração completa de NTP/tempo (w32time): tipo de sincronização (NT5DS=hierarquia do domínio, NTP=
    servidores manuais), servidores NTP configurados, intervalos, fonte atual, stratum, último sync, peers,
    se é o PDC/servidor de tempo confiável, provedor de tempo do Hyper-V (VMICTimeProvider), o OFFSET medido
    contra a fonte e o RELÓGIO do servidor (fuso, deslocamento UTC, hora local e UTC lidas no próprio servidor, em 'Clock'). Só fatos e sinais com limiar à vista; interpretação é do RAG (microsoft-docs)."""
    d = _ps(host, r"""
$ErrorActionPreference='Continue'
$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time'
$p = Get-ItemProperty "$base\Parameters" -ErrorAction SilentlyContinue
$c = Get-ItemProperty "$base\Config" -ErrorAction SilentlyContinue
$ntpc = Get-ItemProperty "$base\TimeProviders\NtpClient" -ErrorAction SilentlyContinue
$ntps = Get-ItemProperty "$base\TimeProviders\NtpServer" -ErrorAction SilentlyContinue
$vmic = Get-ItemProperty "$base\TimeProviders\VMICTimeProvider" -ErrorAction SilentlyContinue
$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters' -ErrorAction SilentlyContinue
$src = ((& w32tm /query /source 2>$null) | Out-String).Trim()
$status = ((& w32tm /query /status 2>$null) | Out-String).Trim()
$peers = ((& w32tm /query /peers 2>$null) | Out-String).Trim()
$target = ($src -replace ',0x\w+$','').Trim()
$off = $null
if ($target -and $target -notmatch 'CMOS|Free-running|VM IC') {
  $sc = (& w32tm /stripchart /computer:$target /samples:3 /dataonly 2>$null) | ? { $_ -match '[+-]\d+\.\d+s' }
  $vals = @($sc | % { if ($_ -match '([+-]\d+\.\d+)s') { [double]$matches[1] } })
  if ($vals.Count) { $off = [math]::Round(($vals | measure -Average).Average, 4) }
}
$svc = Get-Service W32Time -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem
[pscustomobject]@{
  Host=$env:COMPUTERNAME; DomainRole=$cs.DomainRole; PartOfDomain=$cs.PartOfDomain
  ServiceStatus="$($svc.Status)"; ServiceStartType="$($svc.StartType)"
  Type=$p.Type; NtpServer=$p.NtpServer; PolicyType=$pol.Type; PolicyNtpServer=$pol.NtpServer
  SpecialPollIntervalSec=$ntpc.SpecialPollInterval; NtpClientEnabled=$ntpc.Enabled
  NtpServerEnabled=$ntps.Enabled; AnnounceFlags=$c.AnnounceFlags
  MaxPosPhaseCorrection=$c.MaxPosPhaseCorrection; MaxNegPhaseCorrection=$c.MaxNegPhaseCorrection
  VMICTimeProviderEnabled=$vmic.Enabled
  CurrentSource=$src; OffsetSeconds=$off; Status=$status; Peers=$peers; Clock=__CLOCK__
} | ConvertTo-Json -Depth 3 -Compress
""".replace("__CLOCK__", PS_CLOCK), timeout=120)
    if not isinstance(d, dict) or "Host" not in d:
        return d
    st = d.get("Status") or ""
    m = re.search(r"Stratum:\s*(\d+)", st)
    d["Stratum"] = int(m.group(1)) if m else None
    m = re.search(r"Last Successful Sync Time:\s*(.+)", st) or re.search(r"Hora da .ltima sincroniza.+?:\s*(.+)", st)
    d["LastSuccessfulSync"] = m.group(1).strip() if m else None
    role = d.get("DomainRole")
    d["DomainRoleText"] = {0: "Estação standalone", 1: "Estação membro", 2: "Servidor standalone",
                           3: "Servidor membro", 4: "DC (backup)", 5: "DC (PDC emulator)"}.get(role, role)
    src, typ, off = (d.get("CurrentSource") or ""), (d.get("PolicyType") or d.get("Type") or ""), d.get("OffsetSeconds")
    status, findings = SEM, []
    if re.search(r"Local CMOS|Free-running", src, re.I):
        status = SIG
        findings.append(f"Fonte de tempo atual: relógio local ({src}).")
    if off is None and not re.search(r"Local CMOS|Free-running|VM IC", src, re.I):
        status = _worst(status, INC)
        findings.append(f"Não foi possível medir o offset contra '{src}' (fonte inacessível ou não resolvível agora).")
    if off is not None and abs(off) >= 1:
        status = _worst(status, SIG)
        findings.append(f"Offset de {off}s em relação à fonte (limiar do projeto: 1 s).")
    if d.get("ServiceStatus") != "Running":
        status = _worst(status, SIG)
        findings.append(f"Serviço W32Time {d.get('ServiceStatus')}.")
    d["status"], d["findings"] = status, findings or ["Nenhum sinal encontrado."]
    return d


KEY_ROLES = {
    "AD-Domain-Services": ["NTDS", "Netlogon", "KDC", "DFSR"],
    "DNS": ["DNS"], "DHCP": ["DHCPServer"], "Web-Server": ["W3SVC", "WAS"],
    "Hyper-V": ["vmms", "vmcompute"], "Failover-Clustering": ["ClusSvc"],
    "FS-DFS-Namespace": ["Dfs"], "FS-DFS-Replication": ["DFSR"],
    "RDS-RD-Server": ["TermService"], "RDS-Licensing": ["TermServLicensing"],
    "Print-Services": ["Spooler"], "UpdateServices": ["WsusService"], "ADCS-Cert-Authority": ["CertSvc"],
    "NPAS": ["IAS"], "Windows-Server-Backup": ["wbengine"],
}


@mcp.tool
def get_server_roles(host: str):
    """Roles instaladas no Windows Server em hierarquia (Role → Role Services), lista de Features instaladas e
    estado dos serviços das roles principais (AD DS, DNS, DHCP, IIS, Hyper-V, Cluster, DFS, RDS, WSUS, AD CS...).
    Requer admin local."""
    d = _ps(host, r"""
$f = @(Get-WindowsFeature -ErrorAction Stop | ? Installed)
$names = @(__SVCS__)
[pscustomobject]@{
  Host=$env:COMPUTERNAME; OS=(Get-CimInstance Win32_OperatingSystem).Caption
  Installed=@($f | select Name,DisplayName,@{n='Type';e={"$($_.FeatureType)"}},Parent,Depth)
  Services=@(Get-Service -Name $names -ErrorAction SilentlyContinue | select Name,DisplayName,@{n='Status';e={"$($_.Status)"}},@{n='StartType';e={"$($_.StartType)"}})
} | ConvertTo-Json -Depth 4 -Compress
""".replace("__SVCS__", ",".join(f"'{s}'" for s in sorted({x for v in KEY_ROLES.values() for x in v}))), timeout=120)
    if not isinstance(d, dict) or "Installed" not in d:
        return d
    items = _lst(d["Installed"])
    by_name = {i["Name"]: i for i in items}
    svc = {s["Name"].lower(): s for s in _lst(d.get("Services"))}

    def top_role(i):
        while i.get("Parent") and i["Parent"] in by_name:
            i = by_name[i["Parent"]]
        return i

    roles = {}
    for i in items:
        if i["Type"] == "Role" and not i.get("Parent"):
            roles.setdefault(i["Name"], {"name": i["Name"], "display": i["DisplayName"], "role_services": []})
    for i in items:
        if i["Type"] == "Role Service":
            r = top_role(i)
            roles.setdefault(r["Name"], {"name": r["Name"], "display": r["DisplayName"], "role_services": []})
            roles[r["Name"]]["role_services"].append(i["DisplayName"])
    alerts = []
    for name, svcs in KEY_ROLES.items():
        if name in by_name:
            st = [svc.get(s.lower()) for s in svcs]
            for r in roles.values():
                if r["name"] == name or name in (by_name[name].get("Parent") or ""):
                    r["services"] = [s for s in st if s]
            for s in st:
                if s and s["Status"] != "Running" and s["StartType"] != "Disabled":
                    alerts.append(f"Role {name}: serviço {s['Name']} está {s['Status']}.")
    for name, svcs in KEY_ROLES.items():
        if name in by_name and name not in roles:
            roles[name] = {"name": name, "display": by_name[name]["DisplayName"], "role_services": [],
                           "services": [svc[s.lower()] for s in svcs if s.lower() in svc]}
    features = [i["DisplayName"] for i in items if i["Type"] == "Feature" and not i.get("Parent")]
    return {"host": d["Host"], "os": d.get("OS"), "roles_count": len(roles),
            "roles": sorted(roles.values(), key=lambda r: r["display"]),
            "features": sorted(features), "alerts": alerts or ["Serviços das roles principais em execução."]}


# ---------- failover cluster ----------
@mcp.tool
def get_cluster_health(host: str, days: int = 1):
    """Failover Cluster (se existir): configuração detalhada e saúde. Cluster (nome, domínio, versão funcional),
    quorum/witness, nós (estado, voto, peso dinâmico), roles/grupos (dono, estado, nós preferidos), recursos com
    falha, redes do cluster e interfaces, Cluster Shared Volumes (estado, dono, espaço livre, modo redirecionado),
    pool S2D quando houver e eventos de erro/crítico do FailoverClustering no último dia (days ampliável até 90)."""
    d = _ps_long(host, r"""
if (-not (Get-Service ClusSvc -ErrorAction SilentlyContinue)) { [pscustomobject]@{ Clustered=$false; Reason='Serviço ClusSvc não existe (feature Failover-Clustering não instalada).' } | ConvertTo-Json -Compress; exit 0 }
try { Import-Module FailoverClusters -ErrorAction Stop; $cl = Get-Cluster -ErrorAction Stop }
catch { [pscustomobject]@{ Clustered=$false; Reason="Não é membro de cluster ou módulo indisponível: $($_.Exception.Message)" } | ConvertTo-Json -Compress; exit 0 }
$q = Get-ClusterQuorum -ErrorAction SilentlyContinue
$since = (Get-Date).AddDays(-__H__)
[pscustomobject]@{
  Clustered=$true
  Cluster=[pscustomobject]@{ Name=$cl.Name; Domain=$cl.Domain; FunctionalLevel=$cl.ClusterFunctionalLevel
    S2DEnabled=$cl.S2DEnabled; DynamicQuorum=$cl.DynamicQuorum; SameSubnetThreshold=$cl.SameSubnetThreshold
    CrossSubnetThreshold=$cl.CrossSubnetThreshold }
  Quorum=[pscustomobject]@{ Type="$($q.QuorumType)"; Resource="$($q.QuorumResource)"
    WitnessState="$(if ($q.QuorumResource) { (Get-ClusterResource -Name $q.QuorumResource.Name -ErrorAction SilentlyContinue).State })" }
  Nodes=@(Get-ClusterNode | % { [pscustomobject]@{ Name=$_.Name; State="$($_.State)"; StatusInfo="$($_.StatusInformation)"
    NodeWeight=$_.NodeWeight; DynamicWeight=$_.DynamicWeight; Site=$_.FaultDomain } })
  Groups=@(Get-ClusterGroup | % { [pscustomobject]@{ Name=$_.Name; State="$($_.State)"; OwnerNode="$($_.OwnerNode)"
    GroupType="$($_.GroupType)"; Priority=$_.Priority
    PreferredOwners=(@(Get-ClusterOwnerNode -Group $_.Name -ErrorAction SilentlyContinue | % { $_.OwnerNodes.Name }) -join ',') } })
  ResourceCount=@(Get-ClusterResource).Count
  ResourcesNotOnline=@(Get-ClusterResource | ? { "$($_.State)" -ne 'Online' } | % { [pscustomobject]@{
    Name=$_.Name; Type=$_.ResourceType.Name; Group="$($_.OwnerGroup)"; State="$($_.State)"; Owner="$($_.OwnerNode)" } })
  Networks=@(Get-ClusterNetwork | % { [pscustomobject]@{ Name=$_.Name; Role="$($_.Role)"; State="$($_.State)"
    Address="$($_.Address)/$($_.AddressMask)"; Metric=$_.Metric } })
  NetInterfacesNotUp=@(Get-ClusterNetworkInterface | ? { "$($_.State)" -ne 'Up' } | % { [pscustomobject]@{
    Name=$_.Name; Node="$($_.Node)"; Network="$($_.Network)"; State="$($_.State)" } })
  CSVs=@(Get-ClusterSharedVolume -ErrorAction SilentlyContinue | % { $i = $_.SharedVolumeInfo | select -first 1
    $st = Get-ClusterSharedVolumeState -Name $_.Name -ErrorAction SilentlyContinue | select -first 1
    [pscustomobject]@{ Name=$_.Name; State="$($_.State)"; Owner="$($_.OwnerNode)"; Path=$i.FriendlyVolumeName
      SizeGB=[math]::Round($i.Partition.Size/1GB,1); FreeGB=[math]::Round($i.Partition.FreeSpace/1GB,1)
      FreePct=[math]::Round($i.Partition.PercentFree,1); Redirected="$($st.StateInfo)"; RedirectReason="$($st.FileSystemRedirectedIOReason)" } })
  StoragePools=@(try { Get-StoragePool -IsPrimordial $false -ErrorAction Stop | % { [pscustomobject]@{ Name=$_.FriendlyName
    Health="$($_.HealthStatus)"; Operational="$($_.OperationalStatus)"; SizeTB=[math]::Round($_.Size/1TB,2)
    AllocatedTB=[math]::Round($_.AllocatedSize/1TB,2) } } } catch { })
  RecentProblems=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-FailoverClustering';Level=1,2,3;StartTime=$since} -MaxEvents 30 -ErrorAction SilentlyContinue |
    select TimeCreated,Id,@{n='Message';e={Msg $_.Message 400}})
} | ConvertTo-Json -Depth 5 -Compress
""".replace("__H__", str(_days(days))), timeout=180)
    if not isinstance(d, dict) or not d.get("Clustered"):
        return d
    status, findings = SEM, []
    for n in _lst(d.get("Nodes")):
        if n.get("State") != "Up":
            status = _worst(status, SIG)
            findings.append(f"Nó {n['Name']} está {n['State']} {n.get('StatusInfo') or ''}".strip())
    q = d.get("Quorum") or {}
    if q.get("Resource") and q.get("WitnessState") not in ("Online", ""):
        status = _worst(status, SIG)
        findings.append(f"Witness '{q['Resource']}' está {q.get('WitnessState')}.")
    if q.get("Type") == "NodeMajority" and len(_lst(d.get("Nodes"))) % 2 == 0:
        status = _worst(status, SIG)
        findings.append(f"Quorum NodeMajority com {len(_lst(d.get('Nodes')))} nós (número par) e sem witness configurado.")
    for g in _lst(d.get("Groups")):
        if g.get("State") not in ("Online",) and g.get("GroupType") != "AvailableStorage":
            status = _worst(status, SIG)
            findings.append(f"Role '{g['Name']}' {g['State']} (dono {g.get('OwnerNode')}).")
    for r in _lst(d.get("ResourcesNotOnline")):
        if r.get("State") == "Failed":
            status = _worst(status, SIG)
            findings.append(f"Recurso '{r['Name']}' ({r['Type']}) FAILED no grupo {r['Group']}.")
    for n in _lst(d.get("Networks")):
        if n.get("State") != "Up":
            status = _worst(status, SIG)
            findings.append(f"Rede do cluster '{n['Name']}' {n['State']}.")
    for i in _lst(d.get("NetInterfacesNotUp")):
        status = _worst(status, SIG)
        findings.append(f"Interface {i['Name']} ({i['Node']}) {i['State']}.")
    for c in _lst(d.get("CSVs")):
        if c.get("State") != "Online":
            status = _worst(status, SIG)
            findings.append(f"CSV {c['Name']} {c['State']}.")
        if c.get("FreePct") is not None and c["FreePct"] < 10:
            status = _worst(status, SIG)
            findings.append(f"CSV {c['Name']} com {c['FreePct']}% livre (limiar do projeto: 10%).")
        if "Redirected" in (c.get("Redirected") or ""):
            status = _worst(status, SIG)
            findings.append(f"CSV {c['Name']} em I/O redirecionado ({c.get('RedirectReason')}).")
    for p in _lst(d.get("StoragePools")):
        if p.get("Health") != "Healthy":
            status = _worst(status, SIG)
            findings.append(f"Pool {p['Name']} HealthStatus={p['Health']} ({p['Operational']}).")
    if _lst(d.get("RecentProblems")):
        status = _worst(status, SIG)
        findings.append(f"{len(_lst(d['RecentProblems']))} evento(s) de problema do FailoverClustering em {_days(days)} dia(s).")
    d["status"], d["findings"] = status, findings or ["Nenhum sinal encontrado."]
    return d


# ---------- tarefas agendadas ----------
TASK_OK = {0, 0x41300, 0x41301, 0x41303, 0x41325}  # sucesso, pronta, executando, nunca executou, enfileirada


TASK_NAME_RE = re.compile(r"^[A-Za-z0-9 _*?.-]{1,100}$")


@mcp.tool
def get_scheduled_tasks(host: str, only_failed: bool = True, include_microsoft: bool = False, name_filter: str | None = None):
    """Tarefas agendadas com estado, última/próxima execução, resultado (hex) e conta de execução.
    only_failed=True devolve só as que falharam na última execução. Por padrão ignora \\Microsoft\\*.
    name_filter (wildcard no nome da tarefa, ex.: '*backup*') limita às tarefas que casam."""
    if name_filter is not None and not TASK_NAME_RE.match(name_filter):
        raise ValueError("name_filter inválido (letras, números, espaço, '*', '?', '.', '-' e '_')")
    rows = _ps(host, r"""
$t = Get-ScheduledTask -ErrorAction SilentlyContinue
if (-not __MS__) { $t = $t | ? { $_.TaskPath -notlike '\Microsoft\*' } }
if ('__NF__') { $t = $t | ? { $_.TaskName -like '__NF__' } }
@(foreach ($x in $t) {
  $i = $x | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
  [pscustomobject]@{
    Path=$x.TaskPath; Name=$x.TaskName; State=$x.State.ToString(); RunAs=$x.Principal.UserId
    LastRun=$i.LastRunTime; LastResult=$i.LastTaskResult; NextRun=$i.NextRunTime; MissedRuns=$i.NumberOfMissedRuns
    Action=(@($x.Actions | % { ("$($_.Execute) $($_.Arguments)").Trim() }) -join ' | ')
  }
}) | ConvertTo-Json -Compress
""".replace("__MS__", "$true" if include_microsoft else "$false").replace("__NF__", name_filter or ""), timeout=180)
    if isinstance(rows, dict) and "error" in rows:
        return rows
    out = []
    for r in _lst(rows):
        res = r.get("LastResult")
        if isinstance(res, int):
            res &= 0xFFFFFFFF
            r["LastResultHex"] = f"0x{res:08X}"
        never = not r.get("LastRun") or str(r["LastRun"]).startswith("1999")
        r["Failed"] = isinstance(res, int) and res not in TASK_OK and not never
        if not only_failed or r["Failed"]:
            out.append(r)
    return {"total_tasks": len(_lst(rows)), "returned": len(out), "tasks": out}


# ---------- sessões e usuários ----------
QUSER_RE = re.compile(r"^>?(?P<user>\S+)\s+(?:(?P<session>\S+)\s+)?(?P<id>\d+)\s+(?P<state>\S+)\s+(?P<idle>\S+)\s+(?P<logon>.+?)\s*$")


@mcp.tool
def get_user_sessions(host: str):
    """Usuários logados e sessões RDP/console (quser): usuário, sessão, ID, estado, ociosidade e horário de logon.
    Sessões desconectadas há muito tempo prendem memória e licenças RDS."""
    raw = _ps(host, r"""
$ErrorActionPreference='Continue'
$o = (& quser.exe 2>$null | Out-String)
[pscustomobject]@{ Raw=$o } | ConvertTo-Json -Compress
""")
    if not isinstance(raw, dict) or "Raw" not in raw:
        return raw
    lines = [ln for ln in (raw["Raw"] or "").splitlines() if ln.strip()]
    sessions = []
    for ln in lines[1:]:  # 1a linha = cabeçalho (localizado)
        m = QUSER_RE.match(ln.strip())
        if m:
            d = m.groupdict()
            d["current"] = ln.lstrip().startswith(">")
            sessions.append(d)
    return {"count": len(sessions), "sessions": sessions}


@mcp.tool
def get_local_admins(host: str):
    """Membros do grupo local Administradores (via SID S-1-5-32-544, independe do idioma)."""
    return _ps(host, r"""
try {
  @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
    select Name,@{n='ObjectClass';e={"$($_.ObjectClass)"}},@{n='Source';e={"$($_.PrincipalSource)"}},@{n='SID';e={"$($_.SID)"}}) |
    ConvertTo-Json -Compress
} catch {
  $n = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
  $g = [ADSI]"WinNT://$env:COMPUTERNAME/$n,group"
  @($g.Invoke('Members') | % {
    [pscustomobject]@{
      Name=((($_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null)) -replace '^WinNT://','').Split('/') | select -last 2) -join '\'
      ObjectClass=$_.GetType().InvokeMember('Class','GetProperty',$null,$_,$null); Source='ADSI'; SID=$null }
  }) | ConvertTo-Json -Compress
}
""")


# O coletor devolve só FATOS: o SID e, em SID de domínio (S-1-5-21-...), o RID numérico. O SIGNIFICADO de um RID (ex.: 512)
# e o que cada grupo 'pode fazer' são interpretação e ficam no RAG (microsoft-docs), com fonte. Nenhuma tabela de rótulos aqui.


def _member_source(sid: str, is_local: bool) -> str:
    """Origem do membro pelo SID: conta local, grupo interno, principal do sistema (NT AUTHORITY, Everyone...),
    domínio (S-1-5-21-...) ou Azure AD (S-1-12-1-...). Antes tudo que não era local virava 'Domínio/Externo'."""
    if is_local:
        return "Local"
    if sid.startswith("S-1-12-1-"):
        return "Azure AD"
    if sid.startswith("S-1-5-21-"):
        return "Domínio"
    if sid.startswith("S-1-5-32-"):
        return "Interno (BUILTIN)"
    if re.fullmatch(r"S-1-(1-0|2-\d+|3-\d+|5-\d{1,2}|5-(80|82|83|90|96)-[\d-]+)", sid):
        return "Sistema (NT AUTHORITY)"
    return "Externo"


@mcp.tool
def get_local_groups(host: str, group: str | None = None, include_users: bool | None = None):
    """TODOS os grupos locais e seus membros (independe do idioma: usa SID). Para cada grupo: nome, SID, descrição,
    se é grupo interno, e membros com tipo (usuário/grupo), origem (local/domínio/AzureAD), SID, e, para contas
    locais, estado (habilitada, último logon, senha alterada em, senha nunca expira). Resolve SIDs de domínio
    mesmo com o DC inacessível (Get-LocalGroupMember falha com erro 1789 nesse caso) e devolve o RID numérico (último componente) dos SIDs S-1-5-21-...
    de domínio (o significado do RID é do RAG). Inclui 'signals' (só fatos): SIDs não resolvidos, principais de domínio/Azure AD no grupo
    Administradores, contas locais habilitadas com senha que nunca expira, contas desabilitadas como membros e
    quantidade de grupos vazios. Não classifica nada como 'privilegiado' nem recomenda: isso é do RAG (microsoft-docs).
    'group' filtra por nome; include_users omite/inclui a lista de contas locais (padrão: omitida quando 'group' é
    informado, incluída na listagem de todos os grupos).
    Em controlador de domínio não há grupos locais (use as ferramentas de AD)."""
    if group is not None and not NAME_RE.match(group):
        raise ValueError("group inválido")
    if include_users is None:
        include_users = group is None
    res = _ps(host, r"""
$ErrorActionPreference = 'Continue'
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { [pscustomobject]@{ IsDomainController=$true } | ConvertTo-Json -Compress; return }
$flt = '__G__'
$lu = @{}; foreach ($u in @(Get-LocalUser -ErrorAction SilentlyContinue)) { $lu["$($u.SID)"] = $u }
function Rs($sid) { try { (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { $null } }
$groups = foreach ($g in @(Get-LocalGroup -ErrorAction SilentlyContinue | ? { -not $flt -or $_.Name -eq $flt })) {
  $ads = [ADSI]"WinNT://./$($g.Name),group"
  $mem = foreach ($o in @(try { $ads.Invoke('Members') } catch {})) {
    $t = $o.GetType(); $sid = $null
    try { $sid = (New-Object Security.Principal.SecurityIdentifier($t.InvokeMember('objectSid','GetProperty',$null,$o,$null), 0)).Value } catch {}
    $path = "$($t.InvokeMember('ADsPath','GetProperty',$null,$o,$null))" -replace '^WinNT://', ''
    $cls = "$($t.InvokeMember('Class','GetProperty',$null,$o,$null))"
    $name = if ($sid) { Rs $sid } else { $null }; if (-not $name) { $name = $path -replace '/', '\' }
    $u = if ($sid) { $lu[$sid] } else { $null }
    $local = [bool]$u -or ($sid -and $sid -match '^S-1-5-32-') -or ($path -like "$env:COMPUTERNAME/*")
    $unres = [bool]($sid -and -not (Rs $sid))
    [pscustomobject]@{ Name=$name; SID=$sid; Class=$cls; Local=$local; Unresolved=$unres
      Enabled=$(if ($u) { $u.Enabled } else { $null }); LastLogon=$(if ($u) { $u.LastLogon } else { $null })
      PasswordLastSet=$(if ($u) { $u.PasswordLastSet } else { $null })
      PasswordNeverExpires=$(if ($u) { [bool]($u.PasswordNeverExpires -or -not $u.PasswordExpires) } else { $null }) }
  }
  [pscustomobject]@{ Name=$g.Name; SID="$($g.SID)"; Description=$g.Description; BuiltIn=("$($g.SID)" -like 'S-1-5-32-*')
    Members=@($mem) }
}
$users = if (__U__) { @($lu.Values | sort Name | % { [pscustomobject]@{ Name=$_.Name; SID="$($_.SID)"; Enabled=$_.Enabled
  LastLogon=$_.LastLogon; PasswordLastSet=$_.PasswordLastSet; PasswordExpires=$_.PasswordExpires
  PasswordNeverExpires=[bool](-not $_.PasswordExpires); AccountExpires=$_.AccountExpires; Description=$_.Description } }) } else { @() }
[pscustomobject]@{ Computer=$env:COMPUTERNAME; Groups=@($groups); Users=$users } | ConvertTo-Json -Depth 5 -Compress
""".replace("__G__", group or "").replace("__U__", "$true" if include_users else "$false"), timeout=120)
    if not isinstance(res, dict) or "Groups" not in res:
        if isinstance(res, dict) and res.get("IsDomainController"):
            return {"host": host, "error": "Controlador de domínio: não há grupos locais. Use ferramentas de AD."}
        return res
    groups = _lst(res.get("Groups"))
    empty, unresolved, domain_in_admins, never_expires, disabled = [], [], [], [], []
    for g in groups:
        members = _lst(g.get("Members"))
        g["Members"] = members
        g["MemberCount"] = len(members)
        for m in members:
            sid = m.get("SID") or ""
            rid = sid.rsplit("-", 1)[-1] if sid.startswith("S-1-5-21-") else None
            m["Rid"] = int(rid) if rid and rid.isdigit() else None
            m["Source"] = _member_source(sid, bool(m.get("Local")))
            ref = {"group": g["Name"], "member": m.get("Name")}
            if m.get("Unresolved"):
                unresolved.append({**ref, "sid": sid, "rid": m["Rid"]})
            if g.get("SID") == "S-1-5-32-544" and m["Source"] in ("Domínio", "Azure AD"):
                domain_in_admins.append({**ref, "source": m["Source"], "sid": sid, "rid": m["Rid"]})
            if m.get("Enabled") is True and m.get("PasswordNeverExpires"):
                never_expires.append(ref)
            if m.get("Enabled") is False:
                disabled.append(ref)
        if not members:
            empty.append(g["Name"])
    return {"host": host, "computer": res.get("Computer"), "group_count": len(groups),
            "groups": [g for g in groups if g["Members"] or group],
            "empty_groups": empty, "local_users": _lst(res.get("Users")),
            "signals": {"unresolvedSids": unresolved, "domainPrincipalsInLocalAdministrators": domain_in_admins,
                        "enabledLocalAccountsPasswordNeverExpires": never_expires, "disabledAccountsAsMembers": disabled,
                        "emptyGroupCount": len(empty)}}


LOGON_SUBSTATUS = {
    "0xc000006a": "Senha incorreta",
    "0xc0000064": "Usuário não existe",
    "0xc0000234": "Conta bloqueada",
    "0xc0000072": "Conta desabilitada",
    "0xc000006f": "Fora do horário permitido",
    "0xc0000070": "Estação de trabalho não permitida",
    "0xc0000071": "Senha expirada",
    "0xc0000193": "Conta expirada",
    "0xc0000224": "Troca de senha obrigatória",
    "0xc000015b": "Tipo de logon não concedido",
    "0xc000006d": "Usuário ou credencial inválidos",
    "0xc000005e": "Nenhum servidor de logon disponível (DC inacessível)",
    "0xc0000133": "Relógio fora de sincronia com o DC",
    "0xc000018d": "Falha na relação de confiança",
    "0xc0000192": "Serviço Netlogon não iniciado",
    "0xc0000413": "Firewall de autenticação bloqueou o logon",
}


@mcp.tool
def get_failed_logons(host: str, days: int = 1, top: int = 25):
    """Logons com falha (evento 4625 do log Security) agrupados por conta + IP de origem, com tipo de logon e
    motivo (SubStatus traduzido). Detecta força bruta, contas de serviço com senha antiga e bloqueios.
    Requer permissão de leitura no log Security (admin local ou equivalente)."""
    res = _ps(host, PS_EV + r"""
$ev = @(Ev 'Security' '__XP__' __CAP__)
# Campos do 4625 por posição (schema fixo): 5=TargetUserName 6=TargetDomainName 7=Status 9=SubStatus
# 10=LogonType 13=WorkstationName 18=ProcessName 19=IpAddress. Bem mais rápido que ToXml() por evento.
$rows = foreach ($e in $ev) {
  $p = $e.Properties; $st = '0x{0:x}' -f $p[7].Value; $ss = '0x{0:x}' -f $p[9].Value
  [pscustomobject]@{ Time=$e.TimeCreated; Account="$($p[6].Value)\$($p[5].Value)"; SourceIp="$($p[19].Value)"
    Workstation="$($p[13].Value)"; LogonType="$($p[10].Value)"; SubStatus=$(if ($ss -eq '0x0') { $st } else { $ss }); Process="$($p[18].Value)" }
}
[pscustomobject]@{
  TotalEvents=$ev.Count; Truncated=($ev.Count -ge __CAP__); OldestRead=$(if ($ev.Count) { $ev[-1].TimeCreated })
  Groups=@($rows | group Account,SourceIp | sort Count -desc | select -first __T__ | % {
    $g=$_.Group | sort Time
    [pscustomobject]@{ Count=$_.Count; Account=$g[0].Account; SourceIp=$g[0].SourceIp; Workstation=$g[0].Workstation
      LogonTypes=(@($g.LogonType | select -unique) -join ','); SubStatus=@($g.SubStatus | select -unique)
      Process=$g[-1].Process; First=$g[0].Time; Last=$g[-1].Time } })
} | ConvertTo-Json -Depth 4 -Compress
""".replace("__XP__", _xpath(ids=[4625], days=_days(days))).replace("__T__", str(max(1, min(int(top), 100))))
       .replace("__CAP__", str(LOGON_CAP)), timeout=180)
    if isinstance(res, dict):
        for g in _lst(res.get("Groups")):
            g["Reasons"] = [LOGON_SUBSTATUS.get(s, s) for s in _lst(g.get("SubStatus"))]
        if res.get("Truncated"):
            res["Note"] = (f"Mais de {LOGON_CAP} falhas no período (limite de leitura): foram lidas só as mais "
                           "recentes. TotalEvents e Count são LIMITE INFERIOR e 'First' pode ser posterior ao início "
                           "real (veja OldestRead). Reduza 'days' para ver o período completo.")
    return res


# ---------- registro e variáveis de ambiente (somente leitura) ----------
# Princípio: o coletor lê, não interpreta. Valores cujo NOME sugere segredo não são lidos (voltam como '<mascarado>').
SECRET_NAME_RE = (r"pass(word|wd|phrase)?|pwd|secret|token|credential|api[_-]?key|private[_-]?key|access[_-]?key|"
                  r"shared[_-]?key|connection[_-]?string")
REG_PATH_RE = re.compile(r"^HKLM:\\[A-Za-z0-9 ._,(){}\\-]{1,400}$")
REG_DENY_RE = re.compile(r"^HKLM:\\(SAM|SECURITY)(\\|$)", re.I)
REG_MAX_VALUES = 200
REG_MAX_SUBKEYS = 100
ENV_SPLIT_VARS = {"path", "psmodulepath", "pathext"}


def is_secret_name(name: str) -> bool:
    return re.search(SECRET_NAME_RE, name or "", re.I) is not None


def _reg_path(path: str) -> str:
    r"""Valida o caminho do registro: só HKLM:\..., sem curingas, aspas ou '..', e nunca SAM/SECURITY."""
    p = (path or "").strip().rstrip("\\")
    if not REG_PATH_RE.match(p) or ".." in p.split("\\") or REG_DENY_RE.match(p):
        raise ValueError(r"Caminho do registro inválido: use HKLM:\SOFTWARE\... (não são permitidos HKCU/HKU, SAM, SECURITY, curingas ou '..')")
    return p


def _env_entries(var: dict) -> dict:
    """Separa por ';' as variáveis que são listas (Path etc.): fato da estrutura, sem interpretar."""
    if str(var.get("Name", "")).lower() in ENV_SPLIT_VARS and isinstance(var.get("Value"), str) and not var.get("Masked"):
        return {"Name": var["Name"], "Entries": [x for x in var["Value"].split(";") if x]}
    return var


@mcp.tool
def get_registry(host: str, path: str, value: str | None = None):
    r"""Lê uma chave do registro (somente leitura): valores (nome, tipo, dado) e nomes das subchaves. Só HKLM:\...
    (ex.: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion). 'value' devolve só esse valor. SAM e SECURITY são
    recusados e valores cujo nome sugere segredo (senha, token, chave de API, connection string) voltam como
    '<mascarado>'. REG_BINARY mostra os primeiros 64 bytes em hexadecimal. Limites: 200 valores e 100 subchaves."""
    p = _reg_path(path)
    if value is not None and not NAME_RE.match(value):
        raise ValueError("value inválido")
    res = _ps(host, r"""
$rx = '__RX__'; $want = '__V__'
try { $k = Get-Item -LiteralPath '__P__' -ErrorAction Stop } catch {
  [pscustomobject]@{ Exists=$false; Error=$_.Exception.Message } | ConvertTo-Json -Compress; return }
$vals = foreach ($n in @($k.GetValueNames())) {
  if ($want -and $n -ne $want) { continue }
  $kind = "$($k.GetValueKind($n))"; $label = if ($n) { $n } else { '(Default)' }
  if ($n -match $rx) { [pscustomobject]@{ Name=$label; Kind=$kind; Data='<mascarado>'; Masked=$true }; continue }
  $d = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
  if ($d -is [byte[]]) {
    [pscustomobject]@{ Name=$label; Kind=$kind; Data=(($d | select -First 64 | % { $_.ToString('X2') }) -join ''); Bytes=$d.Length; Truncated=($d.Length -gt 64); Masked=$false }
  } else { [pscustomobject]@{ Name=$label; Kind=$kind; Data=$d; Masked=$false } }
}
$sub = @($k.GetSubKeyNames())
[pscustomobject]@{ Exists=$true; Path='__P__'; ValueCount=@($k.GetValueNames()).Count; Values=@($vals | select -First __MV__)
  SubKeyCount=$sub.Count; SubKeys=@($sub | select -First __MS__) } | ConvertTo-Json -Depth 4 -Compress
""".replace("__RX__", SECRET_NAME_RE).replace("__V__", value or "").replace("__P__", p)
       .replace("__MV__", str(REG_MAX_VALUES)).replace("__MS__", str(REG_MAX_SUBKEYS)))
    if isinstance(res, dict) and res.get("Exists") is True:
        res["Values"] = _lst(res.get("Values"))
        res["SubKeys"] = _lst(res.get("SubKeys"))
        if value:
            res["ValueFound"] = bool(res["Values"])
    return res


@mcp.tool
def get_environment_variables(host: str, scope: str = "machine"):
    """Variáveis de ambiente do escopo 'machine' (sistema, padrão) ou 'user' (da conta que a coleta usa no servidor).
    Nomes que sugerem segredo (senha, token, chave de API, connection string) voltam com valor '<mascarado>'.
    Path, PSModulePath e PATHEXT vêm separados em 'Entries'. Só leitura."""
    if scope not in ("machine", "user"):
        raise ValueError("scope deve ser machine ou user")
    res = _ps(host, r"""
$rx = '__RX__'
$d = [Environment]::GetEnvironmentVariables('__S__')
$vars = @($d.GetEnumerator() | sort Name | % {
  if ($_.Key -match $rx) { [pscustomobject]@{ Name="$($_.Key)"; Value='<mascarado>'; Masked=$true } }
  else { [pscustomobject]@{ Name="$($_.Key)"; Value="$($_.Value)"; Masked=$false } } })
[pscustomobject]@{ Scope='__S__'; Count=$vars.Count; Variables=$vars } | ConvertTo-Json -Depth 4 -Compress
""".replace("__RX__", SECRET_NAME_RE).replace("__S__", scope.capitalize()))
    if isinstance(res, dict) and "Variables" in res:
        res["Variables"] = [_env_entries(v) for v in _lst(res["Variables"])]
    return res


# ---------- permissões (ACL) de arquivos e pastas (somente leitura) ----------
ACL_MAX_ENTRIES = 200


GENERIC_RIGHTS = {0x10000000: "GenericAll", 0x20000000: "GenericExecute", 0x40000000: "GenericWrite", 0x80000000: "GenericRead"}


def _decode_rights(rights) -> str | None:
    """Direitos que o .NET devolve só como número (bits GENERIC_* das ACEs de herança, ex.: 268435456) viram nomes.
    Bits fora dos quatro GENERIC_* ficam em hexadecimal; texto já legível (FullControl...) não é tocado."""
    if not isinstance(rights, str) or not re.fullmatch(r"-?\d+", rights.strip()):
        return None
    v = int(rights) & 0xFFFFFFFF
    names = [n for bit, n in GENERIC_RIGHTS.items() if v & bit]
    rest = v & ~sum(GENERIC_RIGHTS)
    if rest:
        names.append(f"0x{rest:08X}")
    return ", ".join(names) or "0"


def _acl_shape(res):
    """Normaliza a resposta: lista de entradas sempre lista e contagem de entradas Deny (fato, sem interpretar)."""
    if isinstance(res, dict) and res.get("Exists") is True:
        res["Entries"] = _lst(res.get("Entries"))
        for e in res["Entries"]:
            if isinstance(e, dict) and (d := _decode_rights(e.get("Rights"))) is not None:
                e["RightsDecoded"] = d
        res["DenyEntries"] = sum(1 for e in res["Entries"] if isinstance(e, dict) and e.get("Type") == "Deny")
        res["Truncated"] = (res.get("EntryCount") or 0) > len(res["Entries"])
    return res


@mcp.tool
def get_permissions(host: str, path: str):
    r"""ACL de um arquivo ou pasta (somente leitura), no formato C:\pasta: dono, grupo, se a herança está bloqueada
    e cada entrada (identidade, SID, Allow/Deny, direitos, herdada, flags de herança), até 200 entradas. Útil para
    erros de 'acesso negado'. Devolve só fatos: não classifica nenhuma permissão como excessiva ou adequada."""
    p = _path(path).rstrip("\\") if len(path) > 3 else _path(path)
    res = _ps(host, r"""
$p = '__P__'
try { $a = Get-Acl -LiteralPath $p -ErrorAction Stop } catch {
  [pscustomobject]@{ Exists=$false; Error=$_.Exception.Message } | ConvertTo-Json -Compress; return }
function Sid($i) { try { "$($i.Translate([Security.Principal.SecurityIdentifier]).Value)" } catch { $null } }
$all = @($a.Access)
$rules = @($all | select -First __MAX__ | % { [pscustomobject]@{ Identity="$($_.IdentityReference)"; SID=(Sid $_.IdentityReference)
  Type="$($_.AccessControlType)"; Rights="$($_.FileSystemRights)"; Inherited=[bool]$_.IsInherited
  InheritanceFlags="$($_.InheritanceFlags)"; PropagationFlags="$($_.PropagationFlags)" } })
$it = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
[pscustomobject]@{ Exists=$true; Path=$p; IsDirectory=[bool]($it -and $it.PSIsContainer); Owner="$($a.Owner)"; Group="$($a.Group)"
  InheritanceBlocked=[bool]$a.AreAccessRulesProtected; EntryCount=$all.Count; Entries=$rules } | ConvertTo-Json -Depth 4 -Compress
""".replace("__P__", p).replace("__MAX__", str(ACL_MAX_ENTRIES)))
    return _acl_shape(res)


# ---------- DNS do ponto de vista do servidor (somente leitura) ----------
DNS_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")
DNS_FILTER_RE = re.compile(r"^[A-Za-z0-9_*.-]{1,253}$")
DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT")
DNS_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
# Códigos de status do cliente DNS (WinDNS.h): só os que aparecem no cache; os demais ficam como número.
DNS_STATUS_NAMES = {0: "Success", 9003: "DNS_ERROR_RCODE_NAME_ERROR (nome inexistente)", 9501: "DNS_INFO_NO_RECORDS (sem registros)"}
DNS_CACHE_MAX = 500


def _dns_cache_shape(res, name_filter, top):
    """Nomes legíveis para tipo e status (números do Windows) e contagens; o que não é conhecido fica numérico."""
    if not isinstance(res, dict) or "Entries" not in res:
        return res
    ents = _lst(res.get("Entries"))
    for e in ents:
        if isinstance(e, dict):
            t, st = e.get("Type"), e.get("Status")
            if isinstance(t, int):
                e["TypeName"] = DNS_TYPE_NAMES.get(t, str(t))
            if isinstance(st, int):
                e["StatusName"] = DNS_STATUS_NAMES.get(st, str(st))
    res["Entries"] = ents
    res["Filter"] = name_filter
    res["Top"] = top
    res["Truncated"] = (res.get("Matched") or 0) > len(ents)
    return res


@mcp.tool
def get_dns_cache(host: str, name_filter: str | None = None, top: int = 100):
    """Cache do cliente DNS do servidor (somente leitura): nome, tipo, status, seção, TTL restante e dado de cada
    entrada. 'name_filter' aceita curinga (ex.: '*.familia.local'). Máximo 500 entradas (padrão 100); 'Total' informa
    quantas existem e 'Matched' quantas casam com o filtro. Entradas de status 9003 são respostas negativas em cache. Só fatos."""
    if name_filter is not None and not DNS_FILTER_RE.match(name_filter):
        raise ValueError("name_filter inválido (letras, números, '.', '-', '_' e '*')")
    n = max(1, min(int(top), DNS_CACHE_MAX))
    res = _ps(host, r"""
$f = '__F__'
$all = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
$m = @($all | ? { -not $f -or $_.Entry -like $f -or $_.Name -like $f })
$sel = @($m | sort Entry | select -First __N__ |
  % { [pscustomobject]@{ Entry=$_.Entry; Name=$_.Name; Type=[int]$_.Type; Status=[int]$_.Status; Section=[int]$_.Section
        TTL=[int]$_.TimeToLive; Data=$_.Data } })
[pscustomobject]@{ Total=$all.Count; Matched=$m.Count; Entries=$sel } | ConvertTo-Json -Depth 4 -Compress
""".replace("__F__", name_filter or "").replace("__N__", str(n)))
    return _dns_cache_shape(res, name_filter, n)


@mcp.tool
def resolve_dns_name(host: str, name: str, record_type: str = "A", dns_server: str | None = None):
    """Resolve um nome DNS DO PONTO DE VISTA DO SERVIDOR (somente leitura; a consulta sai do servidor, para o DNS dele
    ou para 'dns_server'). Tipos: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT. Devolve os registros (nome, tipo, TTL,
    seção, dado) ou o motivo da falha. Serve para comparar a resolução entre servidores. O coletor em si não consulta DNS."""
    rt = record_type.strip().upper()
    if rt not in DNS_RECORD_TYPES:
        raise ValueError(f"record_type inválido. Válidos: {', '.join(DNS_RECORD_TYPES)}")
    if not DNS_NAME_RE.match(name):
        raise ValueError("name inválido (letras, números, '.', '-' e '_')")
    if dns_server is not None and not HOST_RE.match(dns_server):
        raise ValueError("dns_server inválido")
    res = _ps(host, r"""
$srv = '__S__'
$args2 = @{ Name='__N__'; Type='__T__'; DnsOnly=$true; ErrorAction='Stop' }
if ($srv) { $args2.Server = $srv }
try {
  $r = @(Resolve-DnsName @args2)
  $recs = @($r | % {
    $d = if ($_.IPAddress) { $_.IPAddress } elseif ($_.NameHost) { $_.NameHost }
         elseif ($_.NameExchange) { "$($_.NameExchange) (preferência $($_.Preference))" }
         elseif ($_.NameTarget) { "$($_.NameTarget):$($_.Port) (prioridade $($_.Priority), peso $($_.Weight))" }
         elseif ($_.Strings) { ($_.Strings -join ' ') } elseif ($_.PrimaryServer) { "$($_.PrimaryServer) $($_.NameAdministrator)" } else { $null }
    [pscustomobject]@{ Name=$_.Name; Type="$($_.Type)"; TTL=$_.TTL; Section="$($_.Section)"; Data=$d } })
  [pscustomobject]@{ Query='__N__'; Type='__T__'; Server=$(if ($srv) { $srv } else { 'padrão do servidor' }); Resolved=$true; Records=$recs } | ConvertTo-Json -Depth 4 -Compress
} catch {
  [pscustomobject]@{ Query='__N__'; Type='__T__'; Server=$(if ($srv) { $srv } else { 'padrão do servidor' }); Resolved=$false
    Error=$_.Exception.Message } | ConvertTo-Json -Compress
}
""".replace("__S__", dns_server or "").replace("__N__", name).replace("__T__", rt))
    if isinstance(res, dict) and res.get("Resolved") is True:
        res["Records"] = _lst(res.get("Records"))
    return res


# ---------- usuários locais (somente leitura) ----------
def _users_shape(res):
    """Contagens objetivas sobre as contas locais (só fatos, sem classificar nenhuma conta)."""
    if isinstance(res, dict) and "Users" in res:
        us = [u for u in _lst(res.get("Users")) if isinstance(u, dict)]
        res["Users"] = us
        res["Counts"] = {
            "Total": len(us),
            "Enabled": sum(1 for u in us if u.get("Enabled") is True),
            "Disabled": sum(1 for u in us if u.get("Enabled") is False),
            "EnabledPasswordNeverExpires": sum(1 for u in us if u.get("Enabled") is True and u.get("PasswordNeverExpires") is True),
            "NeverLoggedOn": sum(1 for u in us if not u.get("LastLogon")),
        }
    return res


@mcp.tool
def get_local_users(host: str, name: str | None = None):
    """Contas de usuário LOCAIS (somente leitura): nome, nome completo, SID, habilitada, descrição, último logon, senha
    alterada em, senha expira em, senha nunca expira, senha exigida, usuário pode alterar a senha e expiração da conta.
    'name' filtra por nome. 'Counts' traz contagens objetivas (total, habilitadas, desabilitadas, habilitadas com senha
    que nunca expira, nunca logaram). Não classifica nenhuma conta. Em controlador de domínio não há contas locais
    (use as ferramentas de AD). Para grupos e membros, use get_local_groups."""
    if name is not None and not NAME_RE.match(name):
        raise ValueError("name inválido")
    res = _ps(host, r"""
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { [pscustomobject]@{ IsDomainController=$true } | ConvertTo-Json -Compress; return }
$f = '__N__'
try { $us = @(Get-LocalUser -ErrorAction Stop | ? { -not $f -or $_.Name -eq $f } | sort Name) } catch {
  [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress; return }
[pscustomobject]@{ Computer=$env:COMPUTERNAME; Users=@($us | % { [pscustomobject]@{
  Name=$_.Name; FullName=$_.FullName; SID="$($_.SID)"; Enabled=[bool]$_.Enabled; Description=$_.Description
  LastLogon=$_.LastLogon; PasswordLastSet=$_.PasswordLastSet; PasswordExpires=$_.PasswordExpires
  PasswordNeverExpires=[bool](-not $_.PasswordExpires); PasswordRequired=[bool]$_.PasswordRequired
  UserMayChangePassword=[bool]$_.UserMayChangePassword; AccountExpires=$_.AccountExpires
  PrincipalSource="$($_.PrincipalSource)" } }) } | ConvertTo-Json -Depth 4 -Compress
""".replace("__N__", name or ""), timeout=90)
    if isinstance(res, dict) and res.get("IsDomainController"):
        return {"host": host, "error": "Controlador de domínio: não há contas locais. Use ferramentas de AD."}
    if isinstance(res, dict) and res.get("Error") and "Users" not in res:
        return {"host": host, "error": res["Error"]}
    return _users_shape(res)


# ---------- leitura de logs em pastas permitidas (somente leitura) ----------
# Segurança: NÃO é leitura de arquivo arbitrário. Só arquivos .log/.txt dentro de pastas de log conhecidas (lista abaixo,
# ampliável com WINRM_LOG_DIRS_EXTRA, separadas por ';'), sem '..', sem link simbólico/junção no caminho, e as linhas
# devolvidas têm valores de senha/token/chave mascarados.
LOG_DIRS_DEFAULT = [
    "C:" + chr(92) + "Windows" + chr(92) + "Logs",
    "C:" + chr(92) + "Windows" + chr(92) + "System32" + chr(92) + "LogFiles",
    "C:" + chr(92) + "Windows" + chr(92) + "Panther",
    "C:" + chr(92) + "Windows" + chr(92) + "INF",
    "C:" + chr(92) + "Windows" + chr(92) + "debug",
    "C:" + chr(92) + "inetpub" + chr(92) + "logs",
]
LOG_EXTS = (".log", ".txt")
LOG_MAX_TAIL = 500
LOG_MAX_MATCHES = 200
LOG_MAX_LIST = 200
LOG_LINE_CHARS = 500
LOG_SEARCH_MAX_BYTES = 200 * 1024 * 1024
LOG_SECRET_RE = re.compile(r"(?i)\b(pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|shared[_-]?key|"
                           r"connection[_-]?string)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)")


def _log_dirs() -> list[str]:
    extra = [d.strip().rstrip(chr(92)) for d in os.getenv("WINRM_LOG_DIRS_EXTRA", "").split(";") if d.strip()]
    dirs = list(LOG_DIRS_DEFAULT)
    for d in extra:
        if PATH_RE.match(d) and ".." not in d.split(chr(92)) and d not in dirs:
            dirs.append(d)
    return dirs


def _log_root(p: str) -> str | None:
    """A pasta permitida que contém 'p' (ou None). Comparação sem diferenciar maiúsculas, sempre por limite de pasta."""
    low = p.lower().rstrip(chr(92))
    for d in _log_dirs():
        dl = d.lower()
        if low == dl or low.startswith(dl + chr(92)):
            return d
    return None


def _log_path(path: str, must_be_file: bool = True) -> tuple[str, str]:
    """Valida o caminho do log. Devolve (caminho, pasta permitida). Recusa '..', '/', extensão fora de .log/.txt e pasta fora da lista."""
    p = _path((path or "").strip()).rstrip(chr(92))
    if "/" in p or ".." in p.split(chr(92)):
        raise ValueError("Caminho inválido (sem '/' nem '..')")
    root = _log_root(p)
    if root is None:
        raise ValueError("Pasta fora da lista de logs permitidos. Permitidas: " + "; ".join(_log_dirs()))
    if must_be_file and not p.lower().endswith(LOG_EXTS):
        raise ValueError("Só arquivos .log e .txt são lidos")
    return p, root


def _mask_secrets(line):
    """Mascara o VALOR em pares 'senha=...', 'token: ...', 'api_key=...' (o resto da linha fica como está)."""
    if not isinstance(line, str):
        return line
    return LOG_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "***", line)


def _check_pattern(pattern: str) -> str:
    if not pattern or len(pattern) > 100 or any(ord(c) < 32 for c in pattern):
        raise ValueError("pattern inválido (1 a 100 caracteres, sem caracteres de controle)")
    return pattern


PS_LOG_GUARD = r"""
$p = '__P__'; $root = '__R__'
try { $it = Get-Item -LiteralPath $p -Force -ErrorAction Stop } catch {
  [pscustomobject]@{ Refused=$_.Exception.Message } | ConvertTo-Json -Compress; return }
if ($it.PSIsContainer) { [pscustomobject]@{ Refused='O caminho é uma pasta, não um arquivo' } | ConvertTo-Json -Compress; return }
$x = $it
while ($x -and $x.FullName.TrimEnd('\').Length -gt $root.Length) {
  if ($x.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    [pscustomobject]@{ Refused='Link simbólico ou junção no caminho: não é seguido' } | ConvertTo-Json -Compress; return }
  $x = if ($x.PSIsContainer) { $x.Parent } else { $x.Directory } }
"""


def _log_result(res, host: str):
    """Recusas do servidor viram erro; linhas e trechos passam pelo mascaramento de segredos."""
    if isinstance(res, dict) and res.get("Refused"):
        return {"host": host, "error": res["Refused"]}
    if isinstance(res, dict):
        if "Lines" in res:
            # defesa extra: se alguma linha chegar como objeto ({"value": ...}), usa só o texto; nada de PSPath etc.
            res["Lines"] = [_mask_secrets(x.get("value") if isinstance(x, dict) else x) for x in _lst(res.get("Lines"))]
        if "Matches" in res:
            res["Matches"] = _lst(res.get("Matches"))
            for m in res["Matches"]:
                if isinstance(m, dict):
                    m["Text"] = _mask_secrets(m.get("Text"))
    return res


@mcp.tool
def list_log_files(host: str, directory: str, name_filter: str | None = None):
    r"""Lista arquivos .log/.txt de uma pasta de log permitida (somente leitura), do mais recente ao mais antigo:
    nome, tamanho e última gravação (até 200). Pastas permitidas: C:\Windows\Logs, C:\Windows\System32\LogFiles,
    C:\Windows\Panther, C:\Windows\INF, C:\Windows\debug, C:\inetpub\logs (e as de WINRM_LOG_DIRS_EXTRA). Não é recursivo."""
    d, _root = _log_path(directory, must_be_file=False)
    if name_filter is not None and not re.fullmatch(r"[A-Za-z0-9_.*?-]{1,100}", name_filter):
        raise ValueError("name_filter inválido")
    res = _ps(host, r"""
$d = '__D__'; $f = '__F__'
if (-not (Test-Path -LiteralPath $d -PathType Container)) { [pscustomobject]@{ Refused='Pasta não encontrada' } | ConvertTo-Json -Compress; return }
$all = @(Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue | ? { $_.Extension -in '.log','.txt' -and (-not $f -or $_.Name -like $f) } |
  ? { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | sort LastWriteTime -Descending)
[pscustomobject]@{ Directory=$d; Total=$all.Count; Files=@($all | select -First __N__ | % { [pscustomobject]@{
  Name=$_.Name; SizeBytes=$_.Length; LastWriteTime=$_.LastWriteTime } }) } | ConvertTo-Json -Depth 4 -Compress
""".replace("__N__", str(LOG_MAX_LIST)).replace("__D__", d).replace("__F__", name_filter or ""))
    res = _log_result(res, host)
    if isinstance(res, dict) and "Files" in res:
        res["Files"] = _lst(res["Files"])
        res["Truncated"] = (res.get("Total") or 0) > len(res["Files"])
    return res


@mcp.tool
def get_log_tail(host: str, path: str, lines: int = 100):
    r"""Últimas N linhas (padrão 100, máximo 500) de um arquivo .log/.txt de pasta de log permitida (ver list_log_files).
    Somente leitura: sem '..', sem link simbólico no caminho, linhas cortadas em 500 caracteres e valores de
    senha/token/chave mascarados. Rápido mesmo em arquivos grandes."""
    p, root = _log_path(path)
    n = max(1, min(int(lines), LOG_MAX_TAIL))
    res = _ps(host, (PS_LOG_GUARD + r"""
$lines = @(Get-Content -LiteralPath $p -Tail __N__ -ErrorAction Stop | % { [string]$_ })
[pscustomobject]@{ Path=$p; SizeBytes=$it.Length; LastWriteTime=$it.LastWriteTime; LineCount=$lines.Count
  Lines=@($lines | % { if ($_.Length -gt __C__) { $_.Substring(0, __C__) + '…' } else { $_ } }) } | ConvertTo-Json -Depth 3 -Compress
""").replace("__N__", str(n)).replace("__C__", str(LOG_LINE_CHARS)).replace("__R__", root).replace("__P__", p))
    return _log_result(res, host)


@mcp.tool
def search_log(host: str, path: str, pattern: str, max_matches: int = 50):
    r"""Procura um texto LITERAL (sem diferenciar maiúsculas) em um arquivo .log/.txt de pasta de log permitida e devolve
    até 200 linhas (número e texto, cortado em 500 caracteres). Mesmas proteções de get_log_tail. Recusa arquivos com mais de
    200 MB (use get_log_tail). Não é regex."""
    p, root = _log_path(path)
    pat = _check_pattern(pattern)
    n = max(1, min(int(max_matches), LOG_MAX_MATCHES))
    res = _ps(host, (PS_LOG_GUARD + r"""
if ($it.Length -gt __MAXB__) { [pscustomobject]@{ Refused='Arquivo maior que 200 MB: use get_log_tail' } | ConvertTo-Json -Compress; return }
$m = @(Select-String -LiteralPath $p -Pattern '__PAT__' -SimpleMatch -ErrorAction Stop | select -First __N__)
[pscustomobject]@{ Path=$p; SizeBytes=$it.Length; Pattern='__PAT__'; MatchCount=$m.Count
  Matches=@($m | % { $t = "$($_.Line)"; [pscustomobject]@{ Line=$_.LineNumber; Text=$(if ($t.Length -gt __C__) { $t.Substring(0, __C__) + '…' } else { $t }) } }) } | ConvertTo-Json -Depth 4 -Compress
""").replace("__N__", str(n)).replace("__C__", str(LOG_LINE_CHARS)).replace("__MAXB__", str(LOG_SEARCH_MAX_BYTES))
       .replace("__R__", root).replace("__P__", p).replace("__PAT__", pat.replace("'", "''")), timeout=180)
    res = _log_result(res, host)
    if isinstance(res, dict) and "Matches" in res:
        res["Truncated"] = (res.get("MatchCount") or 0) >= n
    return res


# ---------- contexto de segurança da própria coleta (somente leitura) ----------
INTEGRITY_LEVELS = {"S-1-16-0": "Untrusted", "S-1-16-4096": "Low", "S-1-16-8192": "Medium", "S-1-16-8448": "MediumPlus",
                    "S-1-16-12288": "High", "S-1-16-16384": "System", "S-1-16-20480": "ProtectedProcess"}   # SIDs de nível de integridade


def _security_context_shape(res):
    """Listas sempre listas e o nível de integridade por nome (SIDs documentados)."""
    if isinstance(res, dict) and "Groups" in res:
        res["Groups"] = [g for g in _lst(res.get("Groups")) if isinstance(g, dict)]
        res["Privileges"] = [p for p in _lst(res.get("Privileges")) if isinstance(p, dict)]
        sid = res.get("IntegritySid")
        res["IntegrityLevel"] = INTEGRITY_LEVELS.get(sid, sid) if sid else None
    return res


@mcp.tool
def get_security_context(host: str):
    """Identidade com que a COLETA roda no servidor (somente leitura): conta, SID, tipo de autenticação, nível de
    integridade (Low/Medium/High/System), se é membro do grupo Administradores local, grupos do token (SID e nome) e
    privilégios do token (nome e estado como o Windows informa, no idioma do servidor). Descreve a conta usada pelo
    coletor, não o servidor: serve para explicar 'acesso negado' ou recusas de leitura. Só fatos."""
    res = _ps(host, r"""
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
function Nm($sid) { try { $sid.Translate([Security.Principal.NTAccount]).Value } catch { $null } }
$groups = @($id.Groups | % { [pscustomobject]@{ SID="$($_.Value)"; Name=(Nm $_) } })
# o rótulo de integridade não vem em $id.Groups; 'whoami /groups' o lista, e a coluna SID independe do idioma
$integ = @(whoami /groups /fo csv /nh 2>$null | ConvertFrom-Csv -Header Name,Type,SID,Attr | ? { $_.SID -like 'S-1-16-*' } | select -First 1)
$priv = @(whoami /priv /fo csv /nh 2>$null | ConvertFrom-Csv -Header Name,Description,State | % { [pscustomobject]@{ Name=$_.Name; State=$_.State } })
[pscustomobject]@{ Computer=$env:COMPUTERNAME; Name=$id.Name; UserSid="$($id.User.Value)"
  AuthenticationType=$id.AuthenticationType; ImpersonationLevel="$($id.ImpersonationLevel)"
  IsSystem=$id.IsSystem; IsAnonymous=$id.IsAnonymous; IsGuest=$id.IsGuest
  IntegritySid=$(if ($integ) { $integ[0].SID } else { $null })
  MemberOfAdministratorsGroup=[bool]($groups | ? { $_.SID -eq 'S-1-5-32-544' })
  GroupCount=$groups.Count; Groups=$groups; Privileges=$priv } | ConvertTo-Json -Depth 4 -Compress
""", timeout=60)
    return _security_context_shape(res)


# ---------- arquivos e pastas (somente leitura, com bloqueios) ----------
# Leitura de caminhos arbitrários, entregue com salvaguardas (é uma LISTA DE BLOQUEIO, melhor esforço, e não uma garantia):
#  - formato C:\pasta, sem '..', '/', aspas, curingas ou '$' no caminho;
#  - locais sensíveis recusados (hives do registro, NTDS, DPAPI/credenciais, chaves SSH, System Volume Information);
#  - arquivos sensíveis recusados pelo nome/extensão (certificados com chave privada, chaves, KeePass, dumps, discos
#    virtuais, respostas de instalação com senha); mais pastas em WINRM_FILE_DENY_EXTRA (separadas por ';');
#  - nenhum link simbólico ou junção no caminho (senão seria um desvio da lista de bloqueio);
#  - arquivos binários não são exibidos; chave privada em texto recusa o arquivo; valores de senha/token/chave mascarados;
#  - tamanhos limitados (linhas, caracteres por linha, resultados, arquivos comparados).
FS_DENY_PATH_PATTERNS = [
    r"^[a-z]:\\windows\\system32\\config(\\|$)",
    r"\\ntds(\\|$)",
    r"^[a-z]:\\windows\\system32\\microsoft\\(protect|crypto)(\\|$)",
    r"\\microsoft\\(credentials|protect|vault|crypto)(\\|$)",
    r"\\\.ssh(\\|$)",
    r"^[a-z]:\\system volume information(\\|$)",
]
FS_DENY_EXTS = (".pfx", ".p12", ".pem", ".key", ".ppk", ".pvk", ".kdbx", ".kdb", ".jks", ".keystore", ".dit", ".hiv",
                ".dmp", ".hdmp", ".mdmp", ".rdp", ".vhd", ".vhdx", ".vmdk")
FS_DENY_NAME_RE = re.compile(r"^(id_(rsa|dsa|ecdsa|ed25519)|\.git-credentials|\.netrc|ntuser\.dat.*|(auto)?unattend\.xml|sysprep\.(xml|inf))$", re.I)
FS_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
FS_ENCODINGS = ("utf8", "unicode", "ascii", "default", "oem", "utf32", "bigendianunicode")
FS_NAME_FILTER_RE = re.compile(r"^[A-Za-z0-9 _*?.()-]{1,100}$")
FS_MAX_LINES = 500
FS_LINE_CHARS = 500
FS_MAX_LIST = 200
FS_MAX_FIND = 500
FS_FIND_VISIT_CAP = 50000
FS_COMPARE_MAX_LINES = 5000
FS_COMPARE_MAX_BYTES = 2 * 1024 * 1024
FS_COMPARE_MAX_DIFFS = 200
FS_HASH_MAX_BYTES = 200 * 1024 * 1024


def _fs_deny_extra() -> list[str]:
    out = []
    for d in os.getenv("WINRM_FILE_DENY_EXTRA", "").split(";"):
        d = d.strip().rstrip(chr(92))
        if d and PATH_RE.match(d) and ".." not in d.split(chr(92)):
            out.append(d)
    return out


def _fs_blocked_path(p: str) -> str | None:
    """Motivo do bloqueio se o caminho (arquivo ou pasta) está numa área recusada; None se liberado."""
    low = p.lower().rstrip(chr(92))
    for pat in FS_DENY_PATH_PATTERNS:
        if re.search(pat, low):
            return "área sensível (hives do registro, NTDS, credenciais/DPAPI, chaves SSH ou System Volume Information)"
    for d in _fs_deny_extra():
        dl = d.lower()
        if low == dl or low.startswith(dl + chr(92)):
            return "pasta bloqueada em WINRM_FILE_DENY_EXTRA"
    return None


def _fs_blocked_name(name: str) -> str | None:
    """Motivo do bloqueio pelo nome/extensão do arquivo; None se liberado."""
    low = (name or "").lower()
    if low.endswith(FS_DENY_EXTS):
        return "tipo de arquivo bloqueado (certificado/chave, KeePass, dump, disco virtual, hive ou RDP)"
    if FS_DENY_NAME_RE.match(low):
        return "arquivo sensível (chave SSH, credenciais, resposta de instalação)"
    return None


def _fs_path(path: str) -> str:
    """Valida o caminho de pasta ou arquivo e recusa as áreas bloqueadas."""
    p = _path((path or "").strip())
    if len(p) > 3:
        p = p.rstrip(chr(92))
    if "/" in p or ".." in p.split(chr(92)):
        raise ValueError("Caminho inválido (sem '/' nem '..')")
    why = _fs_blocked_path(p)
    if why:
        raise ValueError(f"Caminho bloqueado: {why}")
    return p


def _fs_file(path: str) -> str:
    p = _fs_path(path)
    why = _fs_blocked_name(p.rsplit(chr(92), 1)[-1])
    if why:
        raise ValueError(f"Arquivo bloqueado: {why}")
    return p


def _fs_deny_regex() -> str:
    """Regex único (mesmos padrões do Python) para o script de busca pular pastas bloqueadas."""
    parts = list(FS_DENY_PATH_PATTERNS)
    for d in _fs_deny_extra():
        parts.append("^" + re.escape(d.lower()) + r"(\\|$)")
    return "|".join(f"(?:{x})" for x in parts).replace("'", "''")


def _fs_mask_and_check(texts):
    """Aplica o mascaramento e detecta chave privada. Devolve (textos, erro_ou_None)."""
    out = []
    for t in texts:
        if isinstance(t, str) and FS_PRIVATE_KEY_RE.search(t):
            return None, "O arquivo contém uma chave privada: o conteúdo não é exibido"
        out.append(_mask_secrets(t))
    return out, None


PS_FS_GUARD = r"""
function Guard([string]$p) {
  try { $it = Get-Item -LiteralPath $p -Force -ErrorAction Stop } catch { return $_.Exception.Message }
  if ($it.PSIsContainer) { return 'O caminho é uma pasta, não um arquivo' }
  $x = $it
  while ($x) {
    if ($x.Attributes -band [IO.FileAttributes]::ReparsePoint) { return 'Link simbólico ou junção no caminho: use o caminho real' }
    $x = if ($x.PSIsContainer) { $x.Parent } else { $x.Directory } }
  $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
  try { $buf = New-Object byte[] 4096; $n = $fs.Read($buf, 0, 4096) } finally { $fs.Dispose() }
  if ($n -gt 0) {
    $bom = ($n -ge 2 -and (($buf[0] -eq 255 -and $buf[1] -eq 254) -or ($buf[0] -eq 254 -and $buf[1] -eq 255))) -or
           ($n -ge 3 -and $buf[0] -eq 239 -and $buf[1] -eq 187 -and $buf[2] -eq 191)
    if (-not $bom -and ($buf[0..($n - 1)] -contains 0)) { return 'Arquivo binário: o conteúdo não é exibido' } }
  return $null
}
"""

PS_FS_DIRGUARD = r"""
function DirGuard([string]$d) {
  try { $it = Get-Item -LiteralPath $d -Force -ErrorAction Stop } catch { return $_.Exception.Message }
  if (-not $it.PSIsContainer) { return 'O caminho é um arquivo, não uma pasta' }
  $x = $it
  while ($x) {
    if ($x.Attributes -band [IO.FileAttributes]::ReparsePoint) { return 'Link simbólico ou junção no caminho: use o caminho real' }
    $x = $x.Parent }
  return $null
}
"""


def _fs_result(res, host: str):
    """Recusas do servidor viram erro; linhas e diferenças passam por mascaramento e checagem de chave privada."""
    if isinstance(res, dict) and res.get("Refused"):
        return {"host": host, "error": res["Refused"]}
    if not isinstance(res, dict):
        return res
    if "Lines" in res:
        lines = [x.get("value") if isinstance(x, dict) else x for x in _lst(res.get("Lines"))]
        lines, err = _fs_mask_and_check(lines)
        if err:
            return {"host": host, "error": err}
        res["Lines"] = lines
    if "Diffs" in res:
        diffs = [d for d in _lst(res.get("Diffs")) if isinstance(d, dict)]
        texts, err = _fs_mask_and_check([d.get("Text") for d in diffs])
        if err:
            return {"host": host, "error": err}
        for d, t in zip(diffs, texts):
            d["Text"] = t
        res["Diffs"] = diffs
    return res


@mcp.tool
def list_directory(host: str, path: str, name_filter: str | None = None, top: int = 100):
    r"""Lista o conteúdo de UMA pasta (somente leitura), do mais recente ao mais antigo: nome, tipo, tamanho, última
    gravação, atributos e se é link. 'path' no formato C:\pasta; 'name_filter' aceita curinga; até 200 itens (padrão 100).
    Itens cujo conteúdo é bloqueado para leitura vêm com ReadBlocked=true. Recusa áreas sensíveis, links e junções."""
    p = _fs_path(path)
    if name_filter is not None and not FS_NAME_FILTER_RE.match(name_filter):
        raise ValueError("name_filter inválido")
    n = max(1, min(int(top), FS_MAX_LIST))
    res = _ps(host, PS_FS_DIRGUARD + r"""
$d = '__D__'; $f = '__F__'
$r = DirGuard $d
if ($r) { [pscustomobject]@{ Refused=$r } | ConvertTo-Json -Compress; return }
$all = @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | ? { -not $f -or $_.Name -like $f })
[pscustomobject]@{ Directory=$d; Total=$all.Count; Entries=@($all | sort LastWriteTime -Descending | select -First __N__ | % {
  [pscustomobject]@{ Name=$_.Name; IsDirectory=[bool]$_.PSIsContainer; SizeBytes=$(if ($_.PSIsContainer) { $null } else { $_.Length })
    LastWriteTime=$_.LastWriteTime; Attributes="$($_.Attributes)"; IsLink=[bool]($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } }) } | ConvertTo-Json -Depth 4 -Compress
""".replace("__N__", str(n)).replace("__D__", p).replace("__F__", name_filter or ""))
    res = _fs_result(res, host)
    if isinstance(res, dict) and "Entries" in res:
        res["Entries"] = [e for e in _lst(res["Entries"]) if isinstance(e, dict)]
        for e in res["Entries"]:
            child = p.rstrip(chr(92)) + chr(92) + str(e.get("Name"))
            e["ReadBlocked"] = bool(_fs_blocked_path(child) or (not e.get("IsDirectory") and _fs_blocked_name(str(e.get("Name")))))
        res["Truncated"] = (res.get("Total") or 0) > len(res["Entries"])
    return res


@mcp.tool
def find_files(host: str, path: str, pattern: str, max_depth: int = 5, max_results: int = 100):
    r"""Procura ARQUIVOS pelo nome (wildcard, ex.: '*.config', 'web.config') a partir de uma pasta, sem seguir links ou
    junções e sem entrar em áreas bloqueadas (somente leitura). max_depth 0-10 (padrão 5), até 500 resultados (padrão
    100), com caminho, tamanho e última gravação. Lê no máximo 50.000 itens: 'Visited' informa quantos e 'Truncated'
    avisa se a busca foi cortada. Procura por NOME; para texto dentro de arquivos use search_log (logs) ou read_file."""
    p = _fs_path(path)
    if not FS_NAME_FILTER_RE.match(pattern or ""):
        raise ValueError("pattern inválido (letras, números, espaço, '*', '?', '.', '(', ')', '-' e '_')")
    depth = max(0, min(int(max_depth), 10))
    cap = max(1, min(int(max_results), FS_MAX_FIND))
    res = _ps(host, PS_FS_DIRGUARD + r"""
$root = '__D__'; $pat = '__PAT__'; $max = __DEPTH__; $cap = __CAP__; $visitCap = __VC__; $deny = '__DENY__'
$r = DirGuard $root
if ($r) { [pscustomobject]@{ Refused=$r } | ConvertTo-Json -Compress; return }
$script:n = 0; $script:v = 0; $script:res = New-Object System.Collections.ArrayList
function Walk([string]$d, [int]$depth) {
  if ($depth -gt $max -or $script:n -ge $cap -or $script:v -ge $visitCap) { return }
  foreach ($c in @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue)) {
    $script:v++
    if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
    if ($c.PSIsContainer) { if ($c.FullName -inotmatch $deny) { Walk $c.FullName ($depth + 1) } }
    elseif ($c.Name -like $pat) { [void]$script:res.Add([pscustomobject]@{ Path=$c.FullName; SizeBytes=$c.Length; LastWriteTime=$c.LastWriteTime }); $script:n++ }
    if ($script:n -ge $cap -or $script:v -ge $visitCap) { return } } }
Walk $root 0
[pscustomobject]@{ Root=$root; Pattern=$pat; Visited=$script:v; Count=$script:n; Files=@($script:res) } | ConvertTo-Json -Depth 4 -Compress
""".replace("__DEPTH__", str(depth)).replace("__CAP__", str(cap)).replace("__VC__", str(FS_FIND_VISIT_CAP))
       .replace("__DENY__", _fs_deny_regex()).replace("__D__", p).replace("__PAT__", pattern), timeout=240)
    res = _fs_result(res, host)
    if isinstance(res, dict) and "Files" in res:
        res["Files"] = [f for f in _lst(res["Files"]) if isinstance(f, dict)]
        for f in res["Files"]:
            f["ReadBlocked"] = bool(_fs_blocked_path(str(f.get("Path"))) or _fs_blocked_name(str(f.get("Path")).rsplit(chr(92), 1)[-1]))
        res["Truncated"] = (res.get("Count") or 0) >= cap or (res.get("Visited") or 0) >= FS_FIND_VISIT_CAP
    return res


@mcp.tool
def file_info(host: str, path: str, hash: bool = False):
    r"""Metadados de um arquivo ou pasta (somente leitura), no formato C:\caminho: tipo, tamanho, datas de criação,
    gravação e acesso, atributos, dono, se é link (e o destino) e, para executáveis e bibliotecas, a versão (arquivo,
    produto, empresa, nome original). hash=true acrescenta o SHA-256 (arquivos até 200 MB e fora da lista de bloqueio).
    Não lê o conteúdo."""
    p = _fs_path(path)
    name = p.rsplit(chr(92), 1)[-1]
    if hash and _fs_blocked_name(name):
        raise ValueError("hash recusado: arquivo bloqueado para leitura")
    res = _ps(host, r"""
$p = '__P__'; $hash = __H__
try { $it = Get-Item -LiteralPath $p -Force -ErrorAction Stop } catch {
  [pscustomobject]@{ Exists=$false; Error=$_.Exception.Message } | ConvertTo-Json -Compress; return }
$owner = try { (Get-Acl -LiteralPath $p -ErrorAction Stop).Owner } catch { $null }
$vi = $null
if (-not $it.PSIsContainer -and $it.VersionInfo -and ($it.VersionInfo.FileVersion -or $it.VersionInfo.ProductName)) {
  $v = $it.VersionInfo
  $vi = [pscustomobject]@{ FileVersion=$v.FileVersion; ProductVersion=$v.ProductVersion; ProductName=$v.ProductName
    CompanyName=$v.CompanyName; OriginalFilename=$v.OriginalFilename; FileDescription=$v.FileDescription } }
$sha = $null; $shaNote = $null
if ($hash -and -not $it.PSIsContainer) {
  if ($it.Length -gt __HM__) { $shaNote = 'Arquivo maior que 200 MB: hash não calculado' }
  else { $sha = try { (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null } } }
[pscustomobject]@{ Exists=$true; Path=$it.FullName; IsDirectory=[bool]$it.PSIsContainer
  SizeBytes=$(if ($it.PSIsContainer) { $null } else { $it.Length })
  CreationTime=$it.CreationTime; LastWriteTime=$it.LastWriteTime; LastAccessTime=$it.LastAccessTime
  Attributes="$($it.Attributes)"; Owner=$owner
  IsLink=[bool]($it.Attributes -band [IO.FileAttributes]::ReparsePoint); LinkType=$it.LinkType; LinkTarget=$(if ($it.Target) { "$($it.Target)" } else { $null })
  Version=$vi; Sha256=$sha; HashNote=$shaNote } | ConvertTo-Json -Depth 4 -Compress
""".replace("__H__", "$true" if hash else "$false").replace("__HM__", str(FS_HASH_MAX_BYTES)).replace("__P__", p))
    if isinstance(res, dict) and res.get("Exists"):
        res["ReadBlocked"] = bool(_fs_blocked_path(p) or (not res.get("IsDirectory") and _fs_blocked_name(name)))
    return res


@mcp.tool
def read_file(host: str, path: str, start_line: int = 1, end_line: int = 200, tail: bool = False, encoding: str | None = None):
    r"""Lê um arquivo de TEXTO (somente leitura), no formato C:\caminho. Por intervalo (start_line a end_line, até 500
    linhas por chamada) ou, com tail=true, as últimas end_line linhas (máx. 500). encoding opcional: utf8, unicode,
    ascii, default, oem, utf32, bigendianunicode (padrão: detecta pelo BOM). Linhas cortadas em 500 caracteres e valores
    de senha/token/chave mascarados. Recusa: áreas e arquivos sensíveis, binários, links/junções e arquivos com chave
    privada. Para logs de serviços use também get_log_tail/search_log."""
    p = _fs_file(path)
    if encoding is not None and encoding.lower() not in FS_ENCODINGS:
        raise ValueError("encoding inválido. Válidos: " + ", ".join(FS_ENCODINGS))
    enc = f" -Encoding {encoding.lower()}" if encoding else ""
    if tail:
        count = max(1, min(int(end_line), FS_MAX_LINES))
        read = f"@(Get-Content -LiteralPath $p -Tail {count}{enc} -ErrorAction Stop | % {{ [string]$_ }})"
        first = None
    else:
        s0 = max(1, int(start_line))
        e0 = int(end_line)
        if e0 < s0:
            raise ValueError("end_line deve ser maior ou igual a start_line")
        e0 = min(e0, s0 + FS_MAX_LINES - 1)
        read = f"@(Get-Content -LiteralPath $p -TotalCount {e0}{enc} -ErrorAction Stop | select -Skip {s0 - 1} | % {{ [string]$_ }})"
        first = s0
    res = _ps(host, PS_FS_GUARD + r"""
$p = '__P__'
$r = Guard $p
if ($r) { [pscustomobject]@{ Refused=$r } | ConvertTo-Json -Compress; return }
$it = Get-Item -LiteralPath $p -Force
$lines = __READ__
[pscustomobject]@{ Path=$p; SizeBytes=$it.Length; LastWriteTime=$it.LastWriteTime; Mode='__MODE__'; StartLine=__FIRST__; LineCount=$lines.Count
  Lines=@($lines | % { if ($_.Length -gt __C__) { $_.Substring(0, __C__) + '…' } else { $_ } }) } | ConvertTo-Json -Depth 3 -Compress
""".replace("__READ__", read).replace("__MODE__", "tail" if tail else "range").replace("__FIRST__", str(first) if first else "$null")
       .replace("__C__", str(FS_LINE_CHARS)).replace("__P__", p))
    return _fs_result(res, host)


@mcp.tool
def compare_files(host: str, path_a: str, path_b: str, max_diffs: int = 100):
    r"""Compara dois arquivos de TEXTO do mesmo servidor, linha a linha (somente leitura): 'Identical', quantas linhas
    cada um tem, 'DiffCount' e as diferenças (Side OnlyInA ou OnlyInB, número da linha e texto, até 200). Cada arquivo:
    até 2 MB e 5.000 linhas. Mesmas proteções de read_file (áreas e arquivos sensíveis, binários, links, chave privada;
    segredos mascarados). Útil para comparar o mesmo arquivo de configuração entre duas pastas ou versões."""
    a, b = _fs_file(path_a), _fs_file(path_b)
    n = max(1, min(int(max_diffs), FS_COMPARE_MAX_DIFFS))
    res = _ps(host, PS_FS_GUARD + r"""
$pa = '__A__'; $pb = '__B__'
foreach ($p in $pa, $pb) {
  $r = Guard $p
  if ($r) { [pscustomobject]@{ Refused="$p : $r" } | ConvertTo-Json -Compress; return }
  $it = Get-Item -LiteralPath $p -Force
  if ($it.Length -gt __MB__) { [pscustomobject]@{ Refused="$p : arquivo maior que 2 MB" } | ConvertTo-Json -Compress; return } }
function Load($p) {
  $l = @(Get-Content -LiteralPath $p -TotalCount (__ML__ + 1) -ErrorAction Stop | % { [string]$_ })
  if ($l.Count -gt __ML__) { return $null }
  $o = New-Object System.Collections.ArrayList; $i = 0
  foreach ($t in $l) { $i++; [void]$o.Add([pscustomobject]@{ N=$i; Text=$t }) }
  return ,$o }
$A = Load $pa; $B = Load $pb
if ($A -eq $null -or $B -eq $null) { [pscustomobject]@{ Refused='Arquivo com mais de __ML__ linhas' } | ConvertTo-Json -Compress; return }
$d = @(Compare-Object $A $B -Property Text -PassThru -SyncWindow 50 | sort @{e={$_.SideIndicator}}, N)
[pscustomobject]@{ PathA=$pa; PathB=$pb; LeftLines=$A.Count; RightLines=$B.Count; DiffCount=$d.Count; Identical=($d.Count -eq 0)
  Diffs=@($d | select -First __N__ | % { [pscustomobject]@{ Side=$(if ($_.SideIndicator -eq '<=') { 'OnlyInA' } else { 'OnlyInB' }); Line=$_.N
    Text=$(if ($_.Text.Length -gt __C__) { $_.Text.Substring(0, __C__) + '…' } else { $_.Text }) } }) } | ConvertTo-Json -Depth 4 -Compress
""".replace("__MB__", str(FS_COMPARE_MAX_BYTES)).replace("__ML__", str(FS_COMPARE_MAX_LINES)).replace("__N__", str(n))
       .replace("__C__", str(FS_LINE_CHARS)).replace("__A__", a).replace("__B__", b), timeout=180)
    res = _fs_result(res, host)
    if isinstance(res, dict) and "Diffs" in res:
        res["Truncated"] = (res.get("DiffCount") or 0) > len(res["Diffs"])
    return res


# ---------- painel de saúde rápido ----------
@mcp.tool
def get_health_summary(
    host: str,
    cpu_warn: int = 80,
    mem_warn: int = 85,
    disk_warn_pct: int = 15,
    patch_warn_days: int = 45,
    uptime_warn_days: int = 120,
):
    """Painel de saúde em UMA chamada: CPU, memória, discos, serviços automáticos parados, reboot pendente,
    uptime, dias sem patch, flags do CBS, eventos críticos (24h) e desligamentos inesperados (7d).
    Só fatos e sinais: devolve status por área (sem_sinais | sinais_presentes | verificacao_incompleta), status geral
    e achados com o limiar do projeto à vista (parâmetros *_warn / *_pct / *_days). Não classifica gravidade nem
    recomenda: isso é do RAG (microsoft-docs)."""
    d = _ps(host, PS_EV + r"""
$os = Get-CimInstance Win32_OperatingSystem
$c0 = Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'"; Start-Sleep -Milliseconds 1000
$c1 = Get-CimInstance Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'"
# CPU real no intervalo de 1 s (contador bruto: ocioso/tempo), independente do idioma; antes 3x Win32_Processor = 5 s.
$cpuPct = [math]::Max(0, [math]::Round(100 * (1 - ($c1.PercentProcessorTime - $c0.PercentProcessorTime) / [double]([math]::Max(1, $c1.Timestamp_Sys100NS - $c0.Timestamp_Sys100NS))), 0))
$mem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'
$last = Get-HotFix | ? InstalledOn | sort InstalledOn -desc | select -first 1
[pscustomobject]@{
  Host=$env:COMPUTERNAME; OS=$os.Caption; LastBoot=$os.LastBootUpTime
  UptimeDays=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalDays,1)
  CpuPct=$cpuPct
  MemUsedPct=[math]::Round(100-100*$os.FreePhysicalMemory/$os.TotalVisibleMemorySize,1)
  MemCommitPct=$mem.PercentCommittedBytesInUse
  Disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ? Size | select DeviceID,
    @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},
    @{n='FreePct';e={[math]::Round(100*$_.FreeSpace/$_.Size,1)}})
  StoppedAuto=__SVC__
  RebootCBS=(Test-Path "$k\Component Based Servicing\RebootPending")
  RebootWU=(Test-Path "$k\WindowsUpdate\Auto Update\RebootRequired")
  PendingXml=(Test-Path "$env:SystemRoot\WinSxS\pending.xml")
  LastHotfix=$last.HotFixID; DaysSincePatch=if ($last) { [int]((Get-Date)-$last.InstalledOn).TotalDays } else { $null }
  Critical24h=(@(Ev 'System' '__XC__').Count + @(Ev 'Application' '__XC__').Count)
  Error24h=(@(Ev 'System' '__XE__' 5000).Count + @(Ev 'Application' '__XE__' 5000).Count)
  Unexpected7d=@(Ev 'System' '__XU__' | ? { $_.Id -eq 6008 -or $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' }).Count
} | ConvertTo-Json -Depth 3 -Compress
""".replace("__SVC__", PS_STOPPED_AUTO).replace("__XC__", _xpath(levels=[1], days=1)).replace("__XE__", _xpath(levels=[2], days=1))
       .replace("__XU__", _xpath(ids=[41, 6008], days=7)), timeout=120)
    if not isinstance(d, dict) or "Host" not in d:
        return d

    areas, findings = {}, []

    def flag(area, st, msg=None):
        areas[area] = _worst(areas.get(area, SEM), st)
        if msg:
            findings.append(f"{area}: {msg}")

    cpu = d.get("CpuPct") or 0
    flag("CPU", SIG if cpu >= cpu_warn else SEM,
         f"{cpu}% de uso (limiar do projeto: {cpu_warn}%)" if cpu >= cpu_warn else None)
    mu, mc = d.get("MemUsedPct") or 0, d.get("MemCommitPct") or 0
    flag("Memória", SIG if mu >= mem_warn else SEM,
         f"{mu}% da RAM em uso (limiar do projeto: {mem_warn}%)" if mu >= mem_warn else None)
    if mc >= 90:
        flag("Memória", SIG, f"commit em {mc}% (limiar do projeto: 90%)")
    flag("Disco", SEM)
    for dk in _lst(d.get("Disks")):
        fp, fg = dk.get("FreePct") or 0, dk.get("FreeGB") or 0
        if fp <= disk_warn_pct or fg < 2:
            flag("Disco", SIG, f"{dk['DeviceID']} com {fg} GB livres ({fp}%) (limiar do projeto: {disk_warn_pct}% ou 2 GB)")
    flag("Serviços", SEM)
    svc = _service_facts(_lst(d.get("StoppedAuto")))
    failed = [x for x in svc["services"] if x["failed_exit_code"] or x["transitional_state"]]
    if failed:
        flag("Serviços", SIG, "automáticos parados com código de saída de falha ou em estado transitório: " +
             ", ".join(f"{x['Name']} ({x['State']}, exit {x['ExitCode']})" for x in failed[:10]))
    flag("Patches", SEM)
    dp = d.get("DaysSincePatch")
    if dp is None:
        flag("Patches", INC, "não foi possível determinar o último patch")
    elif dp >= patch_warn_days:
        flag("Patches", SIG, f"{dp} dias desde o último patch ({d.get('LastHotfix')}) (limiar do projeto: {patch_warn_days})")
    if d.get("RebootCBS") or d.get("RebootWU") or d.get("PendingXml"):
        flag("Patches", SIG, "reboot pendente (CBS/WU/pending.xml)")
    up = d.get("UptimeDays") or 0
    flag("Disponibilidade", SEM)
    if up >= uptime_warn_days:
        flag("Disponibilidade", SIG, f"{up} dias desde o último boot (limiar do projeto: {uptime_warn_days})")
    if d.get("Unexpected7d"):
        flag("Disponibilidade", SIG, f"{d['Unexpected7d']} desligamento(s) inesperado(s) em 7 dias")
    flag("Eventos", SEM)
    if d.get("Critical24h"):
        flag("Eventos", SIG, f"{d['Critical24h']} evento(s) crítico(s) nas últimas 24h")
    if (d.get("Error24h") or 0) >= 50:
        flag("Eventos", SIG, f"{d['Error24h']} eventos de erro nas últimas 24h (limiar do projeto: 50; System+Application)")

    return {
        "host": d["Host"], "os": d.get("OS"), "overall": _worst(*areas.values()),
        "areas": areas, "findings": findings or ["Nenhum sinal encontrado."],
        "metrics": {k: d.get(k) for k in ("CpuPct", "MemUsedPct", "MemCommitPct", "UptimeDays", "LastBoot",
                                          "DaysSincePatch", "LastHotfix", "Critical24h", "Error24h", "Unexpected7d")},
        "disks": _lst(d.get("Disks")),
        "stopped_auto_services": svc["services"], "stopped_auto_signals": svc["signals"],
        "next_steps": "Áreas com sinais podem ser aprofundadas com: validate_cbs, get_event_summary, "
                      "get_top_processes, get_disk_usage_tree, get_service_failures.",
    }


@mcp.prompt
def root_cause_analysis(host: str, symptom: str, days: int = 1) -> str:
    """Roteiro de RCA para um sintoma em um servidor (logs do último dia por padrão)."""
    return (
        f"Faça análise de causa raiz no servidor {host}. Sintoma: {symptom}.\n"
        f"Regra de coleta: logs só de problema (Crítico/Erro/Aviso) e período days={_days(days)}; "
        "só amplie o período se o usuário pedir ou se o início do problema for anterior.\n"
        "1) get_health_summary, get_uptime e get_reboot_and_crash_history; 2) get_top_resource_consumers; "
        "3) get_event_summary (include_operational=true se o sintoma envolver GPO/update/tarefas/RDS/tempo) "
        "e depois get_events nos IDs/provedores suspeitos; 4) get_disks, get_service_failures, "
        "get_last_patches e, se envolver patch/update, validate_cbs e get_cbs_log_errors. "
        "Monte uma linha do tempo, separe fatos de hipóteses, aponte a causa mais provável "
        "e a evidência que a sustenta."
    )


@mcp.prompt
def ops_health_check(host: str) -> str:
    """Health check operacional completo de um Windows Server."""
    return (
        f"Faça um health check operacional do servidor {host}. Comece por get_health_summary e get_uptime; "
        "depois validate_cbs e get_last_patches; get_top_resource_consumers; get_network_config, "
        "get_network_adapters, get_nic_teaming, get_routes, get_network_connections, get_listening_ports, "
        "get_applied_gpos, get_time_config, get_server_roles, get_cluster_health, "
        "get_scheduled_tasks, get_user_sessions, get_local_admins e get_failed_logons. Complete com "
        "get_system_overview, "
        "get_patch_status (+ get_pending_updates e get_windows_update_history), "
        "get_performance_snapshot, get_disks, get_stopped_auto_services e get_service_failures, "
        "get_roles_and_features, get_security_posture e "
        "get_expiring_certificates. Inclua a saúde do CBS/Windows Update (get_cbs_health, "
        "get_cbs_log_errors, get_windows_update_health, get_update_error_analysis) e o disco "
        "(get_common_space_offenders, get_disk_allocation_analysis e, nos volumes com pouco espaço, "
        "get_disk_usage_tree). Todas as coletas de log usam o padrão de 1 dia e só Crítico/Erro/Aviso. "
        "Entregue um resumo só com fatos e sinais por área (sem severidade). Recomendação, suporte ou boa prática "
        "só se o usuário pedir, via microsoft-docs."
    )


if __name__ == "__main__":
    mcp.run()  # stdio; para HTTP: mcp.run(transport="http", host="0.0.0.0", port=8000)
