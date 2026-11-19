"""MCP (FastMCP) para análise de causa raiz em Windows Server via WinRM.

Somente leitura: nenhuma tool executa comando arbitrário nem altera o servidor.

Variáveis de ambiente:
  WINRM_USER, WINRM_PASSWORD     credenciais (use conta de serviço com menor privilégio)
  WINRM_TRANSPORT                ntlm (padrão) | kerberos | credssp | basic
  WINRM_SSL                      true -> HTTPS/5986 (recomendado) | false -> HTTP/5985
  WINRM_VALIDATE_CERT            validate (padrão) | ignore
  WINRM_ALLOWED_HOSTS            lista separada por vírgula (allowlist de servidores)
"""
import base64
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import winrm
from fastmcp import FastMCP

mcp = FastMCP("windows-server-rca")

ALLOWED = {h.strip().lower() for h in os.getenv("WINRM_ALLOWED_HOSTS", "").split(",") if h.strip()}
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
NAME_RE = re.compile(r"^[A-Za-z0-9 ._/-]{1,100}$")


# ---------- infraestrutura WinRM ----------
def _session(host: str, timeout: int = 60) -> winrm.Session:
    if not HOST_RE.match(host):
        raise ValueError("Hostname inválido")
    if ALLOWED and host.lower() not in ALLOWED:
        raise ValueError(f"Host '{host}' fora da allowlist WINRM_ALLOWED_HOSTS")
    use_ssl = os.getenv("WINRM_SSL", "false").lower() == "true"
    scheme, port = ("https", 5986) if use_ssl else ("http", 5985)
    return winrm.Session(
        f"{scheme}://{host}:{port}/wsman",
        auth=(os.environ["WINRM_USER"], os.environ["WINRM_PASSWORD"]),
        transport=os.getenv("WINRM_TRANSPORT", "ntlm"),
        server_cert_validation=os.getenv("WINRM_VALIDATE_CERT", "validate"),
        operation_timeout_sec=timeout,
        read_timeout_sec=timeout + 30,
    )


DATE_RE = re.compile(r"\\/Date\((-?\d+)(?:[+-]\d+)?\)\\/")


def _ps(host: str, script: str, timeout: int = 60):
    """Executa PowerShell e devolve JSON já parseado (datas convertidas para ISO 8601 UTC)."""
    r = _session(host, timeout).run_ps("$ErrorActionPreference='Stop'\n" + script)
    if r.status_code != 0:
        return {"error": r.std_err.decode(errors="replace")[:2000]}
    out = r.std_out.decode(errors="replace").strip()
    out = DATE_RE.sub(
        lambda m: datetime.fromtimestamp(int(m.group(1)) / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), out)
    if not out:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"raw": out[:20000]}


def _ps_long(host: str, script: str, timeout: int = 300):
    """Para scripts grandes: a linha de comando do WinRM aceita ~8 KB, então o script é enviado em pedaços
    para um arquivo temporário em %TEMP%, executado e apagado em seguida (nada mais é alterado no servidor)."""
    s = _session(host, 60)
    f = rf"$env:TEMP\mcp_{uuid.uuid4().hex[:12]}.b64"
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    try:
        for i in range(0, len(b64), 2400):
            r = s.run_ps(f"Add-Content -LiteralPath \"{f}\" -Value '{b64[i:i + 2400]}' -NoNewline -Encoding ASCII")
            if r.status_code != 0:
                return {"error": r.std_err.decode(errors="replace")[:2000]}
        return _ps(host, rf"""
$f = "{f}"
try {{ $code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([IO.File]::ReadAllText($f))) }}
finally {{ Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }}
Invoke-Expression $code
""", timeout)
    finally:
        try:
            s.run_ps(f'Remove-Item -LiteralPath "{f}" -Force -ErrorAction SilentlyContinue')
        except Exception:
            pass


def _ints(values) -> str:
    return ",".join(str(int(v)) for v in values)


# ---------- tools ----------
@mcp.tool
def get_system_overview(host: str):
    """Versão do SO, uptime, último boot, CPU/RAM total e domínio."""
    return _ps(host, r"""
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
[pscustomobject]@{
  Host=$env:COMPUTERNAME; OS=$os.Caption; Build=$os.BuildNumber
  LastBoot=$os.LastBootUpTime; UptimeHours=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours,1)
  Domain=$cs.Domain; Sockets=$cs.NumberOfProcessors; LogicalCPUs=$cs.NumberOfLogicalProcessors
  RAM_GB=[math]::Round($cs.TotalPhysicalMemory/1GB,1)
  FreeRAM_GB=[math]::Round($os.FreePhysicalMemory/1MB,1)
} | ConvertTo-Json -Compress
""")


@mcp.tool
def get_performance_snapshot(host: str):
    """Snapshot de CPU, memória, paginação, fila de CPU e latência/fila de disco.
    Usa classes CIM (independe do idioma do Windows, ao contrário do Get-Counter)."""
    return _ps(host, r"""
$cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor | ? Name -eq '_Total'
$mem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
$sys = Get-CimInstance Win32_PerfFormattedData_PerfOS_System
$dsk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk | ? Name -eq '_Total'
[pscustomobject]@{
  CpuPct=$cpu.PercentProcessorTime; CpuPrivilegedPct=$cpu.PercentPrivilegedTime
  CpuInterruptPct=$cpu.PercentInterruptTime; ProcessorQueue=$sys.ProcessorQueueLength
  ContextSwitchesSec=$sys.ContextSwitchesPersec
  MemAvailableMB=$mem.AvailableMBytes; MemCommittedPct=$mem.PercentCommittedBytesInUse
  PagesPerSec=$mem.PagesPersec; PoolNonpagedMB=[math]::Round($mem.PoolNonpagedBytes/1MB,1)
  DiskReadMs=[math]::Round($dsk.AvgDisksecPerRead*1000,2)
  DiskWriteMs=[math]::Round($dsk.AvgDisksecPerWrite*1000,2)
  DiskQueue=$dsk.CurrentDiskQueueLength; DiskIOPS=$dsk.DiskTransfersPersec
} | ConvertTo-Json -Compress
""")


@mcp.tool
def get_top_processes(host: str, sort_by: str = "cpu", top: int = 15):
    """Top processos por 'cpu' ou 'memory' (valores instantâneos)."""
    key = "PercentProcessorTime" if sort_by == "cpu" else "WorkingSetPrivate"
    return _ps(host, rf"""
Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
  ? {{ $_.Name -notin '_Total','Idle' }} | sort {key} -desc | select -first {int(top)} |
  select Name,IDProcess,PercentProcessorTime,
    @{{n='PrivateMB';e={{[math]::Round($_.WorkingSetPrivate/1MB,1)}}}},ThreadCount,HandleCount |
  ConvertTo-Json -Compress
""")


@mcp.tool
def get_events(
    host: str,
    log_name: str = "System",
    hours: int = 24,
    levels: list[int] = [1, 2, 3],
    event_ids: list[int] | None = None,
    provider: str | None = None,
    max_events: int = 50,
):
    """Eventos do Event Viewer. levels: 1=Crítico, 2=Erro, 3=Aviso, 4=Info."""
    if not NAME_RE.match(log_name) or (provider and not NAME_RE.match(provider)):
        raise ValueError("log_name/provider inválido")
    flt = f"LogName='{log_name}'; StartTime=(Get-Date).AddHours(-{int(hours)}); Level={_ints(levels)}"
    if event_ids:
        flt += f"; Id={_ints(event_ids)}"
    if provider:
        flt += f"; ProviderName='{provider}'"
    return _ps(host, rf"""
Get-WinEvent -FilterHashtable @{{{flt}}} -MaxEvents {min(int(max_events), 200)} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,LevelDisplayName,ProviderName,
    @{{n='Message';e={{($_.Message -replace '\s+',' ').Substring(0,[math]::Min(500,$_.Message.Length))}}}} |
  ConvertTo-Json -Compress
""")


@mcp.tool
def get_event_summary(host: str, hours: int = 24):
    """Agrupa erros/críticos de System e Application por provedor+ID (ótimo ponto de partida da RCA)."""
    return _ps(host, rf"""
$since=(Get-Date).AddHours(-{int(hours)})
foreach($l in 'System','Application'){{
  Get-WinEvent -FilterHashtable @{{LogName=$l;StartTime=$since;Level=1,2}} -ErrorAction SilentlyContinue |
    group ProviderName,Id | sort Count -desc | select -first 15 |
    select @{{n='Log';e={{$l}}}},Count,Name,
      @{{n='First';e={{($_.Group|sort TimeCreated|select -first 1).TimeCreated}}}},
      @{{n='Last';e={{($_.Group|sort TimeCreated|select -last 1).TimeCreated}}}}
}} | ConvertTo-Json -Compress
""")


@mcp.tool
def get_reboot_and_crash_history(host: str, days: int = 30):
    """Reboots, desligamentos inesperados e BSOD (IDs 41, 1001, 1074, 1076, 6005, 6006, 6008)."""
    return _ps(host, rf"""
Get-WinEvent -FilterHashtable @{{LogName='System';StartTime=(Get-Date).AddDays(-{int(days)});Id=41,1001,1074,1076,6005,6006,6008}} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,ProviderName,
    @{{n='Message';e={{($_.Message -replace '\s+',' ').Substring(0,[math]::Min(400,$_.Message.Length))}}}} |
  ConvertTo-Json -Compress
""")


@mcp.tool
def get_stopped_auto_services(host: str):
    """Serviços com início automático que não estão em execução."""
    return _ps(host, r"""
Get-CimInstance Win32_Service | ? { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } |
  select Name,DisplayName,State,ExitCode,StartName | ConvertTo-Json -Compress
""")


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
def get_pending_updates(host: str):
    """Updates pendentes (não instalados) segundo o agente do Windows Update / WSUS.
    Obs.: a API COM do WUA pode retornar 'Access denied' em sessões remotas WinRM;
    nesse caso use get_patch_status + get_windows_update_history."""
    return _ps(host, r"""
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
def get_windows_update_history(host: str, days: int = 60):
    """Histórico de instalação/falha de updates (WindowsUpdateClient: 19=sucesso, 20=falha, 21=reboot necessário)."""
    return _ps(host, r"""
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';
  StartTime=(Get-Date).AddDays(-__D__);Id=19,20,21} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,
    @{n='Message';e={($_.Message -replace '\s+',' ').Substring(0,[math]::Min(400,$_.Message.Length))}} |
  ConvertTo-Json -Compress
""".replace("__D__", str(int(days))))


# ---------- serviços ----------
SVC_RE = re.compile(r"^[A-Za-z0-9*._-]{1,100}$")


@mcp.tool
def get_services(
    host: str,
    name_filter: str = "*",
    state: str | None = None,
    start_mode: str | None = None,
):
    """Lista serviços (wildcard em nome/display name). state: Running|Stopped; start_mode: Auto|Manual|Disabled."""
    if not SVC_RE.match(name_filter):
        raise ValueError("name_filter inválido")
    if state not in (None, "Running", "Stopped") or start_mode not in (None, "Auto", "Manual", "Disabled"):
        raise ValueError("state/start_mode inválido")
    extra = (f" -and $_.State -eq '{state}'" if state else "") + (
        f" -and $_.StartMode -eq '{start_mode}'" if start_mode else ""
    )
    return _ps(host, rf"""
Get-CimInstance Win32_Service |
  ? {{ ($_.Name -like '{name_filter}' -or $_.DisplayName -like '{name_filter}'){extra} }} |
  select Name,DisplayName,State,StartMode,StartName,ProcessId,ExitCode,PathName |
  ConvertTo-Json -Compress
""")


@mcp.tool
def get_service_failures(host: str, hours: int = 72):
    """Falhas de serviços no SCM (7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7032, 7034)."""
    return _ps(host, rf"""
Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='Service Control Manager';
  StartTime=(Get-Date).AddHours(-{int(hours)});Id=7000,7001,7009,7011,7022,7023,7024,7026,7031,7032,7034}} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,
    @{{n='Message';e={{($_.Message -replace '\s+',' ').Substring(0,[math]::Min(400,$_.Message.Length))}}}} |
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


@mcp.tool
def get_installed_software(host: str, name_filter: str = "*"):
    """Software instalado (registro de Uninstall, 64 e 32 bits)."""
    if not SVC_RE.match(name_filter):
        raise ValueError("name_filter inválido")
    return _ps(host, rf"""
$p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $p -ErrorAction SilentlyContinue | ? {{ $_.DisplayName -like '{name_filter}' }} |
  sort DisplayName | select DisplayName,DisplayVersion,Publisher,InstallDate | ConvertTo-Json -Compress
""")


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


@mcp.tool
def get_time_sync_status(host: str):
    """Status do w32time (fonte, último sync, offset). Desvio de hora quebra Kerberos/AD."""
    return _ps(host, r"""
[pscustomobject]@{
  Source=(w32tm /query /source | Out-String).Trim()
  Status=(w32tm /query /status | Out-String).Trim()
} | ConvertTo-Json -Compress
""")


@mcp.tool
def get_expiring_certificates(host: str, days_threshold: int = 60):
    """Certificados do repositório LocalMachine\\My vencidos ou que vencem em até N dias."""
    return _ps(host, r"""
Get-ChildItem Cert:\LocalMachine\My |
  select Subject,Thumbprint,NotAfter,HasPrivateKey,
    @{n='DaysLeft';e={[int]($_.NotAfter-(Get-Date)).TotalDays}} |
  ? { $_.DaysLeft -le __D__ } | sort DaysLeft | ConvertTo-Json -Compress
""".replace("__D__", str(int(days_threshold))))


# ---------- saúde do CBS e do Windows Update (erros escondidos na aplicação de patches) ----------
HEX_RE = re.compile(r"0x[0-9A-Fa-f]{8}")
WU_HINTS = {
    "0x80073712": "Component store corrompido/arquivo ausente (CBS). Rodar DISM /RestoreHealth.",
    "0x80073701": "Assembly ausente no component store (CBS). Rodar DISM /RestoreHealth.",
    "0x800f081f": "Arquivos-fonte não encontrados (CBS). DISM /RestoreHealth com fonte válida.",
    "0x800f0831": "Store corrompido ou pré-requisito (KB anterior) ausente.",
    "0x800f0922": "Falha genérica de instalação; comum: pouco espaço na System Reserved/EFI, corrupção CBS, rollback.",
    "0x80070070": "Disco cheio.",
    "0x80070005": "Acesso negado (permissões, antivírus, TrustedInstaller).",
    "0x80070002": "Arquivo não encontrado (cache do WU/CBS).",
    "0x8007000d": "Dados inválidos (cache do WU ou store corrompido).",
    "0x80070bc9": "Reboot pendente impedindo a instalação.",
    "0x800705b4": "Timeout na operação.",
    "0x80240034": "Falha no download do update.",
    "0x80246007": "Update não foi baixado.",
    "0x8024402c": "Falha de resolução de nome/proxy/WSUS.",
    "0x80244022": "Serviço WSUS/Microsoft indisponível (HTTP 503).",
}
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
    res = _ps(host, r"""
$ErrorActionPreference='Continue'
$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
$out = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1; $code = $LASTEXITCODE
$dism = ($out | Out-String).Trim()
$cbs = Get-ChildItem "$env:SystemRoot\Logs\CBS" -Force -ErrorAction SilentlyContinue
[pscustomobject]@{
  DismCheckHealth=$dism; DismExitCode=$code
  PendingXmlExists=(Test-Path "$env:SystemRoot\WinSxS\pending.xml")
  RebootPending=(Test-Path "$k\RebootPending"); RebootInProgress=(Test-Path "$k\RebootInProgress")
  PackagesPending=(Test-Path "$k\PackagesPending"); SessionsPending=(Test-Path "$k\SessionsPending")
  TrustedInstaller=(Get-Service TrustedInstaller | select Status,StartType)
  CbsLogDir_MB=[math]::Round((($cbs | measure Length -Sum).Sum)/1MB,1)
  CbsLog_LastWrite=($cbs | ? Name -eq 'CBS.log' | select -first 1).LastWriteTime
} | ConvertTo-Json -Depth 3 -Compress
""", timeout=120)
    if isinstance(res, dict) and "DismCheckHealth" in res:
        txt = res["DismCheckHealth"] or ""
        res["Heuristic_StoreRepairable"] = bool(re.search(r"repairable|repar[aá]vel", txt, re.I))
        res["Heuristic_Healthy"] = res["DismExitCode"] == 0 and not res["Heuristic_StoreRepairable"]
    return res


@mcp.tool
def get_component_store_analysis(host: str):
    """DISM /AnalyzeComponentStore: tamanho real do WinSxS, espaço recuperável e se limpeza é recomendada.
    Somente leitura, mas pode levar de 1 a 3 minutos."""
    return _ps(host, r"""
$ErrorActionPreference='Continue'
$out = & dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1; $code = $LASTEXITCODE
[pscustomobject]@{ ExitCode=$code; Output=(($out | Out-String).Trim()) } | ConvertTo-Json -Compress
""", timeout=300)


@mcp.tool
def get_cbs_log_errors(host: str, tail_lines: int = 20000, max_matches: int = 40):
    """Erros recentes no CBS.log (HRESULTs 0x800f/0x8007, 'Cannot repair', 'corrupt', 'failed').
    Revela corrupção e falhas de patch que não aparecem no Event Viewer."""
    return _ps(host, r"""
$log = "$env:SystemRoot\Logs\CBS\CBS.log"
if(-not (Test-Path -LiteralPath $log)){ [pscustomobject]@{Error='CBS.log não encontrado'} | ConvertTo-Json -Compress; return }
$lines = Get-Content -LiteralPath $log -Tail __T__ -ErrorAction Stop
$m = @($lines | ? { $_ -match 'Error|0x800f|0x8007|0x8002|corrupt|Cannot repair|failed|HRESULT' })
[pscustomobject]@{
  LinesScanned=$lines.Count; TotalMatches=$m.Count
  CannotRepairCount=@($lines | ? { $_ -match 'Cannot repair' }).Count
  CorruptCount=@($lines | ? { $_ -match 'corrupt' }).Count
  Matches=@($m | select -last __M__ | % { $_.Substring(0,[math]::Min(300,$_.Length)) })
} | ConvertTo-Json -Depth 3 -Compress
""".replace("__T__", str(min(int(tail_lines), 100000))).replace("__M__", str(min(int(max_matches), 200))), timeout=120)


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
def get_update_error_analysis(host: str, days: int = 90):
    """Falhas de instalação/download de updates agrupadas por código de erro (HRESULT), com causa provável."""
    ev = _ps(host, r"""
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';
  StartTime=(Get-Date).AddDays(-__D__);Id=20,31} -ErrorAction SilentlyContinue |
  select TimeCreated,Id,
    @{n='Message';e={($_.Message -replace '\s+',' ').Substring(0,[math]::Min(500,$_.Message.Length))}} |
  ConvertTo-Json -Compress
""".replace("__D__", str(int(days))), timeout=120)
    if isinstance(ev, dict) and "Id" not in ev:
        return ev  # erro ou saída crua
    events = _lst(ev)
    agg = {}
    for e in events:
        for code in {c.lower() for c in HEX_RE.findall(e.get("Message") or "")}:
            a = agg.setdefault(code, {"error_code": code, "count": 0, "last_seen": None,
                                      "hint": WU_HINTS.get(code, "Código sem dica local; pesquisar o HRESULT.")})
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
):
    """Análise de espaço estilo TreeSize, em uma única passada rápida (API nativa FindFirstFileEx + paralelismo).
    Retorna: árvore de pastas até 'depth' níveis (maiores filhos, % do total), maiores arquivos, uso por extensão,
    volume de dados sem modificação há 'old_days' dias e contagem de acessos negados. Tamanhos são lógicos.
    Se estourar scan_timeout_s devolve resultado parcial (partial=true). Exige Add-Type (C#) liberado no servidor."""
    p = _path(path)
    depth = max(1, min(int(depth), 6))
    args = (f"'{p}', {depth}, {max(3, min(int(top_children), 30))}, {max(5, min(int(top_files), 100))}, "
            f"{max(1, int(min_file_size_mb)) * 1048576}, {max(1, min(int(threads), 16))}, "
            f"{max(30, min(int(scan_timeout_s), 1500))}, {max(1, int(old_days))}")
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
    espaço não alocado, partições sem letra/ponto de montagem e volumes muito subutilizados (possível desperdício)."""
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
            findings.append(f"{tag}: OFFLINE – capacidade alocada sem uso (candidato a reclamação).")
        elif d["Partitioning"] == "RAW":
            findings.append(f"{tag}: não inicializado (RAW) – alocado e nunca utilizado.")
        elif d["UnallocatedGB"] >= 1:
            findings.append(f"{tag}: {d['UnallocatedGB']} GB não alocados.")
        if d["Health"] != "Healthy":
            findings.append(f"{tag}: HealthStatus = {d['Health']}.")
    for p in _lst(data["Partitions"]):
        if p["Type"] == "Basic" and not p["DriveLetter"] and not _lst(p["MountPaths"]):
            findings.append(f"Disco {p['DiskNumber']} partição {p['PartitionNumber']} ({p['SizeGB']} GB): "
                            "sem letra nem ponto de montagem – dados inacessíveis/possível desperdício.")
    for v in _lst(data["Volumes"]):
        if v["SizeGB"] and v["SizeGB"] >= 100 and (v["FreePct"] or 0) >= 90:
            findings.append(f"Volume {v['DriveLetter'] or v['FileSystemLabel']}: {v['SizeGB']} GB com "
                            f"{v['FreePct']}% livre – subutilizado (candidato a right-sizing).")
    data["Findings"] = findings or ["Nenhuma anomalia de alocação encontrada."]
    return data


@mcp.prompt
def root_cause_analysis(host: str, symptom: str) -> str:
    """Roteiro de RCA para um sintoma em um servidor."""
    return (
        f"Faça análise de causa raiz no servidor {host}. Sintoma: {symptom}.\n"
        "1) get_system_overview e get_reboot_and_crash_history; 2) get_performance_snapshot e "
        "get_top_processes; 3) get_event_summary e depois get_events nos IDs/provedores suspeitos; "
        "4) get_disks, get_stopped_auto_services e get_recent_hotfixes para correlação. "
        "Monte uma linha do tempo, separe fatos de hipóteses, aponte a causa mais provável "
        "e a evidência que a sustenta."
    )


@mcp.prompt
def ops_health_check(host: str) -> str:
    """Health check operacional completo de um Windows Server."""
    return (
        f"Faça um health check operacional do servidor {host}: get_system_overview, "
        "get_patch_status (+ get_pending_updates e get_windows_update_history), "
        "get_performance_snapshot, get_disks, get_stopped_auto_services e get_service_failures, "
        "get_roles_and_features, get_security_posture, get_time_sync_status e "
        "get_expiring_certificates. Inclua a saúde do CBS/Windows Update (get_cbs_health, "
        "get_cbs_log_errors, get_windows_update_health, get_update_error_analysis) e o disco "
        "(get_common_space_offenders, get_disk_allocation_analysis e, nos volumes com pouco espaço, "
        "get_disk_usage_tree). Entregue um resumo com status (OK/Atenção/Crítico) por área, "
        "os achados priorizados e as ações recomendadas."
    )


if __name__ == "__main__":
    mcp.run()  # stdio; para HTTP: mcp.run(transport="http", host="0.0.0.0", port=8000)
