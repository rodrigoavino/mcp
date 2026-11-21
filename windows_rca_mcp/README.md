# windows-rca-mcp: MCP de OPS para Windows Server

## Missão

Dar a um assistente de IA (Claude Code, Claude Desktop ou qualquer cliente MCP) **visão operacional completa de servidores Windows Server**, de forma **segura e somente leitura**. O assistente consegue triar incidentes, fazer health check e análise de causa raiz (RCA) sem um operador precisar abrir RDP, Event Viewer, Gerenciador de Tarefas, `dism` etc.

Foco em **OPS**: eventos, disco, performance, serviços, roles/features, patches, saúde do CBS/Windows Update, uptime, rede, tarefas agendadas e sessões/segurança de logon.

## Arquitetura

```
Claude / cliente MCP ──(stdio ou HTTP)──► FastMCP (este projeto)
                                              │  pywinrm (NTLM/Kerberos)
                                              ▼
                               WinRM HTTPS :5986  ──►  Windows Server alvo
                                                       (scripts PowerShell fixos, somente leitura → JSON)
```

- Cada tool executa um **script PowerShell fixo**, parametrizado só com valores validados (hostname, inteiros, nomes e caminhos passam por regex). Não existe tool de "executar comando".
- A saída é JSON. As datas ISO saem em **GMT-3** (`-03:00`, fixo, sem horário de verão); só a apresentação muda, o servidor segue em UTC. Ajuste com `MCP_TZ_OFFSET_HOURS` (padrão `-3`); datas sentinela (ano < 1900) e textos livres de eventos ficam como estão.
- Falhas de conexão, autenticação ou SSL voltam como `{"error": ..., "host": ...}` e não derrubam o servidor MCP.

## Estrutura

```
windows_rca_mcp/
├── src/windows_rca_mcp/
│   ├── __init__.py      # main(): inicia o servidor (stdio ou http)
│   ├── server.py        # todas as tools e prompts
│   └── diskscan.cs      # scanner de disco (C#) usado por get_disk_usage_tree
├── teste.py             # chama qualquer tool pela linha de comando
├── .env.example         # modelo de configuração
├── pyproject.toml / uv.lock
└── README.md
```

## Pré-requisitos

### Máquina que roda o MCP
- Python ≥ 3.12 e [uv](https://docs.astral.sh/uv/).
- Acesso de rede à porta **5986/TCP** dos servidores alvo.

### Servidor Windows alvo
1. **Listener WinRM HTTPS na 5986**, com certificado emitido pela CA interna para o FQDN do servidor:
   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\My | ? { $_.Subject -like "*$env:COMPUTERNAME*" } | select -first 1
   New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -HostName ([Net.Dns]::GetHostEntry('').HostName) -Force
   New-NetFirewallRule -Name WinRM-HTTPS-In -DisplayName 'WinRM HTTPS (5986)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
   ```
   Em **laboratório** dá para usar certificado autoassinado (`New-SelfSignedCertificate -DnsName <fqdn> -CertStoreLocation Cert:\LocalMachine\My`) com `WINRM_VALIDATE_CERT=ignore`.
2. **Conta de serviço** dedicada:
   - Mínimo: grupos `Remote Management Users` + `Event Log Readers` + `Performance Monitor Users`.
   - Para DISM/CBS (`get_cbs_health`, `validate_cbs`, `get_component_store_analysis`), `Get-WindowsFeature`, log Security (`get_failed_logons`) e leitura completa de disco, é preciso **administrador local**.
3. Para `get_disk_usage_tree`: `Add-Type` (compilação C#) liberado, ou seja, sem bloqueio de AppLocker/WDAC/Constrained Language. Se não puder, use `get_largest_folders`/`get_largest_files`.

## Configuração

Copie `.env.example` para `.env` e preencha (o `.env` está no `.gitignore`):

| Variável | Padrão | Descrição |
|---|---|---|
| `WINRM_USER` / `WINRM_PASSWORD` | (obrigatório) | Credencial (`DOMINIO\usuario` ou `usuario@dominio`) |
| `WINRM_TRANSPORT` | `ntlm` | `ntlm` · `kerberos` · `credssp` · `basic` |
| `WINRM_SSL` | `true` | `true` = HTTPS; `false` = HTTP |
| `WINRM_PORT` | `5986` (SSL) / `5985` | Só defina para porta não padrão. Se ficar comentada, a porta segue o `WINRM_SSL` |
| `WINRM_VALIDATE_CERT` | `validate` | `ignore` **só em laboratório** |
| `WINRM_ALLOWED_HOSTS` | **(obrigatória)** | Allowlist separada por vírgula, com curingas (`*.dominio.local,srv01`). **Vazia = nenhum host** (fail-closed). `*` libera tudo: use só conscientemente |
| `WINRM_ENV_FILE` | (vazio) | Caminho explícito do `.env`, se ele não estiver no diretório de trabalho |
| `MCP_TRANSPORT` | `stdio` | `stdio` (Claude Code/Desktop) · `http` (deploy remoto) |
| `MCP_HOST` / `MCP_PORT` | `127.0.0.1` / `8000` | Endereço no modo `http` |
| `MCP_AUTH_TOKEN` | (vazio) | **Obrigatório no modo `http`**: token Bearer com 32 ou mais caracteres |
| `MCP_ALLOW_INSECURE_LOOPBACK` | `false` | `true` permite `http` sem token, **somente em loopback** (testes) |
| `MCP_AUDIT` | `on` | `off` desliga o log de auditoria |
| `MCP_AUDIT_LOG` | `<projeto>/logs/audit.jsonl` | Arquivo do log de auditoria (rotação 5 MB x 5) |

O `.env` é lido do **diretório de trabalho** do processo (por isso o Claude usa `uv --directory <pasta do projeto>`) ou do caminho em `WINRM_ENV_FILE`.

## Instalação e execução

```powershell
cd C:\mcp\windows_rca_mcp
uv sync
uv run windows-rca-mcp                       # stdio
# HTTP em 127.0.0.1:8000/mcp (exige token)
$env:MCP_TRANSPORT='http'; $env:MCP_AUTH_TOKEN = (uv run python -c "import secrets;print(secrets.token_urlsafe(32))")
uv run windows-rca-mcp
```

Teste rápido de uma tool pela linha de comando:

```powershell
uv run python teste.py get_health_summary host=srv01.dominio.local
uv run python teste.py get_events host=srv01 log_name=System days=3 "levels=[1,2]"
uv run python teste.py test_connectivity host=srv01 target=dc01.dominio.local port=389
```

## Integração com o Claude Code

```powershell
claude mcp add windows-ops --scope user -- uv --directory C:\mcp\windows_rca_mcp run windows-rca-mcp
claude mcp list
```

Depois é só pedir em linguagem natural, por exemplo: *"faça um health check do srv01"*, *"por que o srv02 reiniciou ontem?"*, *"o CBS do srv03 está quebrado?"*. Também dá para usar os prompts prontos `ops_health_check` e `root_cause_analysis`.

**Claude Desktop** (`claude_desktop_config.json`):
```json
{ "mcpServers": { "windows-ops": {
  "command": "uv",
  "args": ["--directory", "C:\\mcp\\windows_rca_mcp", "run", "windows-rca-mcp"] } } }
```

## Deploy em outro ambiente

1. Copie a pasta (sem `.venv` e `.env`), ou gere o pacote com `uv build` e instale o `.whl`.
2. Crie o `.env` do ambiente, com uma conta de serviço própria, `WINRM_VALIDATE_CERT=validate` e `WINRM_ALLOWED_HOSTS` preenchido. O `.env` precisa estar no diretório de onde o serviço é iniciado; senão, aponte `WINRM_ENV_FILE` para ele.
3. Para uso compartilhado, rode em modo HTTP (`MCP_TRANSPORT=http`) com **`MCP_AUTH_TOKEN`** definido; sem token o servidor não inicia. Se expor fora do host (`MCP_HOST=0.0.0.0`), coloque **TLS na frente** (proxy reverso), porque o token trafega no cabeçalho `Authorization`.
4. Registre no cliente, enviando o token:
   `claude mcp add --transport http windows-ops https://<host>/mcp --header "Authorization: Bearer <token>"`.

## Catálogo de tools (54)

Todas recebem `host` (nome ou FQDN do servidor alvo).

### Padrão de resposta (envelope)
Toda tool responde no mesmo formato mínimo, e o conteúdo vai **só** em `data`:

```json
{ "computerName": "FASTMCP", "timestamp": "2026-11-20T20:00:00Z", "success": true, "data": {} }
```

- **Análises completas** (painel de saúde etc.) acrescentam `os` e `summary` (`status` e quantidade de `findings`); os achados ficam em `data`.
- **`moreAvailable`** (opcional) é **uma linha** que apenas sugere o que mais pode ser obtido. O coletor não coleta nada além do perguntado.
- **Falha:** `{ "computerName", "timestamp", "success": false, "error": "..." }`. Erros de uso (host inválido, fora da allowlist) continuam como erro do MCP.
- **Não entram por padrão** (boot, uptime, disco, CPU, memória, serviços, usuários, eventos, volumes, adaptadores de rede): só se a pergunta pedir, se forem necessários para responder ou se forem erro/diagnóstico relacionado.
- O envelope é aplicado na **fronteira do MCP** (middleware do FastMCP), então as funções Python e as chamadas internas entre tools seguem devolvendo o dado cru, e toda tool nova já nasce no padrão.
- O MCP entrega ao Claude, ao conectar, as **instruções** desse padrão (responder só o perguntado e sugerir o resto, usar o filtro mais estreito, só fatos, carga só com evidência, data de instalação só local, nada inventado).

### Data de instalação de software (fato local)
`get_installed_software` determina a data **só com evidência local do host, nunca internet ou documentação**, nesta ordem, e informa a confiança:

| Prioridade | Fonte | `source` | `confidence` |
|---|---|---|---|
| 1 | `InstallDate` no registro Uninstall (HKLM 64 e 32 bits) | `Registry` | `high` |
| 2 | Instalação por usuário (HKCU e HKEY_USERS carregados) | `Registry` (com `scope`) | `high` (se tiver `InstallDate`) |
| 3 | Eventos `MsiInstaller` 1033 (status 0) e 11707 | `MsiInstaller` | `medium` |
| 4 | Package Management (só se o provedor expuser data; o provedor `Programs` não expõe) | `PackageManagement` | `medium` |
| 5 | `CreationTime` da pasta do produto, senão do executável | `FileSystem` | `low` |

- O evento **11724 não é usado**: pelo que se sabe é de remoção, e não há nenhum no servidor de teste para confirmar.
- A correspondência de evento com programa é por **nome igual** (ignorando arquitetura e versão no fim); nunca por prefixo.
- Hives de outros usuários **não carregados** não são lidos (carregá-los seria alterar o servidor).
- `installed_since_days` (0 = hoje, 1 = hoje e ontem, dias de calendário do servidor) devolve **só** os programas do período; `get_last_patches` tem o mesmo parâmetro e o `Get-HotFix` informa só a data, não a hora.

### Padrão de coleta de logs (foco em problema, análise rápida)
- **Event Viewer:** só **Crítico (1), Erro (2) e Aviso (3)**. Informativos ficam de fora, a não ser que `levels=[4]` seja pedido explicitamente.
- **Período padrão: `days=1`** (último dia) em todas as tools de log: `get_events`, `get_event_summary`, `get_reboot_and_crash_history`, `get_service_failures`, `get_windows_update_history`, `get_update_error_analysis`, `get_cbs_log_errors`, `validate_cbs`, `get_applied_gpos`, `get_failed_logons` e `get_cluster_health`. Para analisar mais dias, informe `days` (máximo 90).
- **Logs de servicing** (CBS.log, CbsPersist_*.log, dism.log): mesma regra. São lidas só as linhas Error/Warning e as Info com HRESULT de falha, "Cannot repair" ou "corrupt", dentro do período. Mensagens repetidas são **agrupadas** (números normalizados) e os HRESULTs mais frequentes vêm com dica. Arquivos `.cab` compactados são ignorados.
- **Dois modos de busca nos logs de texto (CBS/DISM).** `get_cbs_log_errors` e `validate_cbs` aceitam `mode`/`log_mode`:
  - `rapida` (padrão): só sinais de erro (nível Error, HRESULT 0x8..., Cannot repair, corrupt, `(F)`), últimos 128 MB de cada arquivo, até 20 s. Responde em poucos segundos.
  - `detalhada`: também Warning, Failed, Missing, 0x800..., período inteiro, até 300 s.
  - Como é rápido: pré-filtro por palavra-chave com `IndexOf` (sem processar linha a linha), salto direto ao início do período por busca binária de data e classificação precisa só das linhas candidatas, descartando ruído conhecido.
  - Se a leitura não cobrir tudo, a resposta traz `Coverage='parcial'`, `Note` e uma `Recommendation` com o comando e o tempo estimado da busca detalhada.
- **Event Viewer lido direto do log** (`EventLogReader` + filtro XPath, sem renderizar mensagens): a mensagem só é montada para a amostra de cada grupo. Logs que não existem no servidor são ignorados e listados em `skipped_logs`.
- **Limites sinalizados.** O `get_event_summary` lê até 20.000 eventos por log e o `get_failed_logons` até 5.000. Se o limite for atingido, a resposta traz `truncated`/`Truncated=true`, informando que os totais são um limite inferior.
- O `get_event_summary` cobre System, Application e Setup. Com `include_operational=true`, inclui também GroupPolicy, WindowsUpdateClient, TaskScheduler, RDS, SMBClient, Time-Service, FailoverClustering e DNS-Client.

### Triagem rápida
| Tool | O que faz |
|---|---|
| `get_health_summary` | **Comece por aqui.** Faz uma única chamada e devolve `sem_sinais` / `sinais_presentes` / `verificacao_incompleta` para CPU, memória, disco, serviços, patches, disponibilidade e eventos, com o limiar do projeto à vista (parametrizável). Sem severidade nem recomendação. |
| `get_uptime` | Último boot, uptime, último shutdown planejado (quem/por quê, evento 1074), se o último boot foi inesperado e desligamentos inesperados em 30 dias |
| `get_system_overview` | SO, build, domínio, CPU/RAM, uptime |

### Performance
| Tool | O que faz |
|---|---|
| `get_performance_snapshot` | CPU, fila de CPU, memória, paginação, pool não paginado, latência e fila de disco |
| `get_top_resource_consumers` | **Processos que mais consomem CPU e memória, medidos por amostragem** (delta de CPU em N segundos), com dono, serviços hospedados, horário de início e linha de comando |
| `get_top_processes` | Top processos por `cpu` ou `memory` (leitura instantânea, mais rápida) |

### Eventos
| Tool | O que faz |
|---|---|
| `get_event_summary` | **Ponto de partida da RCA.** Crítico/Erro/Aviso agrupados por log + nível + provedor + ID, com totais, primeira/última ocorrência e mensagem de exemplo |
| `get_events` | Consulta filtrada (log, `days`, níveis, IDs, provedor) |
| `get_reboot_and_crash_history` | Reboots, shutdowns inesperados e BSOD |

### Serviços, roles e software
| Tool | O que faz |
|---|---|
| `get_services` | Lista com filtros (nome/wildcard, estado, tipo de início) |
| `get_stopped_auto_services` | Serviços automáticos parados, **só fatos** por serviço: estado, código de saída (e o específico), conta, início atrasado (`Delayed`), início por gatilho (`Trigger`) e se nunca iniciou desde o boot (código 1077, que não é falha). Sinais: `failedExitCode` (diferente de 0 e de 1077) e `transitionalState` (diferente de `Stopped`). **Não** classifica como esperado ou suspeito: o estado esperado de cada serviço é interpretação do RAG |
| `get_service_failures` | Falhas do Service Control Manager (eventos 70xx) |
| `get_server_roles` | **Roles instaladas em hierarquia** (role → role services), features e estado dos serviços das roles principais (AD DS, DNS, DHCP, IIS, Hyper-V, Cluster, DFS, RDS, WSUS, AD CS…) |
| `get_roles_and_features` | Lista plana de roles e features (inclui as não instaladas com `only_installed=false`) |
| `get_installed_software` | Software instalado como no "Adicionar ou remover programas" (sem componentes de sistema nem atualizações; inclui instalações por usuário). Cada item: `name`, `version`, `installDate`, `confidence`, `source`. `installed_since_days` devolve só o período |
| `get_storage_overview` | **Discos**, só fatos: quantidade, modelo, tamanho, barramento (NVMe/SAS/SATA/SCSI/iSCSI/Virtual) e tipo de mídia (SSD/HDD/SCM) em campos **separados** (`Unspecified` quando o sistema não informa, ex.: disco virtual), GPT/MBR, básico/dinâmico (com a base da detecção), online/offline (+ motivo), somente leitura, saúde, bytes por setor lógico/físico (512n/512e/4Kn). Sinais: `diskOffline`, `diskReadOnly`, `diskNotHealthy`, `dynamicDiskPresent`, `mbrDiskAbove2TiB` (limiar do projeto). Serial e GUID do disco em `identifiers` |
| `get_volumes` | **Partições e volumes** ligados ao disco: letra e pontos de montagem, GUID do volume, rótulo, sistema de arquivos, tamanho do cluster (bytes), tamanho do volume e da partição, espaço livre (bytes e %), saúde, disco/partição/offset, tipo, somente leitura/oculta/ativa e BitLocker (proteção, estado, bloqueio, % criptografado, método, **tipos** de protetor; nunca senha nem chave de recuperação). BitLocker indisponível = `indeterminate`, nunca "desligado". Sinais: `freeSpaceBelowBaseline` (`low_free_pct`, padrão 15, limiar do projeto), `notHealthy`, `readOnly`, `bitLockerIndeterminate` |
| `get_platform_info` | **Plataforma**: físico, virtual (VMware, Hyper-V, KVM/QEMU, Xen, VirtualBox) ou nuvem (AWS, Azure, GCP), com a evidência usada (cadeias SMBIOS, agentes de guest, metadados). Físico: fabricante, modelo, BIOS, placa, chassi, CPU, sockets, núcleos e memória. `indeterminate` quando nada casa. O serviço de metadados da instância só é consultado se o SMBIOS indicar nuvem possível (`probe_cloud`), em campos de lista fixa, nunca credenciais nem user-data. `docs_context` traz rótulos genéricos para o RAG; `identifiers` (serial, UUID, id da instância) são sensíveis e não vão ao RAG |
| `get_license_status` | **Licenciamento do Windows, só fatos**: produto, canal da chave (GVLK, Retail, OEM), `LicenseStatus` (número do WMI), HRESULT do motivo, carência restante (min), fim de avaliação (null se não há), rearme, servidor KMS configurado e descoberto, contagens dos eventos Security-SPP (1014/8198/8200/16398) e desligamentos iniciados pelo `wlms.exe`. Não interpreta o status nem diz se a licença é válida: o significado é do RAG |
| `get_workload_evidence` | **Evidência do que o servidor executa**, sem presumir função: SO e versão, e por carga (SQL Server, IIS, Hyper-V, AD DS, DNS, DHCP, Failover Cluster) o serviço, processo, recurso do Windows, instância do SQL Server no registro (edição, versão, patch) ou software de servidor que a identifica. Cliente do SQL Server (SSMS, ODBC) não conta. `docs_context` lista só cargas com evidência e é o `context` aceitável para o RAG; sem evidência, vale só SO e versão |

### Patches, CBS e Windows Update
| Tool | O que faz |
|---|---|
| `get_last_patches` | Últimos patches aplicados (HotFix e Windows Update), build/UBR, dias desde o último patch. `installed_since_days` devolve só os patches do período (KB, descrição e data) |
| `get_patch_status` | Dias sem patch, WSUS, últimas detecção/instalação, reboot pendente |
| `get_recent_hotfixes` | Últimos KBs (Get-HotFix) |
| `get_pending_updates` | Updates pendentes (API do agente de Windows Update) |
| `get_windows_update_history` | Sucessos, falhas e reboots exigidos (eventos 19/20/21) |
| `get_update_error_analysis` | Falhas agrupadas por HRESULT, com causa provável |
| `validate_cbs` | **Verificação objetiva do CBS** (`sem_sinais` / `sinais_presentes` / `verificacao_incompleta`), com as evidências coletadas. Não recomenda ação |
| `get_cbs_health` | DISM /CheckHealth, pending.xml, flags de reboot, TrustedInstaller |
| `get_cbs_log_errors` | Problemas no CBS.log, CbsPersist e dism.log do período, **agrupados**, com contagem por nível e top HRESULTs com dica |
| `get_component_store_analysis` | DISM /AnalyzeComponentStore (1 a 3 min) |
| `get_windows_update_health` | Serviços do WU, tamanho do SoftwareDistribution/catroot2, proxy |

### Disco
| Tool | O que faz |
|---|---|
| `get_disks` | Volumes: tamanho, livre, % livre |
| `get_disk_usage_tree` | Árvore no estilo TreeSize (rápida, nativa, paralela): maiores pastas e arquivos, uso por extensão, dados antigos |
| `get_largest_folders` / `get_largest_files` | Alternativas em PowerShell puro (mais lentas) |
| `get_common_space_offenders` | Temp, cache do WU, logs do CBS/IIS, dumps, WER, lixeira, pagefile, VSS |
| `get_disk_allocation_analysis` | Discos offline, RAW, espaço não alocado, partições sem letra, volumes subutilizados |

### Rede
| Tool | O que faz |
|---|---|
| `get_network_config` | Adaptadores ativos: IPs, gateway, DNS, sufixos, DHCP, MAC, velocidade |
| `get_network_adapters` | **Configuração das placas de rede**: velocidade, duplex, MTU, VLAN, driver (versão/data), RSS, IPv6, erros e descartes, propriedades avançadas (offloads, jumbo, buffers), NIC Teaming/SET |
| `get_nic_teaming` | **NIC Teaming detalhado**: LBFO (modo, balanceamento, membros ativos/standby, falhas, VLANs) e SET do Hyper-V (membros, vNICs, VLAN), com alertas |
| `get_routes` | **Tabela de rotas** ativa, rotas persistentes e gateways padrão |
| `get_network_connections` | **Equivalente ao netstat -ano** com análise: conexões por estado, maiores destinos, processos com mais conexões, uso de portas efêmeras, alertas de TIME_WAIT/CLOSE_WAIT |
| `get_listening_ports` | Portas TCP (e UDP, com `include_udp`) em escuta, com processo e serviço |
| `test_connectivity` | **A partir do servidor**: resolução de nome, ping e teste de porta TCP até um destino |

### Failover Cluster
| Tool | O que faz |
|---|---|
| `get_cluster_health` | Se o servidor for nó de cluster: configuração (nível funcional, S2D, thresholds), quorum/witness, nós (estado, voto), roles (dono, nós preferidos), recursos com falha, redes e interfaces, CSVs (espaço, I/O redirecionado), pool S2D e erros recentes, com sinais objetivos (sem severidade). Fora de cluster, responde `Clustered=false` com o motivo. |

### Tarefas agendadas, GPO, sessões e segurança
| Tool | O que faz |
|---|---|
| `get_applied_gpos` | **GPOs aplicadas** ao computador e aos usuários com perfil carregado (nome, GUID, link), OU, site, DC, último processamento e erros/avisos do Group Policy |
| `get_scheduled_tasks` | Tarefas (fora de `\Microsoft\`) com último resultado em hex. `only_failed=True` por padrão |
| `get_user_sessions` | Sessões logadas (console/RDP), estado e tempo ocioso |
| `get_local_admins` | Membros do grupo Administradores local (pelo SID, independe do idioma) |
| `get_local_groups` | **Todos os grupos locais e seus membros**: SID, descrição, tipo e origem de cada membro (`Local`, `Interno (BUILTIN)`, `Sistema (NT AUTHORITY)`, `Domínio`, `Azure AD`, `Externo`), estado das contas locais (habilitada, último logon, senha) e **sinais** (só fatos): SIDs não resolvidos, principais de domínio/Azure AD no Administrators, contas locais habilitadas com senha que nunca expira, contas desabilitadas como membros, grupos vazios. Funciona mesmo com o DC inacessível. Não classifica nada como "privilegiado". Filtro por `group` |
| `get_failed_logons` | Eventos 4625 agrupados por conta + IP, com o motivo traduzido |
| `get_security_posture` | Defender, firewall, RDP |
| `get_time_config` | **Configuração NTP completa**: tipo (NT5DS/NTP), servidores, intervalos, fonte, stratum, último sync, peers, papel no domínio, VMICTimeProvider e **offset medido**, com sinais objetivos (sem severidade nem recomendação) |
| `get_expiring_certificates` | Certificados vencidos ou próximos do vencimento |

### Coleta × interpretação
Este MCP **só coleta**: fatos observáveis, normalização, sinais objetivos e comparação com baseline do projeto. Boas práticas, recomendação, severidade e fontes documentais ficam no **`microsoft-docs-mcp`** (`C:\mcp\microsoft_docs_mcp`), outro servidor MCP e o único com acesso à internet. O Claude chama o coletor, depois o RAG, e junta fato e evidência citando a fonte. Veja a tabela do que cada um pode afirmar no README do `microsoft-docs-mcp`.

### Armazenamento: onde está cada campo
| Campo | Tool e campo |
|---|---|
| Quantidade de discos | `get_storage_overview.disk_count` |
| Tipo do disco (SSD/NVMe/SAS/SATA) | `bus_type` (NVMe/SAS/SATA/SCSI...) e `media_type` (SSD/HDD/SCM), separados; `type_text` só junta quando os dois são conhecidos |
| GPT ou MBR | `partition_style` |
| Básico ou dinâmico | `volume_kind` e `dynamic_basis` (MBR tipo 0x42, GUIDs LDM do GPT, ou Logical Disk Manager no WMI) |
| Tamanho do disco | `size_bytes` / `size_gb` |
| Tamanho da partição | `get_volumes.partition_size_bytes` |
| Sistema de arquivos | `get_volumes.filesystem` |
| Cluster size (Allocation Unit Size) | `get_volumes.cluster_size_bytes` |
| Bytes por setor | `logical_sector_bytes`, `physical_sector_bytes`, `sector_format` |
| Mount point ou letra | `drive_letter`, `mount_folders` |
| Espaço livre | `free_bytes`, `free_gb`, `free_percent` |
| Volume GUID | `volume_guid`, `volume_path` |
| Online/offline | disco: `online` e `offline_reason`; volume: `health_status`, `operational_status` |
| ReadOnly | disco: `read_only`; partição: `partition_read_only` |
| BitLocker | `get_volumes.bitlocker` |

### Prompts
- `ops_health_check(host)`: roteiro completo de health check, com relatório por área.
- `root_cause_analysis(host, symptom)`: roteiro de RCA, com linha do tempo, fatos × hipóteses e causa provável.

## Segurança

- **Somente leitura.** Única exceção: quando o script passa do limite de cerca de 8 KB da linha de comando do WinRM (por exemplo `get_disk_usage_tree`, `get_cluster_health`, `get_cbs_log_errors`), ele é enviado pelo **stdin** do `powershell.exe`, em um único processo e **sem gravar nada no servidor**.
- **Validação de entradas**: hostname, nomes, filtros e caminhos passam por regex que bloqueia aspas, `;`, `|`, `$` etc. Números são forçados para `int` e limitados.
- **Allowlist obrigatória (fail-closed).** A credencial só é enviada a hosts que estejam em `WINRM_ALLOWED_HOSTS`. Isso impede que texto malicioso em eventos, logs ou linhas de comando induza o modelo a autenticar num host do atacante.
- **Auditoria.** Cada chamada gera uma linha JSON em `logs/audit.jsonl`: data (GMT-3), tool, host, argumentos, ok/erro, duração e a mensagem de erro (truncada). **Nunca** grava o conteúdo devolvido nem valores de argumentos com cara de segredo (`pass`, `token`, `key`...). Falha ao gravar não derruba a tool. Desligue com `MCP_AUDIT=off`.
- **Modo HTTP autenticado.** O servidor não inicia em `http` sem `MCP_AUTH_TOKEN` (a não ser em loopback com opt-in explícito). Requisições sem o token Bearer correto recebem `401`.
- **Prazo total por tool.** Se o prazo estourar, o shell WinRM remoto é fechado, o que encerra o `powershell.exe` e os processos filhos no servidor. A tool devolve `{"error": "RemoteTimeout..."}` e nada fica órfão.
- **DISM protegido.** As tools de CBS não iniciam o DISM se já houver outro em execução, e o encerram se ele passar do limite. Isso evita fila de DISM travados.
- Use **HTTPS com certificado válido** (`WINRM_VALIDATE_CERT=validate`) fora do laboratório e uma conta de serviço de menor privilégio. Nunca versione o `.env`.
