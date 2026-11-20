# Relatório de testes: windows-rca-mcp v0.2.0

**Data:** 19/11/2026 · **Executado por:** Claude Code (bateria automatizada via `fastmcp.Client` em memória + `teste.py`)
**Resultado:** ✅ **49/49 tools aprovadas** (revisão 4: busca otimizada e `get_local_groups`; a bateria completa da revisão 4 cobriu 48 e o `get_local_groups` foi testado à parte), 2/2 prompts registrados, 3/3 casos negativos rejeitados corretamente.

## 1. Ambiente de teste

| Item | Valor |
|---|---|
| Servidor alvo | `FASTMCP` (`fastmcp.familia.local`, 10.10.0.35/16), testado contra si mesmo |
| Sistema | Windows Server 2025 Standard Evaluation, 24H2, build 26100.1742 |
| Hardware | VM KVM (VirtIO), 8 vCPU, 8 GB RAM, disco C: 31,2 GB |
| Domínio | `familia.local` (DC `dc-w25-03.familia.local`, 10.11.0.3) |
| Conexão MCP → servidor | WinRM **HTTPS 5986**, NTLM, conta `administrator` (laboratório) |
| Certificado | Autoassinado `CN=fastmcp.familia.local` (thumbprint `DEC6CC62…C582`, válido por 3 anos), `WINRM_VALIDATE_CERT=ignore` |
| Integração | Registrado no Claude Code como `windows-ops` (escopo usuário). Status `√ Connected` |

### Configuração feita no servidor
1. Certificado autoassinado criado em `Cert:\LocalMachine\My`.
2. Listener WinRM **HTTPS na 5986** (o listener HTTP 5985, que já existia, foi mantido).
3. Regra de firewall `WinRM-HTTPS-In-TCP-MCP` (TCP 5986, perfis Domain/Private).
4. Autenticação `Basic` do WinRM desabilitada.
5. Arquivo `.env` de laboratório criado (fora do versionamento, via `.gitignore`).

## 2. Metodologia

- Cada tool foi chamada pelo protocolo MCP (`Client.call_tool`), exatamente como o Claude a chama.
- Variações de parâmetros foram testadas: UDP ligado e desligado, filtro por estado de conexão, conectividade positiva e negativa, tarefas com e sem filtro.
- Casos negativos testaram a validação de entrada e erros de conexão.
- Cada falha encontrada foi corrigida, e a tool foi testada de novo até passar.
- Tempo total da bateria final: cerca de 10 min. A maior parte vem do DISM (300 s) e das varreduras de disco em PowerShell puro (cerca de 80 s cada).

## 3. Resultado por tool

> **Nota (2026-11-20):** as colunas e os achados abaixo foram escritos quando o coletor ainda classificava em OK/Atenção/Crítico. Isso é histórico: hoje as análises devolvem só `sem_sinais` / `sinais_presentes` / `verificacao_incompleta`, sem severidade nem recomendação. A regressão pós-migração (54 tools, dois servidores) está no `MVP.md`.

| # | Tool | Resultado | Tempo | Observação |
|---|---|---|---|---|
| 1 | get_health_summary | ✅ | 9 s | Geral **Atenção** (patches/reboot pendente, eventos críticos) |
| 2 | get_uptime | ✅ | 1,5 s | Uptime 2h37m, último shutdown planejado registrado |
| 3 | get_system_overview | ✅ | 0,9 s | |
| 4 | get_performance_snapshot | ✅ | 1,9 s | CPU 1%, 2,5 GB livres |
| 5 | get_top_processes | ✅ | 1,2 s | |
| 6 | get_top_resource_consumers | ✅ | 7 s | Amostra de 5 s; com dono, serviço e linha de comando |
| 7 | get_events | ✅ | 1,9 s | |
| 8 | get_event_summary | ✅ | 1,4 s | *Corrigido* (erro de parser no original) |
| 9 | get_reboot_and_crash_history | ✅ | 1,8 s | |
| 10 | get_services | ✅ | 1,2 s | |
| 11 | get_stopped_auto_services | ✅ | 1,6 s | Revisão 5: só fatos e sinais. 7 serviços parados no lab (4 com gatilho, 3 de início atrasado, 2 sem nenhum dos dois), todos com ExitCode 0; `failedExitCode` e `transitionalState` vazios |
| 12 | get_service_failures | ✅ | 1,2 s | |
| 13 | get_server_roles | ✅ | 2,8 s | Hierarquia role → role services |
| 14 | get_roles_and_features | ✅ | 2,5 s | |
| 15 | get_installed_software | ✅ | 0,8 s | |
| 16 | get_last_patches | ✅ | 3,3 s | |
| 17 | get_patch_status | ✅ | 3,0 s | |
| 18 | get_recent_hotfixes | ✅ | 2,7 s | *Corrigido* (formato da data) |
| 19 | get_pending_updates | ✅ | 9,6 s | 2 pendentes |
| 20 | get_windows_update_history | ✅ | 1,9 s | *Corrigido* (falso erro quando não há eventos) |
| 21 | get_update_error_analysis | ✅ | 1,8 s | |
| 22 | validate_cbs | ✅ | 4,5 s | **Atenção**: servicing pendente, sem corrupção |
| 23 | get_cbs_health | ✅ | 1,0 s | DISM: *No component store corruption detected* |
| 24 | get_cbs_log_errors | ✅ | 1,8 s | 0 "Cannot repair", 0 "corrupt" |
| 25 | get_component_store_analysis | ✅ | 300 s | Proteção funcionou: o DISM travou e foi **encerrado no limite** (ver achado 4.2) |
| 26 | get_windows_update_health | ✅ | 25 s | |
| 27 | get_disks | ✅ | 0,7 s | |
| 28 | get_disk_usage_tree | ✅ | 16 s | 257.590 arquivos varridos em 5,3 s |
| 29 | get_largest_folders | ✅ | 82 s | |
| 30 | get_largest_files | ✅ | 82 s | *Corrigido* (falso erro por acesso negado suprimido) |
| 31 | get_common_space_offenders | ✅ | 14 s | |
| 32 | get_disk_allocation_analysis | ✅ | 4,5 s | |
| 33 | get_network_config | ✅ | 5,2 s | |
| 34 | get_network_adapters | ✅ | 4,1 s | Driver, offloads, RSS, erros/descartes |
| 35 | get_nic_teaming | ✅ | 2,7 s | Sem LBFO/SET neste servidor (resposta correta) |
| 36 | get_routes | ✅ | 2,0 s | |
| 37 | get_network_connections | ✅ | 2,8 s | Testado sem filtro e com `state=Established` |
| 38 | get_listening_ports | ✅ | 2,7 s | Testado com e sem UDP |
| 39 | test_connectivity | ✅ | 4–6 s | Positivo (localhost:5986) e negativo (domínio fora do ar) |
| 40 | get_applied_gpos | ✅ | 3 s | |
| 41 | get_time_config | ✅ | 4 s | |
| 42 | get_time_sync_status | ✅ | 0,6 s | |
| 43 | get_cluster_health | ✅ | 5 s | Sem cluster: devolve `Clustered=false` com o motivo |
| 44 | get_scheduled_tasks | ✅ | 3,1 s | |
| 45 | get_user_sessions | ✅ | 0,9 s | |
| 46 | get_local_admins | ✅ | 1,3 s | |
| 47 | get_failed_logons | ✅ | 1,4 s | *Corrigido* (motivo real da falha) |
| 48 | get_security_posture | ✅ | 3,1 s | |
| 49 | get_expiring_certificates | ✅ | 0,7 s | Nenhum vencendo em 60 dias |

### Casos negativos
| Caso | Esperado | Resultado |
|---|---|---|
| `get_events host="bad;host"` | Rejeitar o hostname | ✅ `Hostname inválido` |
| `get_largest_files path="C:/x'; rm"` | Rejeitar o caminho (tentativa de injeção) | ✅ `Caminho inválido` |
| `get_system_overview host=host-inexistente.local` | Erro tratado, sem derrubar o MCP | ✅ `{"error": "ConnectionError…"}` |
| Comando remoto que passa do prazo (`Start-Sleep 120`, prazo 10 s) | Abortar e encerrar o processo remoto | ✅ `RemoteTimeout` e nenhum processo órfão |

## 4. Achados no servidor FASTMCP

### 4.0 Reteste depois da correção do domínio (14:20): **OK**
| Verificação | Resultado |
|---|---|
| DC locator (`nltest /dsgetdc`) | ✅ `dc-w25-03.familia.local` (10.11.0.3), site Default-First-Site-Name |
| Registro SRV `_ldap._tcp.dc._msdcs` via 10.11.0.3 | ✅ resolve |
| Canal seguro (`nltest /sc_verify`, `Test-ComputerSecureChannel`) | ✅ NERR_Success / True, autenticação via Kerberos |
| `test_connectivity` familia.local: 389, 88, 445, 53, 636, 3268 | ✅ todas abertas, nome resolvido |
| `gpupdate /target:computer` | ✅ *Computer Policy update has completed successfully* |
| `get_applied_gpos` | ✅ OU `CN=Computers`, site, **Default Domain Policy** `{31B2F340…}` linkada em `DC=familia,DC=local` |
| `get_time_config` | ✅ Status **OK**: peer `dc-w25-03` Active, offset medido **+0,0003 s** |
| `get_local_admins` | ✅ resolve `FAMILIA\Domain Admins` |

**Ainda pendente:** o DNS secundário **10.10.0.1** continua configurado neste servidor e responde NXDOMAIN para `familia.local`. Quando o cliente consulta esse servidor, o domínio "some". O recomendado é deixar só DNS do AD.

O histórico abaixo (seção 4.1) é do período **antes** da correção.

### 4.1 Domínio / DNS (antes da correção): **Crítico** (instável)
- **13:4x:** `familia.local` resolvia para 10.11.0.3, com LDAP 389, Kerberos 88, SMB 445 e DNS 53 **abertos**.
- **13:47 e 14:17:** `familia.local` e `dc-w25-03` **não resolvem**. O DNS 10.11.0.3 dá *timeout* e o DNS secundário **10.10.0.1 responde NXDOMAIN** (não conhece o domínio).
- Consequências observadas pelas tools:
  - `nltest /dsgetdc` falha com `ERROR_NO_SUCH_DOMAIN`;
  - GPO não processa (eventos 1129/7017/7320, código 0x54B), e só a *Local Group Policy* aparece aplicada;
  - 6 logons com falha com motivo **"Nenhum servidor de logon disponível (DC inacessível)"** (0xC000005E), vindos de WIN11-01/10.10.0.10;
  - o offset do NTP não pode ser medido.
- **Ação recomendada:**
  1. verificar o serviço DNS / a carga do DC 10.11.0.3;
  2. **tirar 10.10.0.1 da lista de DNS** deste servidor e usar só DNS do AD (idealmente 2 DCs).

### 4.2 Servicing (CBS / Windows Update): **Atenção**
- `pending.xml`, `RebootPending`, `PackagesPending` e `SessionsPending` estão ativos: **reboot pendente**.
- KB5122871 (26100.33438) foi baixada e aguarda reboot. A atualização de inteligência do Defender (KB2267602) ainda não foi baixada.
- O DISM `/CheckHealth` não encontrou corrupção. Já o `/AnalyzeComponentStore` **travou** três vezes: uma por 1h30, antes da correção, e duas vezes pelo limite de 300 s, depois dela. Isso é coerente com servicing pendente.
- **Ação recomendada:** reiniciar o servidor e repetir `validate_cbs` e `get_component_store_analysis`.

### 4.3 Eventos críticos: **Atenção**
- 2 eventos críticos em 24h: *Hyper-V-Hypervisor 41: "Hypervisor launch failed; VMX not present or not enabled"*. A VM não expõe virtualização aninhada, e o WSL está instalado. Não é queda de energia.
- Drivers `dam`/`uiomap` não carregaram (7026): informativo.

### 4.4 Tempo / NTP: **Atenção**
- Tipo `NT5DS` (correto para servidor membro), fonte `dc-w25-03.familia.local`, stratum 2.
- Último sync às 13:24. *Root dispersion* de 18,9 s (alta, por causa da instabilidade do DC).
- `VMICTimeProvider` está habilitado: avaliar desabilitar, para não disputar com a hierarquia do domínio.

### 4.5 Disco: **OK (no limite)**
- C: com 31,2 GB e **5,5 GB livres (17,5%)**, perto do limiar de atenção (15%).
- WinSxS ocupa 16,25 GB (38% do volume), o cache do WU 1,49 GB e os logs do CBS 0,4 GB.
- Depois do reboot, `DISM /StartComponentCleanup` pode liberar espaço.

### 4.6 Demais áreas: **OK**
- **Performance:** CPU 1–5%, RAM em 69% de 8 GB, commit em 60%. Maiores consumidores: `claude`, `MsMpEng` (Defender) e `powershell`.
- **Rede:** 1 NIC VirtIO de 10 Gbps, full duplex, MTU 1500, RSS ligado, **0 erros e 0 descartes**. IP 10.10.0.35/16 (DHCP), gateway 10.10.0.1. Sem NIC teaming, sem rotas persistentes. 15 conexões estabelecidas, sem excesso de TIME_WAIT/CLOSE_WAIT, 46/16.384 portas efêmeras em uso.
- **Roles:** apenas *File and Storage Services*. Sem cluster.
- **Segurança:** Defender ativo com tempo real e assinaturas de hoje. Firewall ligado nos 3 perfis. RDP habilitado. Administradores locais: `FAMILIA\Domain Admins` e `FASTMCP\Administrator`.
- **Tarefas agendadas:** 4 (Edge e Google Updater), nenhuma com falha.

## 5. Bugs encontrados e corrigidos durante os testes

| # | Problema | Impacto | Correção |
|---|---|---|---|
| 1 | O comando remoto **não respeitava o timeout** (o pywinrm consulta a saída indefinidamente) | Tool podia travar para sempre e deixar processo órfão no servidor (DISM ficou 1h30 pendurado) | Novo executor `_run_ps` com prazo total; ao estourar, fecha o shell remoto e encerra o processo |
| 2 | DISM sem limite e sem proteção contra execuções simultâneas | Fila de DISM travados | `RunDism`: não inicia se já houver DISM rodando e encerra ao passar do limite |
| 3 | Falso erro: `powershell.exe` sai com código 1 depois de um erro *suprimido* | `get_windows_update_history` e `get_largest_files` falhavam | `exit 0` no fim de todo script (erros reais continuam interrompendo antes) |
| 4 | `foreach` ligado direto a um pipeline | `get_event_summary` sempre falhava (bug do código original) | Envolvido em `@( )` |
| 5 | `.Substring()` sobre a mensagem do evento sem verificar nulo | Evento sem mensagem derrubava a consulta | Helper `Msg` |
| 6 | stderr em CLIXML (registros de progresso) | Mensagens de erro ilegíveis | `_clean_err` extrai só os erros; `$ProgressPreference` silenciado |
| 7 | DateTime serializado como `{"value","DateTime"}` | Datas aninhadas | `_flatten_dates` |
| 8 | Saída em code page OEM | Acentos corrompidos | `[Console]::OutputEncoding = UTF-8` |
| 9 | Script maior que o limite de 8 KB da linha de comando | 3 tools falhavam com *command line is too long* | `_ps` muda sozinho para o envio em blocos |
| 10 | `if` como valor de hashtable na mesma linha (PS 5.1) e o nome `FT`, que é alias de `Format-Table` | Erro de parser em 2 tools novas | `$(if …)` e função renomeada |
| 11 | Evento 41 do *Hyper-V-Hypervisor* contado como queda de energia | Falso "desligamento inesperado" | Considera só o 41 do *Kernel-Power* e o 6008 |
| 12 | Logon com falha com SubStatus `0x0` | Motivo da falha aparecia como "0x0" | Usa o `Status` quando o SubStatus é 0x0, e ganhou mais códigos traduzidos |

## 6. Otimização da coleta de logs (revisão 2)

Pedido: foco em problema, período padrão de 1 dia com opção de ampliar, valendo também para CBS e outros logs.

| Mudança | Detalhe |
|---|---|
| Níveis | Event Viewer só **Crítico/Erro/Aviso** (`levels=[1,2,3]`) |
| Período | `days=1` como padrão em **11 tools de log**; `days` ampliável até 90 (valores fora disso são limitados) |
| `get_event_summary` | System, Application e **Setup**, com `include_operational` para 8 logs operacionais; totais por log/nível e grupos por provedor+ID com exemplo |
| `get_cbs_log_errors` | Varre **CBS.log + CbsPersist_*.log + dism.log** só do período. Mensagens repetidas são agrupadas e os HRESULTs vêm com dica. Neste servidor: 4 arquivos (393 MB) em **~42 s**, 483 linhas de problema em 352 grupos. Principais códigos: `0x800f0909 CBS_E_PUBLIC_OBJECT_LEAK` (319), `0x8007012f ERROR_DELETE_PENDING` (102), `0x800f0805` (32), `0x80070490` (7) |
| `validate_cbs` | Usa o mesmo período (padrão 1 dia). Não conta mais o "*No component store corruption detected*" como corrupção |
| `get_health_summary` | Passa a contar também os **erros** de 24h (alerta a partir de 50) além dos críticos |
| `get_applied_gpos` | Corrigidos GUID (`GPOID`) e link (`SOM`); incluídos AccessDenied, Disabled e filtro WMI |

Medições depois da mudança (último dia): `get_event_summary` 6 s (3 logs) ou 15 s (11 logs) · `get_events` 8 s · `get_failed_logons` 6 s · `get_service_failures` 5 s · `get_cbs_log_errors` 52 s.

## 7. Correções da revisão de código (Ultrareview do PR 1, revisão 3)

Todos os 10 achados foram aceitos e corrigidos.

| # | Achado | Correção | Teste |
|---|---|---|---|
| 1 | O modo HTTP expunha as 49 tools sem autenticação | `MCP_AUTH_TOKEN` (Bearer, 32 ou mais caracteres, via `StaticTokenVerifier`) passou a ser obrigatório. Sem token só é aceito em loopback com opt-in | ✅ Sem token ou token curto: o servidor não sobe. Sem `Authorization` ou com token errado: **401**. Com o token: **200** |
| 2 | `get_pending_updates` cortado em 60 s (WSUS é lento) | Parâmetro `max_seconds=300` | ✅ Funciona (12 s no lab) |
| 3 | `load_dotenv()` buscava a partir do pacote (quebrava instalação por wheel) | `find_dotenv(usecwd=True)`, mais `WINRM_ENV_FILE` | ✅ Com cwd sem `.env`: não carrega. Com `WINRM_ENV_FILE`: carrega |
| 4 | `get_cbs_log_errors` sem limite de leitura (logs de vários GB estouravam o prazo) | Leitura em blocos de 4 MB, só a cauda de `max_mb_per_file` (256) e orçamento de `max_seconds` (120), com resultado **parcial** em vez de erro | ✅ Com 50 MB: `TailOnly`. Com 15 s: `Partial=true` e `FilesNotRead` listados |
| 5 | `validate_cbs` dava "saudável" quando uma verificação falhava | Falha vira **Atenção**, `complete=false`, evidência "Verificação incompleta" e erro bruto nos detalhes | ✅ Falha simulada: Atenção, `complete=false` |
| 6 | `-MaxEvents` cortava totais em silêncio | `truncated`/`capped_logs`/`OldestRead` e uma nota explicando que os totais são limite inferior | ✅ Com limite 10/2 forçado: sinalizado |
| 7 | Credenciais enviadas a qualquer host com allowlist vazia (risco de prompt injection) | **Allowlist obrigatória (fail-closed)**, com curingas; `*` só por opt-in | ✅ Bloqueia `evil.example.com`, outro domínio e allowlist vazia; aceita `*.familia.local` |
| 8 | `.env.example` fixava `WINRM_PORT=5986` (quebrava `WINRM_SSL=false`) | Porta comentada; o padrão segue o SSL | ✅ |
| 9 | O `RunDism` em `PS_HELPERS` inflava todos os scripts e empurrava tools para o `_ps_long` | Movido para `PS_DISM`, injetado só nas 2 tools de DISM | ✅ `get_cbs_health` OK |
| 10 | `get_time_sync_status` duplicava o `get_time_config` | Removido (agora são **48 tools**) | ✅ |

## 8. Busca otimizada em logs e Event Viewer (revisão 4)
Pedido: pesquisa o mais rápida possível nos arquivos de texto (CBS e demais) e no Event Viewer, com busca **rápida** e **detalhada**. O `validate_cbs` levava mais de 1 minuto.

**Onde estava o tempo (medido no servidor de teste):** `get_cbs_log_errors` gastava 29 s lendo um `CbsPersist` de 617 MB com `-match` por linha (uma regex com alternativas de literais levou 17 s só nesse arquivo). No Event Viewer, `Get-WinEvent` renderiza a mensagem de todo evento: 7,7 s para 319 eventos do TaskScheduler, contra 28 ms com `EventLogReader`.

| Mudança | Antes | Depois |
|---|---|---|
| `get_cbs_log_errors` modo `rapida` (novo padrão, só erros, últimos 128 MB/arquivo) | ~35 s | **2,5 s** |
| `get_cbs_log_errors` modo `detalhada` (erros + avisos + Failed/Missing, cobertura total, 617 MB) | não existia | **12 a 17 s** |
| `validate_cbs` (3 coletas em paralelo; `log_mode`) | >60 s | **2,6 s** (rápida) / **11,7 s** (detalhada) |
| `get_event_summary` 30 dias + logs operacionais | 16 s | **1,4 s** |
| `get_event_summary` 30 dias incluindo Informação | 5,2 s e **erro** (log sem metadados) | **1,4 s**, sem erro |
| `get_health_summary` (CPU em 1 s com contador bruto; eventos via leitor rápido) | 9,1 s | **4,7 s** |
| `get_failed_logons` | 1,0 s | 0,8 s (campos por posição, sem `ToXml`) |
| Scripts grandes (stdin em vez de arquivo temporário) | vários processos | 1 processo, nada gravado no servidor |

Qualidade da busca: no modo rápido a resposta diz `Coverage='parcial'` e recomenda a busca detalhada com tempo estimado; o ruído conhecido (`IIS-HttpErrors`, `CorruptedFileRepair`, linhas `Appl: DetectUpdate`) deixou de contar como problema. Um log inexistente (ex.: FailoverClustering em servidor sem cluster) agora vai para `skipped_logs`. CPU conferida sob carga: 54% (fórmula nova) contra 55% (`Get-Counter`).

Nova tool **`get_local_groups`** (49 tools): 27 grupos locais, membros com SID, origem e estado da conta, achados. Testada em 1,4 s. Achado real no lab: os membros `S-1-5-21-439607407-...-512` (Domain Admins) em Administradores e `...-513` (Domain Users) em Users **não resolvem**, e o `Get-LocalGroupMember` falha com erro 1789; o `get_local_groups` contorna isso por ADSI. **Correção:** depois que o controlador de domínio voltou, os mesmos SIDs passaram a resolver como `FAMILIA\\Domain Admins` e `FAMILIA\\Domain Users`; o motivo era o DC fora do ar, não um domínio anterior.

**Regressão completa:** 58 chamadas, 55 aprovadas e os 3 casos negativos rejeitados corretamente (host inválido, caminho com aspas, host fora da allowlist). A bateria rodou antes do `get_local_groups` existir; ele foi testado à parte.

## 9. Limitações dos testes

- **Cluster e NIC Teaming** foram validados só no caminho "não existe", porque o servidor não tem essas configurações. Os caminhos positivos foram implementados pelos cmdlets oficiais, mas **não foram exercitados**.
- Os testes foram feitos **contra o próprio servidor** (loopback). Um teste contra um segundo servidor validará firewall, certificado e NTLM entre máquinas.
- GPOs de domínio e offset do NTP: validados no reteste depois da correção do domínio (seção 4.0).

## Anexo A. Evidência de carga e plataforma (revisão 5)
Duas tools novas do coletor, só com fatos e evidência (51 tools): `get_workload_evidence` e `get_platform_info`.

| Teste | Resultado |
|---|---|
| Carga: nada instalado | nenhuma carga, `docs_context` vazio |
| Carga: só SSMS e drivers ODBC/OLE DB (cliente) | **não** vira servidor SQL (`sql_client_tools_only=true`) |
| Carga: serviço `MSSQLSERVER`, processo `sqlservr` e instância no registro | SQL Server com 4 evidências, `running=true` |
| Carga: instância nomeada `MSSQL$PROD` parada | SQL Server presente, `running=false` |
| Carga: recurso Web-Server instalado; DomainRole 5 | IIS e AD DS identificados; DNS `Available` não conta |
| Servidor de teste (real) | nenhuma carga; vale só SO e versão (Windows Server 2025 Standard, build 26100, UBR 33822) |
| Plataforma: VMware, Hyper-V, AWS Nitro, AWS Xen, GCP, KVM/QEMU, VirtualBox (sintéticos) | todos classificados com a evidência |
| Plataforma: Hyper-V genérico | **não** vira Azure sem agente de guest ou metadados |
| Plataforma: físico Dell sem hypervisor; físico HPE com Hyper-V (`vmms` rodando) | `physical`; chassi `Rack Mount Chassis`, 2 sockets |
| Plataforma: hypervisor presente sem assinatura (ex.: físico com VBS) | `indeterminate` com nota; nada é chutado |
| Plataforma: servidor de teste (real) | `virtual`, KVM/QEMU, `qemu-ga` em execução; `vmic*` parados **não** contam |
| Privacidade: serial, UUID, id da instância e id da VM | ficam só em `identifiers`; nunca em `docs_context` |
| Metadados da nuvem forçados no servidor de teste (`probe_cloud=all`) | AWS, Azure e GCP inalcançáveis (tempo esgotado em 2 s cada, 8,7 s no total); tratamento de erro validado |

**Não validado:** os caminhos de **sucesso** do serviço de metadados (AWS, Azure e GCP) não foram exercitados contra uma nuvem real, porque o laboratório é KVM. A leitura e a classificação desses campos foram testadas só com respostas sintéticas. A etiqueta de ativo do chassi do Azure, que eu conhecia de memória, **não** foi incluída: a documentação oficial consultada não a confirmou, então a Azure só é declarada com agente de guest em execução ou resposta dos metadados. As assinaturas SMBIOS são do catálogo do projeto, não de documentação oficial, e podem ser alteradas na configuração da VM.

## Anexo B. Armazenamento (revisão 5)
Duas tools novas do coletor (53 tools), só com fatos e sinais objetivos: `get_storage_overview` e `get_volumes`.

| Teste | Resultado |
|---|---|
| GUIDs de partição do disco dinâmico e tipo MBR 0x42 | confirmados em learn.microsoft.com (*set id*, atualizada em 2026-02-16); `verify_claim` sustentada nos dois |
| Discos sintéticos: NVMe/SSD, SAS/HDD 512e offline, SCSI/mídia não informada MBR de 3 TiB com partição 0x42, GPT com LDM Metadata somente leitura 4Kn e saúde Warning | tipo, estilo, básico/dinâmico (com a base), online, leitura, formato de setor e sinais corretos; `mbrDiskAbove2TiB` aponta o disco 2 |
| Mídia `Unspecified` com barramento SCSI | `type_text` diz que o tipo de mídia não foi informado: **não** presume SSD nem HDD |
| Serial e GUID do disco | só em `identifiers`, fora das linhas dos discos |
| BitLocker sem o recurso | `indeterminate` com o motivo (nunca "desligado") |
| BitLocker com recurso (sintético) | proteção, estado, bloqueio, % e método; **só tipos** de protetor |
| Volume sem letra | BitLocker `indeterminate` (não mapeável por letra) |
| Volume sintético com ponto de montagem em pasta | `mount_folders` separa a pasta; GUID extraído; sinal `freeSpaceBelowBaseline` com 12% |
| Servidor de teste (real), `get_storage_overview` | 1 disco VirtIO de 32 GB, SCSI, mídia não informada, MBR, básico, online, 512n, saudável; nenhum sinal |
| Servidor de teste (real), `get_volumes` | 3 volumes NTFS com cluster de 4096; `C:` com 12,8% livre (sinal `freeSpaceBelowBaseline` com baseline de 15%); BitLocker `indeterminate` (cmdlet ausente) |
| `low_free_pct=500` | limitado a 99 |

**Não validado:** (1) a detecção de **disco dinâmico** foi testada só com dados sintéticos, porque o laboratório não tem disco dinâmico; os critérios (MBR 0x42, GUIDs LDM, Logical Disk Manager no WMI) estão confirmados na documentação, mas a leitura real desses campos num disco dinâmico não foi exercitada; (2) o caminho **com BitLocker instalado** foi testado só com dados sintéticos, porque o recurso não existe no servidor de teste; (3) o mapeamento de BitLocker é por letra de unidade.

## Anexo C. Serviços e grupos locais: só fatos e sinais (revisão 5)
Pedido: o coletor só coleta; classificações e recomendações ficam no RAG. Este anexo cobre `get_stopped_auto_services` e `get_local_groups` (substitui o PR 3, que classificava serviços como "suspeito" e "esperado").

| Mudança | Detalhe |
|---|---|
| `get_stopped_auto_services` | Devolve, por serviço, estado, `ExitCode`, `SvcExitCode`, conta, `Delayed`, `Trigger`, `never_started_since_boot`, `failed_exit_code`, `transitional_state`. **Sem** `Classification`, `Reason`, `Severity`, `suspicious` nem `expected` |
| `get_health_summary` | Usa os mesmos fatos; só `failed_exit_code` ou `transitional_state` mudam o status de Serviços (como já era para código de saída diferente de 0). O código 1077 deixa de contar como falha |
| `get_local_groups` | `findings` com severidade foi substituído por `signals` (só fatos). `PRIV_GROUPS` (descrições do que cada grupo "pode fazer", sem fonte) e `DOMAIN_RIDS` (rótulos de RID) foram removidos; fica o `rid` numérico |
| Correções do `get_local_groups` | Campos de conta que não é local saem `null` (antes `{}`); a origem do membro vem do SID (`Local`, `Interno (BUILTIN)`, `Sistema (NT AUTHORITY)`, `Domínio`, `Azure AD`, `Externo`) |

Fatos que o código usa e que foram **conferidos na documentação oficial** (via `microsoft-docs-mcp`):
- código **1077** = `ERROR_SERVICE_NEVER_STARTED`, "No attempts to start the service have been made since the last boot" (*System Error Codes 1000-1299*, atualizada em 2025-07-16);
- SID `S-1-5-32-544` (Administrators), nas páginas *Well-known SIDs* e *Security Identifiers*.

**Não é consulta em tempo de execução:** listar usuários e grupos usa só o servidor (ADSI e Get-LocalUser); o coletor não faz chamada externa. A conferência acima foi feita uma vez, no desenvolvimento. Por isso a tabela de rótulos de RID (512 = Domain Admins etc.) **foi removida** do coletor: ele devolve o fato (o RID numérico em `rid`) e o significado fica com o RAG, com fonte. (Os 11 rótulos tinham sido confirmados na página *Security Identifiers*, atualizada em 2026-10-20.)

| Teste | Resultado |
|---|---|
| Serviços sintéticos: código 1066, `StartPending`, 1077 com gatilho, atraso, sem código | sinais corretos (`failedExitCode=[a]`, `transitionalState=[b]`); nenhuma chave de classificação |
| Servidor de teste (real) | 7 serviços parados com fatos completos, sem sinais; painel de saúde com Serviços em OK |
| `get_local_groups` (real) | sem `findings`; `signals` com `FAMILIA\Domain Admins` no Administrators e a conta `Guest` desabilitada como membro; origem dos membros por SID |

**Limite achado no RAG (não neste PR):** a busca do RAG não trouxe a página dos códigos de erro nem a dos RIDs. A causa é que tabelas viram células soltas (cada `td` é um bloco), perdendo a ligação linha/coluna. Os fatos acima foram conferidos lendo as páginas diretamente. Registrado em Pendências.

## Anexo D. Envelope padrão e coleta objetiva (revisão 5)
Padrão confirmado pelo usuário: toda tool responde `{computerName, timestamp, success, data}` (análises acrescentam `os` e `summary`), responde só o perguntado e apenas sugere o resto (`moreAvailable`). Data de instalação de software é fato local, com confiança.

| Teste | Resultado |
|---|---|
| Envelope (unidade): lista, dicionário com `Host`, falha, análise (`os` e `summary`), `more_available`, erro parcial com dados, texto cru, formato do timestamp | todos conforme o padrão; erro parcial com dados continua `success: true` |
| Envelope pelo cliente MCP: 6 tools de natureza diferente | nenhuma chave fora do padrão; host inalcançável vira `success: false`; host inválido continua erro do MCP |
| **Regressão completa com o envelope** | 62 chamadas, 49 tools, 59 aprovadas e as 3 recusas esperadas; todas as respostas em JSON legível tinham o envelope e nenhuma chave fora do padrão; nenhuma falha de coleta |
| Instruções do servidor (handshake stdio real) | entregues ao cliente (1574 caracteres, com o padrão) |
| "Software instalado hoje" (`installed_since_days=0`) | só o **7-Zip 26.06**, `installDate 2026-11-20`, `confidence low`, `source FileSystem` (a chave não tem `InstallDate`); bate com o "Adicionar ou remover programas" |
| "Patches de hoje" | só **KB5131079** e **KB5131080** |
| Instalações por usuário (HKCU e HKEY_USERS) | achou o **Visual Studio Code (User)** e o **uv**, que o `HKLM` não mostra |
| Eventos MsiInstaller (itens simulados) | `GitHub CLI` casa pelo evento 1033 (2026-11-19, `MsiInstaller`); com sufixo de versão ou arquitetura casa; com palavra extra, inexistente e `Git` **não** casam |

**Defeitos achados e corrigidos nos testes:**
1. A coleta lia só o `InstallDate` e dava "sem data" ao 7-Zip, que o Windows mostra como instalado hoje. Agora segue a ordem de evidências locais (registro, por usuário, eventos MSI, Package Management, arquivos).
2. O XPath do provedor (`@Name='MsiInstaller'`) tem aspas simples e quebrava a string do PowerShell **em silêncio**, dentro de um `try/catch`: nenhum evento era lido. Agora as aspas são dobradas.
3. A correspondência de evento por **prefixo** fazia `Git` herdar a data do `GitHub CLI`. Agora só nome igual (ignorando arquitetura e versão no fim).
4. O teste usou o nome `NI` para uma função, que colide com o alias `ni` do PowerShell (já está nas armadilhas).

**Não validado / limites:** (1) o caminho MsiInstaller foi testado com itens simulados, porque nenhum programa real do servidor de teste dependeu dele; (2) o provedor `Programs` do Package Management não expõe data; (3) hives de outros usuários não carregados não são lidos; (4) o evento 11724 não é usado (pelo que se sabe, é remoção; não há nenhum no servidor de teste para confirmar); (5) a data do `Get-HotFix` não tem hora; (6) a data por pasta (`FileSystem`) tem confiança baixa.
