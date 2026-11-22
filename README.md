# MCPs de operação de Windows Server (windows-ops + microsoft-docs)

Dois servidores MCP **separados**, usados pelo Claude Code:

| Servidor | Pasta | O que faz | Rede |
|---|---|---|---|
| `windows-ops` | `windows_rca_mcp` | **Coleta somente leitura** de servidores Windows via WinRM HTTPS (5986). 78 tools. Só fatos e sinais objetivos | Sai só para os servidores que você pedir (5986/TCP). **Sem internet** |
| `microsoft-docs` | `microsoft_docs_mcp` | **RAG** da documentação oficial da Microsoft: recomendação, suporte, boa prática, com fonte e data | Só internet (4 sites da Microsoft). **Sem credenciais, sem WinRM** |

```
 Claude Code  ──(stdio)──>  windows-ops     ──WinRM HTTPS 5986──>  servidores Windows (qualquer domínio que autentique)
 (no servidor MCP)  └─────>  microsoft-docs  ──HTTPS 443──────────>  learn.microsoft.com, support.microsoft.com, ...
```

Este guia é o **roteiro de teste em produção** com **um novo servidor Windows como base do MCP** (o "servidor MCP"), em um ambiente com **outros domínios e tudo diferente** do laboratório. Documentação detalhada: `windows_rca_mcp\README.md`, `microsoft_docs_mcp\README.md` e `MVP.md`.

> **Regra de ouro:** do laboratório você leva o **código e os modelos de configuração**. Tudo que é **do ambiente** (credencial, certificados, nomes, domínios, lista de servidores) é **recriado** na produção. Veja a seção 4.

---

## 0. Antes de começar (decisões e pedidos)

| Item | Quem resolve | Observação |
|---|---|---|
| Servidor Windows novo para ser o servidor MCP (Windows Server 2022/2025, 2 vCPU e 4 GB bastam) | Infra | Ingressado no domínio, se a sua política exigir |
| **Conta de serviço** para a coleta | AD / Segurança | Uma conta só é usada em **todos** os servidores: ela precisa autenticar em cada domínio (conta de domínio com relação de confiança, ou combinar com cada time). Requisitos de grupo na seção 3 |
| **Servidores piloto**: 1 a 2 por domínio, da lista do CMDB | Você | Comece pequeno; a lista completa continua no CMDB (o MCP não guarda inventário) |
| Liberação de firewall de **saída** do servidor MCP | Rede | `5986/TCP` para os servidores alvo; `443/TCP` para os sites da Microsoft (RAG) e para baixar as ferramentas |
| Certificados | PKI | A CA de **cada domínio** precisa ser confiada pelo servidor MCP (seção 1.4) |
| Janela e aprovação | Gestão | O MCP só lê, mas faz login nos servidores: avise a segurança |

---

## 1. Preparar o servidor MCP (Windows)

Em um PowerShell **como administrador** do servidor MCP.

### 1.1 Relógio, fuso e DNS
```powershell
Get-TimeZone; w32tm /query /status          # hora certa e fuso corretos (o MCP mostra horas em GMT-3 por padrão)
Resolve-DnsName <fqdn-de-um-servidor-piloto> # o nome dos servidores alvo precisa resolver a partir daqui
```
Servidor com hora errada gera datas erradas nas coletas e problemas de certificado.

### 1.2 Instalar as ferramentas
```powershell
winget install --id Git.Git -e
winget install --id astral-sh.uv -e          # uv: gerencia o Python 3.12 e as dependências
irm https://claude.ai/install.ps1 | iex      # Claude Code (confira a documentação de instalação vigente)
```
Feche e abra o PowerShell, e confira: `git --version`, `uv --version`, `claude --version`. Entre no Claude Code uma vez (`claude`) e faça o login.
Se o servidor não alcança a internet direto, configure o proxy (`HTTPS_PROXY`) antes: o `uv` baixa o Python 3.12 e as dependências.

### 1.3 Testar a saída de rede
```powershell
Test-NetConnection <servidor-piloto> -Port 5986                 # deve dar TcpTestSucceeded : True
Test-NetConnection learn.microsoft.com -Port 443                 # idem (RAG)
```

### 1.4 Confiar na CA de cada domínio (para `WINRM_VALIDATE_CERT=validate`)
Importe o certificado **raiz** da CA interna de cada domínio no servidor MCP:
```powershell
Import-Certificate -FilePath .\CA-raiz-dominioX.cer -CertStoreLocation Cert:\LocalMachine\Root
```
Sem isso, a coleta só funciona com `WINRM_VALIDATE_CERT=ignore`, que é **só de laboratório**.

---

## 2. Trazer o código

```powershell
git clone https://github.com/rodrigoavino/mcp C:\mcp       # ou copie a pasta (sem .venv, .env e logs)
cd C:\mcp\windows_rca_mcp;   uv sync
cd C:\mcp\microsoft_docs_mcp; uv sync
cd C:\mcp\windows_rca_mcp;   uv run --group dev pytest -q    # opcional: confirma que o ambiente está bom (deve passar tudo)
```
Para a pasta de instalação, use outro caminho se quiser, mas ajuste os comandos da seção 5.

---

## 3. Preparar os servidores alvo (piloto)

Em **cada servidor piloto** (e depois nos demais), com a conta de serviço:

1. **Listener WinRM HTTPS na 5986**, com certificado da CA interna para o FQDN do servidor:
   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\My | ? { $_.Subject -like "*$env:COMPUTERNAME*" } | select -first 1
   New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -HostName ([Net.Dns]::GetHostEntry('').HostName) -Force
   New-NetFirewallRule -Name WinRM-HTTPS-In -DisplayName 'WinRM HTTPS (5986)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
   ```
   Em muitos ambientes isso é feito por GPO. O nome do certificado precisa bater com o nome usado para conectar.
2. **Conta de serviço** dedicada:
   - Mínimo: grupos `Remote Management Users`, `Event Log Readers` e `Performance Monitor Users`.
   - Para DISM/CBS, log de Security e leitura completa de disco é preciso **administrador local**. Comece pelo mínimo e amplie só se precisar.
3. `Add-Type` (C#) liberado, sem bloqueio de AppLocker/WDAC/Constrained Language, para `get_disk_usage_tree`. Se não puder, a tool avisa e existem alternativas mais lentas.

---

## 4. Importar a configuração do laboratório (o que levar e o que NÃO levar)

| Item do laboratório | Importar? | O que fazer na produção |
|---|---|---|
| Código (`windows_rca_mcp`, `microsoft_docs_mcp`) | **Sim** | `git clone` (seção 2) |
| `.env.example` de cada pasta (modelo, **sem segredos**) | **Sim** | `Copy-Item .env.example .env` e preencher |
| `windows_rca_mcp\.env` do laboratório | **NÃO** | Tem a credencial do laboratório, `WINRM_VALIDATE_CERT=ignore` e `WINRM_ALLOWED_HOSTS=*`. Crie um novo |
| `microsoft_docs_mcp\.env` | Só se quiser | Só ajustes de cache; os padrões servem |
| `WINRM_USER` / `WINRM_PASSWORD` | **NÃO** | Conta de serviço **da produção**; digite direto no `.env`, sem e-mail nem chat |
| `WINRM_VALIDATE_CERT=ignore` | **NÃO** | Use `validate` |
| Domínio `familia.local`, nomes `fastmcp`, `dc-w25-03`, `sql01`, `sql02` | **NÃO** | Não existem na produção |
| `hosts.json` | **NÃO** | O MCP não usa inventário próprio: a lista vem do **CMDB** e é passada por nome ou IP |
| Registro dos MCPs no Claude Code | Refazer | Comandos da seção 5 (não copie o `~/.claude.json`) |
| Memória do Claude (`.claude\projects\...\memory`) | Opcional | Tem nomes do laboratório; só leve as regras genéricas (arquivos `feedback-*.md`) se quiser |
| `logs\`, `.venv\` | **NÃO** | São gerados na produção |

### 4.1 `.env` do coletor (`C:\mcp\windows_rca_mcp\.env`)
```powershell
cd C:\mcp\windows_rca_mcp
Copy-Item .env.example .env
notepad .env
```
Ajustes mínimos para a produção (o arquivo é comentado, variável por variável):

| Variável | Valor na produção |
|---|---|
| `WINRM_USER` / `WINRM_PASSWORD` | Conta de serviço (`DOMINIO\svc_...` ou `conta@dominio`) |
| `WINRM_TRANSPORT` | `ntlm` (padrão). Em ambiente só Kerberos, combine com a segurança |
| `WINRM_SSL` / porta | `true` / 5986 (padrão) |
| `WINRM_VALIDATE_CERT` | `validate` |
| `WINRM_ALLOWED_HOSTS` | Lista de nomes com curinga dos seus domínios (`*.dominio1.com,*.dominio2.local`) ou `*` para não bloquear nada (a decisão do projeto é não bloquear: conecta por nome ou IP) |
| `WINRM_INTERNAL_ONLY` | `false` (padrão). `true` recusa servidor que resolve para IP público |
| `MCP_AUDIT_LOG` | Caminho do log de auditoria (padrão: `logs\audit.jsonl`) |

Proteja o arquivo para só a conta que roda o Claude Code ler:
```powershell
icacls C:\mcp\windows_rca_mcp\.env /inheritance:r /grant:r "$env:USERNAME`:(R,W)" "SYSTEM:(R)" "Administrators:(R,W)"
```

### 4.2 `.env` do RAG (`C:\mcp\microsoft_docs_mcp\.env`) — opcional
`Copy-Item .env.example .env`. Os padrões servem. Se o servidor MCP **não** pode sair para a internet, defina `MS_DOCS_OFFLINE=true` (o RAG só responde do cache) ou libere o `443` para os 4 sites da Microsoft.

---

## 5. Registrar os MCPs no Claude Code

```powershell
claude mcp add windows-ops    --scope user -- uv --directory C:\mcp\windows_rca_mcp    run windows-rca-mcp
claude mcp add microsoft-docs --scope user -- uv --directory C:\mcp\microsoft_docs_mcp run microsoft-docs-mcp
claude mcp list                  # os dois devem aparecer como "Connected"
```
Reinicie o Claude Code depois de qualquer mudança nos `.env`. Sempre que o MCP estiver em execução, não rode `uv sync` nas pastas dele (o `.exe` fica em uso): feche o Claude Code antes de atualizar.

---

## 6. Roteiro de testes (em ordem; só leitura)

Peça em linguagem natural ao Claude Code, ou use a linha de comando (`uv run python teste.py <tool> host=...` em `windows_rca_mcp`).

| # | Teste | Como | Esperado |
|---|---|---|---|
| 1 | **Validar o WinRM de um piloto** | "valide a conexão WinRM do `<servidor>`" (`check_winrm`) | `ok: true`, etapas `dns`, `tcp`, `tls_wsman` (HTTP 401) e `autenticacao_comando` OK, cada uma com o tempo |
| 2 | Um piloto de **cada domínio** | `check_winrm` em um servidor por domínio | `ok: true` nos dois. Se falhar, veja a camada na seção 8 antes de seguir |
| 3 | Falha controlada | `check_winrm` em um nome que não existe | `ok: false`, `category: dns`, em menos de 1 s, com o aviso |
| 4 | Identidade da coleta | `get_security_context` no piloto | Conta de serviço, integridade e grupos |
| 5 | Leitura básica | `get_system_overview` e `get_health_summary` | OS, uptime, CPU/RAM, discos; horário em GMT-3 |
| 6 | Eventos | `get_event_summary` (últimas 24 h) | Eventos agrupados por log, nível, provedor e ID |
| 7 | Vários servidores | `run_on_hosts` com `check_winrm` e 3 a 5 nomes do CMDB | Um resultado por servidor; a falha de um não afeta os outros (máximo de 50 por chamada) |
| 8 | Coleta longa | `start_job` com `get_disk_usage_tree` e `get_job` | `job_id`, depois o resultado completo |
| 9 | **RAG** | "o que a Microsoft recomenda para ...?" (`microsoft-docs`, com `intent`) | Resposta com URL e data da fonte, ou a frase fixa "Não encontrei documentação oficial da Microsoft..." |
| 10 | Auditoria | Abra `C:\mcp\windows_rca_mcp\logs\audit.jsonl` | Uma linha por chamada (tool, host, ok, duração), **sem** conteúdo nem segredos |

> **Cuidado com bloqueio de conta:** não teste senha errada repetidamente com a conta de serviço real. Para ver a falha de autenticação, use uma conta de teste.

---

## 7. Do piloto para o parque

1. Repita o teste 2 em mais 1 ou 2 servidores por domínio e **meça o tempo** das coletas.
2. Passe a lista do **CMDB** em lotes (`run_on_hosts`, até 50 por chamada) para validar o WinRM (`check_winrm`) e só depois para coletar.
3. Sempre comece qualquer coleta pela validação do WinRM: o MCP já faz isso sozinho antes de cada tool (DNS, TCP, TLS e `/wsman`, sem credenciais) e avisa a camada do problema.
4. Registre no CMDB ou na sua planilha os servidores que **não** conectaram, com a categoria do erro (seção 8), para o time responsável.

### Critérios de aceite do teste
- [ ] `claude mcp list` mostra `windows-ops` e `microsoft-docs` conectados.
- [ ] `check_winrm` OK em pelo menos um servidor de **cada** domínio.
- [ ] Uma falha forçada (nome inexistente) é avisada na hora, com a camada correta.
- [ ] Coletas básicas (testes 4 a 6) devolvem dados corretos e datas em GMT-3.
- [ ] O log de auditoria registra as chamadas, sem segredos.
- [ ] O `.env` está protegido e **não** está no git (`git status` limpo).

---

## 8. Problemas comuns (`check_winrm` informa a camada)

| `category` | Camada | O que verificar |
|---|---|---|
| `dns` | dns | O nome resolve no DNS do servidor MCP? Sufixo DNS, registro A, DNS do domínio do alvo |
| `rede_timeout` / `rede_inacessivel` | rede | Firewall (rede e do Windows) e rota. O resultado informa se a 5985 abre e a 5986 não (falta o listener HTTPS) |
| `conexao_recusada` | rede | Serviço WinRM parado ou sem listener na porta |
| `tls_certificado` / `tls` | tls | CA do domínio não confiada no servidor MCP, certificado vencido ou nome diferente (seção 1.4) |
| `servico_winrm` | serviço | A porta abre, mas não responde como WinRM; veja o log `Microsoft-Windows-WinRM/Operational` do alvo |
| `autenticacao` | autenticação | Usuário ou senha, formato do usuário, conta bloqueada, ou sem permissão no alvo (grupos da seção 3) |
| `dominio` | domínio | Kerberos/KDC/SPN, relação de confiança entre domínios, DC inacessível |
| `prazo_comando` / `leitura_timeout` | prazo | A conexão funcionou, mas a coleta demorou: use `start_job` ou reduza o escopo |

Se o `microsoft-docs` aparecer como falha em `claude mcp list` logo após atualizar o código, é o `uv` tentando reinstalar com o `.exe` em uso: feche o Claude Code, rode `uv sync` na pasta e abra de novo.

---

## 9. Segurança e operação

- **Só leitura:** o MCP não executa escrita, comando livre nem SFTP. Mesmo assim, ele **faz login** nos servidores com a conta de serviço: use o menor privilégio que atenda (seção 3).
- **Credencial:** só no `.env` do servidor MCP, com permissão restrita; nunca no git, no chat ou no `~/.claude.json`. Troque a senha da conta conforme a política.
- **Allowlist:** `WINRM_ALLOWED_HOSTS=*` não bloqueia nada e envia a credencial ao servidor pedido. Com `WINRM_VALIDATE_CERT=validate` o certificado barra servidores falsos; com `ignore` não.
- **Auditoria:** `logs\audit.jsonl` (rotação de 5 MB x 5) registra tool, host, argumentos, resultado e duração, sem o conteúdo devolvido.
- **Atualizar:** feche o Claude Code, `git pull`, `uv sync` nas duas pastas, abra o Claude Code e rode o teste 1.
- **Reverter:** `claude mcp remove windows-ops -s user` (e `microsoft-docs`); apague a pasta `C:\mcp`; remova a conta de serviço dos alvos.
