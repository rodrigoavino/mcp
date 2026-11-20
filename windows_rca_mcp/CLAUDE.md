# windows-rca-mcp

MCP (FastMCP) de **OPS para Windows Server**. Serve para o Claude triar incidentes, fazer health check e RCA em servidores remotos via **WinRM HTTPS 5986**. Documentação completa em `README.md`, resultados de teste em `TESTES.md`.

## Regras do projeto (decididas pelo usuário)
- **Somente leitura.** Nenhuma tool executa comando arbitrário nem altera o servidor alvo. Única exceção: nenhuma. O `_ps_long` envia o script pelo stdin, sem arquivo temporário no alvo.
- **Logs com foco em problema.** No Event Viewer, só Crítico(1), Erro(2) e Aviso(3).
- **Período padrão `days=1`** em toda tool que lê log (Event Viewer, CBS/CbsPersist/dism.log, GPO, logons, cluster). Só amplie se o usuário pedir; `_days()` limita a 90.
- Logs grandes (CBS) são **agrupados** (mensagens normalizadas + top HRESULTs com dica), nunca devolvidos crus.
- Toda resposta de saúde usa status **OK / Atenção / Crítico**, com achados e ação recomendada.
- **Segurança (definida na revisão do PR 1):**
  - `WINRM_ALLOWED_HOSTS` é obrigatória (fail-closed, aceita curingas) e nunca deve voltar a ser opcional;
  - o modo `http` exige `MCP_AUTH_TOKEN`;
  - uma verificação que falhou nunca conta como "OK";
  - limites (`-MaxEvents`, tamanho ou tempo de leitura) são sempre **sinalizados** na resposta (`truncated`/`Partial`).
- Toda tool que pode ser lenta passa um `timeout` explícito ao `_ps`. O padrão de 60 s é um prazo total rígido.
- Idioma: português (docstrings, mensagens, README).
- **Fronteira coleta × interpretação (decidida pelo usuário):** este MCP só **coleta**. A interpretação fica no `microsoft-docs-mcp` (`C:\mcp\microsoft_docs_mcp`, outro servidor MCP, o único com acesso à internet).
  - Pode afirmar: existe / não existe, online / offline, valor acima de X ou abaixo de Y, diverge da baseline configurada do projeto, falhou / passou, corrompido / não corrompido. Sinais objetivos derivados de fatos (`diskOffline`, `pendingReboot`, `freeSpaceLow`) são permitidos, com o limiar à vista.
  - **Não** pode afirmar: melhor prática, recomendado pela Microsoft, configuração inadequada ou insegura, "deve ser alterado", fora do padrão Microsoft, nem classificar serviço como "suspeito" ou "esperado". Quem diz qual é o estado esperado é o RAG, com fonte.
  - **Carga do servidor só com evidência:** nunca presumir que o servidor é SQL Server, IIS etc. Use `get_workload_evidence`; sem evidência identificadora vale só o SO e a versão. Cliente (SSMS, ODBC) não identifica servidor. O `context` enviado ao RAG vem só de `docs_context`.
  - **Plataforma:** `get_platform_info` diz se é físico, virtual ou nuvem, só por assinatura com a evidência à vista; `indeterminate` quando nada casa. Serial, UUID, asset tag e id de instância são sensíveis: ficam em `identifiers` e nunca vão ao RAG (só `docs_context`).
  - Nada que saia deste MCP para a internet: nenhuma chamada externa aqui. A única exceção é o serviço de metadados da própria instância (`169.254.169.254`, link-local, executado no servidor alvo e só em campos de lista fixa).
  - Já migradas para fatos + sinais: `get_stopped_auto_services` e `get_local_groups`. Dívida conhecida: ainda trazem julgamento ou recomendação `get_health_summary` e `validate_cbs` (OK/Atenção/Crítico, ações), `get_time_config` ("o recomendado é NT5DS"), `get_cluster_health` ("configure ... witness"), `get_disk_allocation_analysis` ("candidato a reclamação") e as dicas de HRESULT. Devem migrar. Tool nova já nasce sem julgamento.

## Arquitetura
- `src/windows_rca_mcp/server.py`: todas as tools (53) e os prompts (`ops_health_check`, `root_cause_analysis`).
- `src/windows_rca_mcp/__init__.py`: `main()`. `MCP_TRANSPORT=stdio` (padrão) ou `http` (`MCP_HOST`/`MCP_PORT`).
- `src/windows_rca_mcp/diskscan.cs`: scanner de disco em C#, compilado no alvo via `Add-Type` (`get_disk_usage_tree`).
- Execução remota:
  - `_run_ps`: abre o shell WinRM e aplica **prazo total real**. Ao estourar, fecha o shell, o que encerra os processos remotos.
  - `_ps`: injeta `$ErrorActionPreference='Stop'` + `PS_HELPERS` + o script + `exit 0`, e devolve JSON (datas ISO, `_flatten_dates`).
  - Se o script passar de ~8 KB, ele vai pelo **stdin** do powershell.exe (`_run_ps(via_stdin=True)`); `_ps_long` é só um atalho para isso.
- **Busca em arquivos de texto/logs grandes:** nunca use `-match` por linha em centenas de MB (medido: 17 s por 617 MB). Padrão do projeto: pré-filtro `String.IndexOf` ordinal em blocos de 16 MB, busca binária de data para pular o que está fora do período, classificação regex só nas candidatas, e **dois modos** (`rapida`/`detalhada`) com `Coverage`/`Recommendation` quando parcial.
- **Event Viewer:** `Get-WinEvent` renderiza a mensagem de todo evento (7,7 s para 319 eventos do TaskScheduler; `EventLogReader` fez o mesmo em 28 ms). Use `PS_EV` (`Ev`, `Desc`) e `_xpath()`; só chame `Desc` nas amostras. Log inexistente lança exceção: use try/catch e registre em `skipped_logs`.
- `PS_HELPERS` (injetado em todo script):
  - `$ProgressPreference` silencioso;
  - saída em UTF-8;
  - `Msg` trunca mensagem de evento com segurança contra nulo;
  - `RunDism` fica em `PS_DISM`, injetado **só** nas tools de DISM (não infle o `PS_HELPERS`: cada byte a mais empurra scripts para o `_ps_long`).
- Validação de entrada com `HOST_RE`, `NAME_RE`, `SVC_RE`, `PATH_RE`. Números via `int()` e limitados.
- Config por `.env` (python-dotenv): `find_dotenv(usecwd=True)` lê o arquivo do diretório de trabalho; `WINRM_ENV_FILE` sobrepõe. Veja `.env.example`. **O `.env` nunca vai para o git.**
- O lab usa `WINRM_ALLOWED_HOSTS=*.familia.local,localhost`.

## Padrão de resposta do MCP (decidido pelo usuário)
Tudo o que o usuário confirmou vale como padrão das respostas deste MCP. Está no código (`envelope.py` e `INSTRUCTIONS` em `server.py`) e aqui.
- **Envelope mínimo em toda tool:** `{computerName, timestamp, success, data}`; análises completas acrescentam `os` e `summary {status, findings}`; `moreAvailable` é só uma sugestão de uma linha. Aplicado por middleware na fronteira do MCP: as funções Python e as chamadas internas seguem cruas. Tool nova não precisa fazer nada.
- **Responder só o perguntado.** Não incluir boot, uptime, disco, CPU, memória, serviços, usuários, eventos, volumes ou adaptadores a menos que (1) o usuário peça, (2) seja necessário para responder ou (3) seja erro/diagnóstico relacionado. Dar a tool um parâmetro de recorte (período, nome, limite) em vez de devolver tudo e deixar o Claude filtrar. Sugerir o que mais existe e só coletar se autorizado.
- **Data de instalação é fato local**: registro, instalação por usuário, eventos MsiInstaller, Package Management, sistema de arquivos, com confiança (high, medium, low). Nunca internet nem documentação. Evento 11724 não vale como instalação. Correspondência de evento por nome igual, nunca por prefixo.
- **Só fatos e sinais objetivos**; recomendação, boa prática e severidade são do `microsoft-docs`, e só para pergunta de recomendação, suporte, compatibilidade ou boa prática. Inventário, configuração, serviços, usuários, grupos, discos, eventos, SIDs, RIDs e status nunca disparam consulta externa.
- **Carga do servidor só com evidência** (nunca presumir SQL Server etc.); **nada inventado**.
- Ao embutir texto em string `'...'` do PowerShell, **dobre as aspas simples** (`'` vira `''`): um XPath com `@Name='X'` quebrou em silêncio um trecho dentro de `try/catch`.

## Armadilhas do PowerShell 5.1 (já custaram bugs)
- `if` como valor de hashtable na mesma linha com `;` não funciona; use `Key=$(if (...) {...})`.
- `foreach (...) {...} | Cmd` é erro de parser; use `@(foreach ...) | Cmd`.
- Não nomeie funções com aliases existentes (`FT` = Format-Table, `rd`, `sc` etc.).
- `powershell.exe` sai com 1 depois de erro *suprimido* (`-ErrorAction SilentlyContinue`); por isso o `exit 0` no final.
- Enums viram números no `ConvertTo-Json`; use `"$($_.Prop)"` para virar texto.
- Hashtable em f-string Python: dobre as chaves (`{{ }}`), ou use r-string + `.replace("__X__", ...)`.
- Evento 41 só é queda de energia se o provider for `Microsoft-Windows-Kernel-Power` (o Hyper-V-Hypervisor também usa o ID 41).
- 4625 com `SubStatus=0x0`: o motivo está em `Status`.

## Como testar
```powershell
cd C:\mcp\windows_rca_mcp
uv sync
uv run python -c "from windows_rca_mcp.server import mcp"            # import
uv run python teste.py get_health_summary host=fastmcp.familia.local  # uma tool
```
- Bateria completa: chamar todas as tools via `fastmcp.Client(mcp)` em memória (`list_tools` + `call_tool`). Inclua casos negativos: host inválido, caminho com aspas, host inexistente.
- Depois de mudar uma tool, teste-a contra o servidor real antes de dar como pronta.
- `get_component_store_analysis` / DISM podem travar neste laboratório (há reboot pendente); use `max_seconds` baixo nos testes.

## Ambiente de laboratório
- Alvo de teste: `fastmcp.familia.local` (o próprio servidor, Windows Server 2025, VM KVM). Domínio `familia.local`, DC `dc-w25-03` (10.11.0.3).
- WinRM: listener HTTPS 5986 com certificado autoassinado (`WINRM_VALIDATE_CERT=ignore` só no lab), NTLM, conta administrador local. A credencial fica só no `.env`.
- Registrado no Claude Code como `windows-ops` (escopo usuário):
  `claude mcp add windows-ops --scope user -- uv --directory C:\mcp\windows_rca_mcp run windows-rca-mcp`
- Achados conhecidos do lab:
  - DNS secundário 10.10.0.1 não resolve `familia.local`;
  - reboot pendente (CBS/KB5122871);
  - C: com cerca de 17% livre.

## Git
- Repositório em `C:\mcp` (remoto `rodrigoavino/mcp`), branch `main`. Branch `baseline` (commit `11d920e`) criado só para abrir um PR de revisão; pode ser apagado depois.
- Novas mudanças: usar um branch de feature, para o `/code-review ultra` funcionar sem argumentos.

## Pendências (retomar)
- [x] `get_stopped_auto_services` e `get_local_groups` só com fatos e sinais (sem classificar nem recomendar).
- [ ] Migrar para fatos + sinais o que ainda julga (lista na seção de fronteira acima).
- [ ] RAG (`microsoft_docs_mcp`): **tabelas** viram células soltas (cada `td`/`th` é um bloco), então o trecho perde a associação linha/coluna e a busca dá falso negativo (ex.: código 1077, RIDs de domínio). Juntar as células de cada linha num bloco.
- [ ] Lab: **avaliar** o DNS secundário 10.10.0.1 (servidor válido, decisão do usuário; não resolve `familia.local`: com o DC fora do ar o cliente cai nele e recebe "não existe"). Opções: manter, trocar por um 2º DC, ou DC com encaminhador e só o DC no cliente.
