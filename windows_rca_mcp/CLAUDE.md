# windows-rca-mcp

MCP (FastMCP) de **OPS para Windows Server**. Serve para o Claude triar incidentes, fazer health check e RCA em servidores remotos via **WinRM HTTPS 5986**. Documentação completa em `README.md`, resultados de teste em `TESTES.md`.

## Regras do projeto (decididas pelo usuário)
- **Somente leitura.** Nenhuma tool executa comando arbitrário nem altera o servidor alvo. Única exceção: o arquivo temporário em `%TEMP%` usado por `_ps_long`, que é apagado em seguida.
- **Logs com foco em problema.** No Event Viewer, só Crítico(1), Erro(2) e Aviso(3).
- **Período padrão `days=1`** em toda tool que lê log (Event Viewer, CBS/CbsPersist/dism.log, GPO, logons, cluster). Só amplie se o usuário pedir; `_days()` limita a 90.
- Logs grandes (CBS) são **agrupados** (mensagens normalizadas + top HRESULTs com dica), nunca devolvidos crus.
- Toda resposta de saúde usa status **OK / Atenção / Crítico**, com achados e ação recomendada.
- Idioma: português (docstrings, mensagens, README).

## Arquitetura
- `src/windows_rca_mcp/server.py`: todas as tools (49) e os prompts (`ops_health_check`, `root_cause_analysis`).
- `src/windows_rca_mcp/__init__.py`: `main()`. `MCP_TRANSPORT=stdio` (padrão) ou `http` (`MCP_HOST`/`MCP_PORT`).
- `src/windows_rca_mcp/diskscan.cs`: scanner de disco em C#, compilado no alvo via `Add-Type` (`get_disk_usage_tree`).
- Execução remota:
  - `_run_ps`: abre o shell WinRM e aplica **prazo total real**. Ao estourar, fecha o shell, o que encerra os processos remotos.
  - `_ps`: injeta `$ErrorActionPreference='Stop'` + `PS_HELPERS` + o script + `exit 0`, e devolve JSON (datas ISO, `_flatten_dates`).
  - Se o script passar de ~8 KB, `_ps` delega para `_ps_long` (envio em blocos).
- `PS_HELPERS` (injetado em todo script):
  - `$ProgressPreference` silencioso;
  - saída em UTF-8;
  - `Msg` trunca mensagem de evento com segurança contra nulo;
  - `RunDism` tem timeout e não inicia se já houver um DISM rodando.
- Validação de entrada com `HOST_RE`, `NAME_RE`, `SVC_RE`, `PATH_RE`. Números via `int()` e limitados.
- Config por `.env` (python-dotenv), lido do diretório de trabalho. Veja `.env.example`. **O `.env` nunca vai para o git.**

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
