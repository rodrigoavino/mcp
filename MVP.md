# MVP: MCPs de operação de Windows Server (coleta + RAG)

Este documento define o MVP para começar os testes: o que está incluso, como instalar, o que foi validado, o que testar e o que ainda **não** está pronto.

## O que é o MVP

Dois servidores MCP **separados**, com responsabilidades diferentes:

| Servidor | Projeto | Papel | Rede |
|---|---|---|---|
| `windows-ops` | `windows_rca_mcp` | **Coleta** somente leitura de servidores Windows via WinRM HTTPS 5986. 53 tools. Só fatos e sinais objetivos | Só WinRM para os servidores permitidos. **Nenhuma chamada externa** |
| `microsoft-docs` | `microsoft_docs_mcp` | **RAG** da documentação oficial Microsoft: boas práticas, recomendação, fonte e data. 5 tools | Só internet (Microsoft Learn etc.). **Sem credenciais, sem WinRM** |

O Claude chama o coletor (fatos), e só quando a pergunta é de recomendação, suporte, compatibilidade ou boa prática chama o RAG, juntando fato e evidência com a fonte.

## Regras decididas (valem como padrão do MVP)

1. **Coletor só afirma fatos**: existe, online, acima de X, diverge da baseline, falhou, corrompido. Nunca "melhor prática", "recomendado pela Microsoft", "inadequado" ou "deve ser alterado".
2. **Nada inventado.** Sem evidência: *"Não encontrei documentação oficial da Microsoft que confirme essa informação."*
3. **Carga do servidor só com evidência** (SQL Server etc.). Sem evidência vale só o SO e a versão.
4. **Consulta externa só para recomendação, suporte, compatibilidade ou boa prática.** Inventário, configuração, serviços, usuários, grupos, discos, eventos, SIDs, RIDs e status nunca saem para a internet. As tools do RAG exigem `intent` e recusam o resto antes de qualquer requisição.
5. **Data de instalação de software é fato local** (registro, instalação por usuário, eventos MsiInstaller, Package Management, sistema de arquivos), com confiança `high`, `medium` ou `low`.
6. **Resposta objetiva**: só o perguntado, em formato enxuto, com uma linha sugerindo o que mais existe. Todas as tools do coletor respondem `{computerName, timestamp, success, data}` (análises acrescentam `os` e `summary`).

Os dois servidores entregam essas regras ao Claude no handshake (campo `instructions`).

## Instalação

Pré-requisitos: `uv`, Python 3.12, `claude` (Claude Code). No servidor alvo: WinRM HTTPS na 5986, conta administradora, PowerShell 5.1.

```powershell
git clone https://github.com/rodrigoavino/mcp C:\mcp
cd C:\mcp\windows_rca_mcp ; uv sync          # coletor
cd C:\mcp\microsoft_docs_mcp ; uv sync       # RAG
```

Crie `C:\mcp\windows_rca_mcp\.env` a partir do `.env.example` (usuário, senha, `WINRM_ALLOWED_HOSTS` obrigatória, por exemplo `*.dominio.local`). **O `.env` nunca vai para o git.** O RAG não usa `.env`.

```powershell
claude mcp add windows-ops    --scope user -- uv --directory C:\mcp\windows_rca_mcp run windows-rca-mcp
claude mcp add microsoft-docs --scope user -- uv --directory C:\mcp\microsoft_docs_mcp run microsoft-docs-mcp
```

Reinicie o Claude Code e confira com `claude mcp list` (os dois devem aparecer conectados).

Variáveis do RAG (opcionais): `MS_DOCS_CACHE_DIR`, `MS_DOCS_PAGE_TTL_DAYS` (7), `MS_DOCS_SEARCH_TTL_DAYS` (1), `MS_DOCS_OFFLINE=true` (nunca sai para a internet).

## O que foi validado

Validação feita na **árvore integrada** (coletor + RAG juntos, a partir dos próprios branches dos PRs), em checkout limpo, no servidor de teste `fastmcp.familia.local` (VM KVM, Windows Server 2025, domínio `familia.local`).

| Área | Resultado |
|---|---|
| Instalação limpa (`uv sync` nos dois projetos) | OK; scripts de entrada criados; `uv.lock` estável |
| Handshake stdio real, pelos executáveis instalados | Coletor: 53 tools, 2 prompts, instruções entregues. RAG: 5 tools, 1 prompt, instruções entregues |
| Regressão completa do coletor | **66 chamadas, 53 tools, 63 aprovadas e as 3 recusas esperadas** (host inválido, caminho com aspas, host fora da allowlist); 435 s |
| Envelope padrão | 45 respostas legíveis, **nenhuma com chave fora do padrão** e nenhuma falha de coleta |
| RAG: porta de entrada | 25 casos (inglês e português): 10 autorizados e 15 recusados sem requisição |
| RAG: 6 temas de disco e DNS | todos corretos, dentro de 3 documentos e 5 trechos; ampliação de escopo avisada |
| RAG: cache, `cache_only`, `MS_DOCS_OFFLINE` | pergunta repetida = 0 requisições; sem cache devolve `needs_network` sem sair |
| Fluxo de ponta a ponta (coleta → RAG), 6 passos | OK (ver cenários) |
| Segurança e fronteiras | coletor sem import de HTTP; RAG sem WinRM nem credenciais; `.env` não rastreado; **senha de laboratório em 0 commits**; modo HTTP exige `MCP_AUTH_TOKEN` (>= 32 caracteres) nos dois; allowlist fail-closed |

Defeitos achados e corrigidos durante a validação (todos com teste): data de instalação sem fonte local; XPath com aspas quebrando um trecho do PowerShell em silêncio; correspondência de evento por prefixo; busca progressiva que parava sem a recomendação; `matches_observed` marcando o padrão (4 KB) como conforme; **porta de entrada do RAG que não recusava "which users are in the administrators group"**.

## Cenários de teste sugeridos

Pergunte ao Claude, em português, e confira o formato da resposta (curta, só o perguntado, com sugestão do que mais existe).

| # | Pergunta | Esperado |
|---|---|---|
| 1 | "Quais usuários estão no grupo Administradores do servidor X?" | Tabela com os membros (nome, tipo, origem). Sem outras categorias |
| 2 | "Teve software ou patch instalado hoje no servidor X?" | Só os itens de hoje (`installed_since_days=0`), com data, confiança e fonte; patches só com a data (o Get-HotFix não tem hora) |
| 3 | "O servidor X é físico ou virtual? Qual a plataforma?" | `get_platform_info`: tipo, hypervisor ou nuvem, e a evidência usada; `indeterminate` se nada casar |
| 4 | "Como estão os discos e volumes do servidor X?" | `get_storage_overview` e `get_volumes`: fatos e sinais (espaço abaixo da baseline etc.), sem recomendação |
| 5 | "O servidor X executa SQL Server?" | `get_workload_evidence`: só com evidência (serviço, instância, software de servidor). SSMS sozinho não conta |
| 6 | "O cluster de 4 KB do volume D: está recomendado?" | Coletor entrega o fato; o RAG só é chamado se houver carga **coletada** (ex.: SQL Server); devolve recomendação literal, fonte, data e aviso de escopo |
| 7 | "Quais serviços estão parados?" (inventário) | Só o coletor; **nenhuma consulta externa** |
| 8 | Servidor fora da allowlist | Recusa com mensagem clara |
| 9 | Pergunta sobre algo que a documentação não traz | Frase fixa "Não encontrei documentação oficial..." |

## Critérios de aceite do MVP

- [ ] `claude mcp list` mostra os dois servidores conectados.
- [ ] Os 9 cenários acima respondem no formato esperado, sem informação não pedida.
- [ ] Nenhuma pergunta de inventário gera requisição externa (conferir o campo `network` das respostas do RAG).
- [ ] Nenhuma recomendação sai do coletor.
- [ ] Nenhuma carga (SQL Server etc.) é presumida sem evidência.

## Limitações conhecidas (não esconder nos testes)

- **Tools antigas migradas para fatos + sinais** (pós-MVP): `get_health_summary`, `validate_cbs`, `get_time_config`, `get_cluster_health`, `get_disk_allocation_analysis`, conexões, teaming e as dicas de HRESULT. Os status agora são `sem_sinais` / `sinais_presentes` / `verificacao_incompleta`, com o limiar do projeto à vista; sem severidade, ação recomendada ou dica. Os limiares são do projeto, não da Microsoft.
- **RAG:** a busca do Learn é fraca; "sem evidência" pode ser falso negativo de recuperação (já aconteceu). Teto de 12 páginas novas por consulta (era até 54) e versão do SO ("Windows Server 2025") não entra mais na conferência dos termos; "allocation unit size" e "cluster size" são tratados como sinônimos. Tabelas viram células soltas e perdem a ligação linha/coluna (códigos de erro, RIDs). A extração de valor cobre só tamanhos (KB, MB, GB, TB). A verificação é lexical, não semântica.
- **Não exercitado em ambiente real:** consulta ao serviço de metadados de AWS, Azure e GCP (o laboratório é KVM; só o caminho de erro); disco dinâmico real e BitLocker instalado (só dados sintéticos); caminho de eventos MsiInstaller (itens simulados). A etiqueta de ativo do chassi do Azure foi deixada de fora por falta de confirmação.
- **Data de instalação:** o 7-Zip sai com confiança `low` (data da pasta do produto) porque a chave dele não tem `InstallDate`; hives de usuários não carregados não são lidos.
- **Respostas grandes** (18 das 63) foram truncadas no log da regressão, então a conformidade do envelope foi conferida nas 45 legíveis; o middleware é o mesmo para todas.
- Lentidão esperada: `get_largest_folders` e `get_largest_files` (~100 s), `get_component_store_analysis` (~60 s).
- Laboratório com um único servidor (KVM); nada foi testado contra servidores físicos, cluster ou controlador de domínio.

## Ajustes pós-MVP (achados nos 9 cenários de teste)

| Achado | Correção |
|---|---|
| RAG abriu 32 e 16 páginas para respostas vazias | Teto de 12 páginas novas por consulta (`MAX_PAGES_TOTAL`); páginas em cache não contam |
| "NTFS allocation unit size" voltava sem evidência (falso negativo) | O termo de versão do SO saiu da conferência e entrou a variante sinônima "cluster size"; agora acha a página do `format` (sem recomendação literal, só a citação). SQL Server + 4 KB segue devolvendo 64 KB |
| `get_local_groups(group=...)` devolvia também as contas locais | Com `group` informado, `include_users` passa a `False` por padrão (a listagem completa continua trazendo) |

## Ordem de merge dos PRs (histórico, já mesclados na tag `v0.1.0-mvp`)

`main` ← **#4** (RAG) ← **#6** (RAG Fase 1, consulta mínima, porta de entrada) e, em paralelo, `main` ← **#5** (carga, plataforma, armazenamento) ← **#7** (serviços e grupos só com fatos) ← **#8** (envelope e coleta objetiva, este documento). Use **merge commit** (não squash), para os PRs empilhados não duplicarem commits. Depois do merge do #4 e do #5, retargetar o #6 e o #7 para `main` se o GitHub não o fizer.

## Como reportar problema

Anote a pergunta feita, o servidor, o horário (UTC) e a resposta recebida; se for da consulta externa, o campo `network` da resposta. Isso permite reproduzir com os mesmos testes.
