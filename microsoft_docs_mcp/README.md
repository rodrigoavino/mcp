# microsoft-docs-mcp

MCP (FastMCP) **RAG de documentação oficial Microsoft**. Interpreta os fatos coletados pelo `windows-rca-mcp` à luz da documentação oficial, com trecho, URL e data. **Não acessa servidores e não tem credenciais.**

## Divisão de responsabilidades

```
Claude
 ├─ windows-ops (windows-rca-mcp)   COLETA
 │    fatos observáveis, normalização, sinais objetivos, comparação com baseline do projeto. Sem recomendação.
 └─ microsoft-docs (este projeto)   RAG
      boas práticas Microsoft, interpretação, recomendação, severidade, fontes documentais.
```

| O coletor pode afirmar | O coletor **não** afirma | Este RAG afirma (só com fonte) |
|---|---|---|
| existe / não existe | melhor prática | recomendado pela Microsoft |
| online / offline | configuração inadequada ou insegura | fora do padrão Microsoft |
| valor acima de X / abaixo de Y | "deve ser alterado" | severidade e recomendação |
| diverge da baseline configurada | | valor recomendado, citado literalmente |
| falhou / passou, corrompido / não | | |

Exemplo de fluxo:

1. `windows-ops` devolve fatos: `{"volume": "D:", "filesystem": "NTFS", "clusterSize": 4096}` e a evidência de carga (ex.: SQL Server instalado e em execução).
2. O Claude chama `validate_configuration(question="allocation unit size", observed_value=4096, observed_unit="bytes", context=["SQL Server"])`. **O `context` só pode vir de evidência coletada**; sem software que identifique a carga, considera-se só o sistema operacional e a versão.
3. O RAG devolve `supported`, `recommendation` (valor **literal** de uma frase oficial), `matches_observed`, `source` (título, URL, data), `scope_note` e `quote`. Sem evidência: `supported=false` e *"Não encontrei documentação oficial da Microsoft que confirme essa informação."*

Resultado real do teste com esse exemplo (servidor de teste, fonte lida em 2026-11-20):

```json
{
  "supported": true,
  "recommendation": ["64-KB"],
  "recommendation_strength": "recommendation",
  "strength_basis": "frase imperativa em seção/documento de boas práticas",
  "matches_observed": false,
  "also_mentioned": ["4 KB"],
  "quote": "Format your data disk to use 64-KB allocation unit size for all data files placed on a drive other than the temporary D:\\ drive (which has a default of 4 KB).",
  "source": {"title": "Storage: Performance Best Practices & Guidelines - SQL Server on Azure VMs", "url": "https://learn.microsoft.com/en-us/azure/azure-sql/virtual-machines/windows/performance-guidelines-best-practices-storage", "updated_at": "2026-10-19"},
  "scope_note": "... Este é um documento do Azure: a recomendação pode ser específica de VMs no Azure."
}
```

Note o escopo: essa página é de **SQL Server em VMs do Azure**; a ferramenta avisa, e quem interpreta precisa dizer isso ao usuário.

## Tools

| Tool | O que faz |
|---|---|
| `validate_configuration` | **Principal.** Pergunta genérica + valor observado + `context` coletado → evidência com recomendação literal, força (`requirement`, `recommendation`, `avoid`) e fonte. `search_hints` (até 2) acrescenta termos só para a **busca**, porque a busca do Learn é fraca |
| `ground_in_microsoft_docs` | Busca no Learn (1 a 3 consultas), **lê as páginas** e só devolve as que têm um trecho com os termos principais |
| `search_microsoft_docs` | Só localiza candidatas. **Não é evidência** (em teste trouxe Power Platform para consulta de DNS) |
| `get_microsoft_doc` | Lê uma página de fonte permitida; caminho para `support`, `techcommunity`, `aka.ms` e `github.com/microsoft`, que não têm busca aqui |
| `verify_claim_in_microsoft_docs` | Confere se os termos de uma afirmação aparecem na página. Valor específico (número, IP, código) ausente derruba para `sem suporte` |

Prompt: `microsoft_grounded_answer(question)` traz a regra de governança.

## Como evita inventar

- **Sem fonte, sem afirmação.** Mensagem fixa quando não há evidência.
- **A página é lida.** O resultado da busca não vale como evidência. Um trecho só é aceito se tiver a maior parte dos termos e **os termos principais** (os não genéricos), e o **contexto** (ex.: SQL Server) é obrigatório no trecho ou no título.
- **Recomendação literal.** O valor sai de uma frase da página com verbo de exigência/recomendação/proibição, ou imperativa em seção de boas práticas. Valores entre parênteses ou em cláusula "default" não contam como recomendação (saem em `also_mentioned`).
- Verificação **lexical**: termos presentes não provam o sentido. A resposta traz a frase para conferência.

## Fontes permitidas (ordem de confiança)

1. `learn.microsoft.com` 2. `support.microsoft.com` 3. `techcommunity.microsoft.com` 4. `github.com/microsoft` (só sob `/microsoft/`). `aka.ms` só como redirecionador: o destino final precisa ser uma das anteriores. Só HTTPS, sem usuário/porta na URL, cada redirecionamento revalidado, 3 MB por página, cache de 15 min.

## Privacidade e segurança

- A consulta enviada à busca é **recusada** se tiver IP, e-mail, nome de host/domínio ou caminho UNC. Conferência de afirmações e leitura por `query` são locais.
- O texto das páginas é **dado não confiável** (pode conter instruções para o modelo): vem marcado como citação.
- Sem credenciais, sem `.env`, sem WinRM: é o único componente com acesso à internet.
- Modo HTTP exige `MCP_AUTH_TOKEN` (>= 32 caracteres); sem token só em loopback com `MCP_ALLOW_INSECURE_LOOPBACK=true`.

## Instalação e integração

```powershell
cd C:\mcp\microsoft_docs_mcp
uv sync
claude mcp add microsoft-docs --scope user -- uv --directory C:\mcp\microsoft_docs_mcp run microsoft-docs-mcp
```

## Testes (2026-11-20, rede real, Microsoft Learn)

| Teste | Resultado |
|---|---|
| Lista de fontes (12 URLs: http, subdomínio falso, usuário/senha, porta, `github.com/torvalds`...) | só as permitidas aceitas |
| Consulta com IP, e-mail, FQDN, UNC | recusadas; nome de módulo `Microsoft.PowerShell.Management` aceito |
| Redirecionamento (`dns-top` → `dns-overview`) | seguido e revalidado |
| `example.com` | recusado |
| Cinco temas de disco (limite de 2 TB do MBR, GUID do LDM, DNS client, BitLocker, "disco dinâmico obsoleto") | os quatro primeiros acharam a página certa. O último ("disco dinâmico obsoleto") deu `sem evidência`, mas isso foi um **falso negativo de recuperação**: a página existe (*Convert a disk to Dynamic or Basic*, que diz que discos dinâmicos estão obsoletos e não são recomendados para novas implantações) e a busca ampla do Learn não a trazia. A Fase 1 (domínios) a recupera |
| SQL Server + cluster 4096, com `search_hints` | recomenda 64 KB, `matches_observed=false`, frase e fonte citadas |
| O mesmo **sem** `search_hints` | `sem evidência` (a busca do Learn não traz a página sem termos específicos) |
| Contexto obrigatório: página do comando `format` (fala de unidade de alocação, não de SQL Server) | rejeitada |
| `verify_claim`: "sempre usar 8.8.8.8 como DNS alternativo" | `sem suporte` (`8.8.8.8` ausente da página) |

Defeitos achados e corrigidos nos testes:
1. a validação aceitava páginas irrelevantes por termos genéricos (corte por termos principais);
2. os termos das variações de busca diluíam a conferência (a conferência usa só os termos da pergunta);
3. o corte de páginas lidas descartava a página da última consulta (resultados intercalados);
4. o termo de contexto era dispensável (agora obrigatório);
5. **`matches_observed` dava `true` para 4 KB**, o padrão do disco temporário citado entre parênteses na mesma frase (valores entre parênteses e "default" saem de `recommendation`);
6. afirmação inventada saía como `parcial` (valor específico ausente derruba para `sem suporte`).

## Limitações

- Só o Microsoft Learn tem busca; a busca é fraca e às vezes exige `search_hints` com termos específicos. **`sem evidência` pode ser falso negativo de recuperação**: significa que não achei, não que a documentação não existe.
- A extração de recomendação cobre **tamanhos** (KB, MB, GB, TB, bytes). Outros tipos de valor (portas, tempos, nomes de parâmetro) ainda não têm extrator: nesses casos a ferramenta devolve o trecho e diz que não há valor explícito.
- A recomendação do exemplo vem de um documento do Azure: escopo precisa ser confirmado.
