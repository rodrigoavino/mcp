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

## Quando consultar (e quando NÃO)

A consulta externa é o **último** recurso. Antes de chamar qualquer tool deste MCP:

1. O dado já existe no servidor? **Use o coletor** (`windows-ops`).
2. O dado pertence à baseline do projeto? **Use a baseline.**
3. O item é conhecimento Windows conhecido? **Responda sem consulta externa.**
4. A pergunta fala de **recomendação, suporte, compatibilidade ou boa prática**? **Só o item 4 autoriza consulta externa.**

Inventário, configuração, serviços, usuários, grupos, discos, eventos, SIDs, RIDs e status operacionais **nunca** disparam pesquisa externa.

O código impõe isso: toda tool que pode sair para a internet **exige `intent`** (`recommendation`, `support`, `compatibility` ou `best_practice`). Sem `intent`, ou com pedido de inventário/status ou de SID/RID, a tool **recusa antes de qualquer requisição** e devolve o checklist acima. As responsabilidades 1 a 3 são do chamador; o código só consegue verificar a intenção declarada e o tipo de pedido.

### Consulta externa o mínimo possível
- **Cache em disco primeiro:** páginas por 7 dias, buscas por 1 dia (`MS_DOCS_CACHE_DIR`, `MS_DOCS_PAGE_TTL_DAYS`, `MS_DOCS_SEARCH_TTL_DAYS`; no máximo 400 arquivos por tipo). Repetir uma pergunta custa **zero** requisição.
- **Busca progressiva:** 1ª passada com 1 consulta e até 6 páginas, escolhidas pelo título e pela descrição que a própria busca já devolveu; só se não houver resposta amplia (todas as consultas e até 24 páginas, depois fora do domínio). No `validate_configuration` só para quando há uma **recomendação explícita**: evidência sem valor não basta.
- **Transparência:** toda resposta traz `network` (requisições de busca, de página, acertos de cache, se a rede era permitida).
- **`cache_only=true` e `MS_DOCS_OFFLINE=true`** nunca saem: se o cache não responde, devolvem `needs_network` (sem a frase "não encontrei"), e quem decide repetir sem `cache_only` é o chamador.
- Medido: pergunta do DNS a frio = 1 busca e 6 páginas; SQL Server + cluster (caso difícil) a frio = 3 buscas e 24 páginas; **repetida = 0**.

## Tools

| Tool | O que faz |
|---|---|
| `validate_configuration` | **Principal.** Exige `intent`. Pergunta genérica + valor observado + `context` coletado → evidência com recomendação literal, força (`requirement`, `recommendation`, `avoid`) e fonte. `search_hints` (até 2) acrescenta termos só para a **busca**, porque a busca do Learn é fraca |
| `ground_in_microsoft_docs` | Exige `intent`. Busca no Learn (1 a 3 consultas), **lê as páginas** e só devolve as que têm um trecho com os termos principais |
| `search_microsoft_docs` | Exige `intent`. Só localiza candidatas. **Não é evidência** (em teste trouxe Power Platform para consulta de DNS) |
| `get_microsoft_doc` | Exige `intent`. Lê uma página de fonte permitida; caminho para `support`, `techcommunity`, `aka.ms` e `github.com/microsoft`, que não têm busca aqui |
| `verify_claim_in_microsoft_docs` | Exige `intent`. Confere se os termos de uma afirmação aparecem na página. Valor específico (número, IP, código) ausente derruba para `sem suporte` |

Prompt: `microsoft_grounded_answer(question)` traz a regra de governança.

## Como evita inventar

- **Sem fonte, sem afirmação.** Mensagem fixa quando não há evidência.
- **A página é lida.** O resultado da busca não vale como evidência. Um trecho só é aceito se tiver a maior parte dos termos e **os termos principais** (os não genéricos), e o **contexto** (ex.: SQL Server) é obrigatório no trecho ou no título.
- **Recomendação literal.** O valor sai de uma frase da página com verbo de exigência/recomendação/proibição, ou imperativa em seção de boas práticas. Valores entre parênteses ou em cláusula "default" não contam como recomendação (saem em `also_mentioned`).
- Verificação **lexical**: termos presentes não provam o sentido. A resposta traz a frase para conferência.

## O mínimo necessário (Fase 1)

O objetivo não é achar mais conteúdo, e sim o mínimo que responde com evidência:

```
Pergunta → classificação em domínios → busca (25 por consulta) → filtro por caminho do domínio
         → leitura das páginas → portão (termos principais + contexto) → ranking BM25
         → no máximo 3 documentos e 5 trechos → resposta com fonte
```

- **Domínios** (`storage`, `sql-server`, `hyper-v`, `cluster`, `active-directory`, `dns`, `dhcp`, `networking`, `time-service`, `servicing`, `intune-m365`): a pergunta é classificada por palavras-chave e só páginas do Learn **cujo caminho pertence ao domínio** são lidas primeiro. Se nenhuma servir, o RAG **amplia e avisa** (`scope_widened: true`). O servidor de busca do Learn não tem filtro (testado: `scope`, `category` e `$filter` são ignorados), então o filtro é local. `domains` força a lista (vazia = sem restrição).
- **BM25** sobre os trechos das páginas lidas, com IDF calculado nesse conjunto: termos que aparecem em quase todo trecho pesam pouco. Ele **ordena**; quem aceita ou rejeita continua sendo o portão (cobertura de termos, termos principais, contexto obrigatório).
- **Limites:** `TOP_DOCS = 3`, `TOP_CHUNKS = 5`; um trecho só entra se tiver pelo menos 35% da nota do melhor (`REL_CUT`).
- **Não foi adotado um corte fixo de 0,70:** notas de BM25, cobertura de termos e (no futuro) embeddings não são comparáveis. Os cortes aqui foram calibrados com 9 casos reais e **não** foram validados em escala.
- **Não implementado (Fase 2):** embeddings e índice local persistente.

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
| Cinco temas de disco (limite de 2 TB do MBR, GUID do LDM, DNS client, BitLocker, "disco dinâmico obsoleto") | **antes da Fase 1:** os quatro primeiros acharam a página certa; "disco dinâmico obsoleto" deu `sem evidência` por **falso negativo de recuperação** (a página *Convert a disk to Dynamic or Basic* existe e diz que discos dinâmicos estão obsoletos e não são recomendados para novas implantações; a busca ampla não a trazia). **Com a Fase 1:** os cinco acham a página certa |
| SQL Server + cluster 4096, com `search_hints` | recomenda 64 KB, `matches_observed=false`, frase e fonte citadas |
| O mesmo **sem** `search_hints` | **antes da Fase 1:** `sem evidência`. **Com a Fase 1:** acha a mesma página e recomenda 64 KB (domínios `storage` e `sql-server`, 25 candidatos por consulta); `search_hints` virou opcional |
| Limites (6 temas) | no máximo 3 documentos e 5 trechos em todos |
| Ampliação de escopo: BitLocker com domínio errado de propósito (`dns`) | 0 páginas no domínio; amplia (12 páginas) e acha, com `scope_widened: true` |
| Domínio inválido; consulta sem sentido | erro claro com os domínios válidos; `sem evidência` |
| BM25 sintético | bloco com termo raro (3,03) pesa mais que blocos só com termos comuns (0,92 a 1,02) |
| Contexto obrigatório: página do comando `format` (fala de unidade de alocação, não de SQL Server) | rejeitada |
| `verify_claim`: "sempre usar 8.8.8.8 como DNS alternativo" | `sem suporte` (`8.8.8.8` ausente da página) |
| Porta de entrada (25 casos, inglês e português): recomendação, suporte, compatibilidade e boa prática (inclusive as que citam NIC ou serviço mas pedem recomendação); inventário de usuários, grupos, serviços, discos, portas e eventos com `list`, `show`, `which`, `who`, `what`, `quais`, `quem`, `liste`, `quantos`; "o que é o RID 512"; "significado do SID"; sem `intent`; `intent` inválido | todos conforme o esperado: os 10 de recomendação/suporte/compatibilidade/boa prática autorizados e os 15 restantes recusados, sem nenhuma requisição |
| Pelo cliente MCP: `intent` no esquema das 5 tools; inventário; RID com `intent` válido | `intent` obrigatório nas 5; inventário e RID recusados com 0 requisições; chamada sem `intent` rejeitada na validação |
| Cache: pergunta repetida; `cache_only` com cache; `cache_only` sem cache; `MS_DOCS_OFFLINE=true`; consulta com IP | repetida = 0 requisições; com cache responde; sem cache devolve `needs_network` com 0 requisições; offline idem; IP recusado antes de qualquer requisição |

Defeitos achados e corrigidos nos testes:
1. a validação aceitava páginas irrelevantes por termos genéricos (corte por termos principais);
2. os termos das variações de busca diluíam a conferência (a conferência usa só os termos da pergunta);
3. o corte de páginas lidas descartava a página da última consulta (resultados intercalados);
4. o termo de contexto era dispensável (agora obrigatório);
5. **`matches_observed` dava `true` para 4 KB**, o padrão do disco temporário citado entre parênteses na mesma frase (valores entre parênteses e "default" saem de `recommendation`);
6. afirmação inventada saía como `parcial` (valor específico ausente derruba para `sem suporte`);
7. a busca progressiva parava na 1ª página que passava no portão, mesmo sem trazer a recomendação (o SQL Server voltou `rec=None`): agora só para com recomendação explícita;
8. **a porta de entrada não recusava "which users are in the administrators group"** (a regra só reconhecia inventário que começava com `list`, `show`, `get`...), achado no teste de ponta a ponta: agora reconhece interrogativos (`which`, `who`, `what`, `quais`, `quem`...) e termos em português; pergunta com termo de recomendação, suporte ou limite nunca é tratada como inventário.

## Limitações

- Só o Microsoft Learn tem busca; a busca é fraca e às vezes exige `search_hints` com termos específicos. **`sem evidência` pode ser falso negativo de recuperação**: significa que não achei, não que a documentação não existe (já aconteceu: o caso do disco dinâmico).
- O catálogo de domínios é curadoria: se a página estiver fora dos caminhos previstos, o RAG só a acha na etapa ampliada (e avisa). A lista de termos genéricos (`GENERIC`) continua no portão; o BM25 só ordena.
- Os cortes (`0,6` de cobertura, `0,75` de termos principais, `REL_CUT 0,35`) foram calibrados com poucos casos.
- A extração de recomendação cobre **tamanhos** (KB, MB, GB, TB, bytes). Outros tipos de valor (portas, tempos, nomes de parâmetro) ainda não têm extrator: nesses casos a ferramenta devolve o trecho e diz que não há valor explícito.
- A recomendação do exemplo vem de um documento do Azure: escopo precisa ser confirmado.
