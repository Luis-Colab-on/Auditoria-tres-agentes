# Contexto dos agentes e diagnóstico offline

O registro autenticado `manifest` continua completo e imutável. A representação
`agent-manifest-1` mantém o objetivo, limitações, identidade da fonte, hashes de
configuração/perfil/prompts e demais campos de preparação. O catálogo contém caminho,
hash, linhas e categoria de **cada arquivo legível**, inclusive fora do lote atual.
Os metadados repetitivos dos arquivos excluídos ou usados somente pelo runtime ficam
no manifesto integral, disponíveis por consulta; nenhum arquivo é removido do run.

`manifest_ref.sha256` identifica o registro original. `inventory.inventory_sha256`
identifica os registros visíveis na fase; `catalog_id` vincula a versão da representação,
o manifesto, o inventário e o catálogo. A consulta existente
`list_source(offset, limit)` devolve registros integrais paginados, `inventory_ref`,
`offset`, `next_offset` e `page_sha256`. O contrato de argumentos permanece o mesmo,
inclusive nas sessões antigas. Não é necessária outra sessão nem ferramenta nova.

`read_source` e `search_source` continuam disponíveis sobre toda fonte autorizada,
sem filtro pelo lote. Consultar dependências fora do lote não exige alterar o escopo.
Arquivos excluídos/runtime e relatórios em quarentena mantêm as restrições anteriores;
um ponteiro de inventário não concede acesso a conteúdo bloqueado. Relatórios prévios
não aparecem no catálogo nem na paginação antes da publicação da barreira.

O primeiro turno recebe o catálogo. O runtime só omite sua repetição se encontrar
checkpoint autenticado **concluído**, do mesmo papel, sessão, manifesto, versão e
inventário, que tenha incluído aquele catálogo. Reserva, envio, turno ambíguo ou
`not_sent` não demonstram entrega. O objetivo e as restrições permanecem em cada
entrada. O checkpoint registra separadamente o hash lógico, o hash efetivo, a origem
da entrega e os bytes UTF-8 efetivos. A entrada original não é modificada pelo runtime.

O controlador não injeta histórico substituto em `thread/resume`, não apaga mensagens,
não cria novas sessões para evitar compactação e não sintetiza análises anteriores.
Se o agente não tiver mais o catálogo ou trechos necessários no contexto, pode
consultá-los novamente. Catálogo, referência, plano e resumo do cliente não substituem
leitura, evidência, inspeção própria nem resposta final válida. A conclusão e a barreira
continuam verificando essas condições independentemente dos metadados de contexto.

## Unidades e observabilidade

No cliente oficial 0.167.0, `last_token_usage` guarda a última amostra de uso de
resposta observada; `total_token_usage` acumula amostras. A implementação
[`TokenUsageInfo::new_or_append`](https://github.com/openai/codex/blob/rust-v0.167.0/codex-rs/protocol/src/protocol.rs#L2360)
atualiza os dois campos de forma distinta. `thread/tokenUsage/updated` também separa
`last` e `total`. O consumo da sessão não é a ocupação instantânea da janela.
Uma amostra por resposta pode incluir histórico e cache; não representa apenas os
bytes da nova mensagem do controlador. Não converta bytes em tokens para diagnosticar
esse comportamento, nem some snapshots cumulativos como consumo de novas chamadas.

No diagnóstico histórico, 384.399 pertencia a `last_token_usage.input_tokens`;
o acumulado da sessão naquela amostra era 6.874.651. O primeiro valor não era o
acumulado, mas tampouco prova, sozinho, a ocupação exata da janela ou a causa de
uma compactação. É uma observação anterior ao slot 3. O ledger original de consumo
desconhecido não é reescrito com base nessa interpretação.

O slot 3 foi medido no texto efetivo preservado pelo cliente e conferido pelo hash
do checkpoint: **377.560 bytes**. A medição anterior de 398.456 bytes correspondia
à reconstrução da terceira entrada com espaços. São entradas e representações
distintas. A comparação offline da quarta entrada com o novo formato preservou
seus fatos e parâmetros: **39.014 bytes** com catálogo. O caso condicional de referência
tem **13.281 bytes**, mas exige entrega anterior concluída; as quatro chamadas reais
interrompidas não satisfazem essa condição. Não são medições de uma quinta chamada.

Os eventos novos `runtime_activity` e `context_compaction` registram instantes
monotônicos relativos ao início do turno, sem argumentos, resultados, raciocínio ou
credenciais. Distinguem preparação, retorno de `turn/start`, consumo de pedido de
ferramenta, retorno do resultado e ciclo de compactação. O registro de preparação
não afirma que bytes já foram enviados. Esses eventos não consomem passos de
ferramenta nem contam como leitura/inspeção/cobertura. O deadline efetivo e os fatos
financeiros continuam sendo verificados no despacho e no consumo dos eventos.
Os registros históricos sem esses tempos não são preenchidos retroativamente.

## Validação local e recuperação

As regressões usam transporte falso e arquivos sintéticos, sem executar código
auditado no host ou provocar compactação real:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q \
  tests/test_agent_context.py tests/test_context_compaction.py \
  tests/test_runtime_tool_budget.py tests/test_batch_distribution.py tests/test_chained_recovery.py

PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv/bin/python -m pytest -q -m 'not docker and not live'
```

Os testes percorrem 50 lotes por papel, validam as fases persistidas e mostram que
o catálogo não cria cobertura. Testes de compactação e retomada usam a mesma sessão,
preservam a barreira e continuam rejeitando ferramentas desconhecidas e o passo 33.
Isso demonstra o contrato local, sem garantir uma resposta real em 300 segundos.

O run `4014e3a8f175f39ccb181867` permanece com **4 chamadas**,
**449,2679920469818 segundos** e todos os slots de Auditor/initial-0000 consumidos.
Uma proposta de quinta chamada no slot 4 exige autorização específica, novo vínculo
imutável à versão corrigida, às quatro tentativas, às respectivas provas oficiais e
ao mesmo mapa de distribuição. A autorização anterior do slot 3 não permite isso.
Nenhuma quinta chamada ou autorização de slot foi registrada nesta correção local.

Os 50 lotes de cada papel preservam o escopo e exigem 107 fases, ou 111 com a rodada
material adicional. Com uma futura recuperação autorizada e as correções normais,
o pior total de chamadas previsto é 225, dentro de 240. Restam 13.950,732 segundos;
para 107 fases, a média global disponível é 130,381 segundos por fase, incluindo
preparação, execução de testes e demais custos. Todos os turnos a 300 segundos não
cabem. O histórico grande continua na sessão e novas compactações são possíveis.
Nenhum prazo, slot, modelo, esforço ou limite financeiro é ampliado automaticamente.

A proposta concreta e as medições filtradas ficam em
`validation/context-payload-offline-20261113-slot3/`, separados dos registros reais.
Somente antes de uma futura inferência autorizada seriam necessários novos fatos
financeiros e preflight oficial. Esta tarefa offline não os solicita nem renova.
