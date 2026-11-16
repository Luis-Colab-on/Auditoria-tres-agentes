# Planejamento e recuperação durável

Esta revisão parte de `b7249a3ea3b2b8b9d0ce800e462ec6e1991dbfef`.
As verificações desta reestruturação são locais e sintéticas; não constituem uma
nova execução real dos três agentes. Os resultados reais anteriores conservam
seus estados e avaliações originais.

Validação desta revisão: 855 testes offline e sete integrações Docker aprovados,
zero falhas, uma integração live não executada. O pacote instalado passou em 13
verificações fora do checkout. Docker 29.9.3/Compose 5.7.0 usaram somente imagens
locais já aprovadas; não houve pull, build ou inferência. Os recursos temporários
dos sete receipts foram removidos. Os 742 registros históricos examinados
mantiveram seus hashes. Esses resultados não garantem a qualidade de uma auditoria
arbitrária nem a conclusão dos agentes dentro do prazo por turno.

## Fluxo e responsabilidades

`prepare` congela fonte, manifesto, perfil e configuração. `turn_planning` usa a
mesma topologia de `completion.protocol_phases` consumida por `workflow`.
`batch_distribution` preserva o mapa original e registra uma substituição
autenticada dos lotes ainda não iniciados. A versão 2 reserva também a consulta
do baseline quando ele ainda não existe; a versão 1 continua legível.

`workflow` coordena investigação independente, barreira, contraditório, revisão e
julgamento. `PhaseValidator` compartilha as validações com relatório e
reprocessamento, sem instanciar runtime ou executor para gerar um relatório.
`codex_runtime` valida condições financeiras e protocolo, seleciona contexto e
despacha por `codex_rpc`. `Budget` mantém reservas e liquidações duráveis.
`status` e `report` são consultas sem escrita; `review-completion` produz avaliação
separada, vinculada ao contexto atual.

## Preparar e conferir viabilidade

Exemplo com uma fonte sintética local, um perfil confiável do operador e arquivos
de configuração/requisitos fora da fonte:

```bash
.venv/bin/audit3 prepare --repo /caminho/fixture.zip --profile generic --config /caminho/config.json --requirements /caminho/requisitos.txt
.venv/bin/audit3 plan ID
.venv/bin/audit3 plan ID --redistribute --reviewer 'Nome do operador' --output /caminho/novo/distribuicao.json
.venv/bin/audit3 plan ID --redistribute --reviewer 'Nome do operador' --output /caminho/novo/distribuicao-aplicada.json --apply
.venv/bin/audit3 status ID
```

Substitua `ID` pelo campo `prepared`. Sem `--apply`, a distribuição é uma proposta
e não altera o run. O arquivo de saída deve ser novo e externo ao Store. A aplicação
recalcula e congela o mapa, preservando atribuições já iniciadas. Não redistribua
depois de congelar os pareceres iniciais. Um `prepare` com código de saída 2 pode
ter produzido um snapshot válido, mas um plano inviável: examine `planning` e use
o mesmo ID para o planejamento, sem iniciar inferência.

Para B lotes iniciais por Auditor e Defensor, a topologia atual tem `2 × B + 7`
fases obrigatórias; uma rodada material adicional acrescenta quatro. Os números
são derivados da função do protocolo, não de uma estimativa independente por
total de linhas. O plano mostra fases pendentes, chamadas consumidas/disponíveis,
slots, contingência e tempo acumulado. Reservas ainda não copiadas ao ledger também
consomem capacidade. Fases publicadas só são reutilizadas após validação.

A política `minimum_first_shared_contingency` permite iniciar quando o mínimo
obrigatório cabe. Correções e a rodada adicional compartilham o saldo: não há
garantia de que toda contingência caberá. Se novas obrigações excederem o saldo,
o próximo despacho fica bloqueado. Redistribuir lotes exige conferir novamente
esse total. Tempo médio disponível é uma premissa, não previsão de duração real.
Uma linha maior que a resposta de fonte produz impedimento explícito; não conta
como lida. O plano também considera truncamento por bytes e reservas de ferramentas.

## Contexto consultável

O manifesto integral permanece autenticado no controlador. O catálogo pode ser
omitido já na primeira entrega se a requisição não couber. `list_source(offset,
limit)` permite descobrir todo o inventário autorizado e dependências fora do lote;
isso não é leitura da fonte. `read_source` continua exigido para comprovar leitura.

Pareceres do debate e históricos próprios têm documentos imutáveis e páginas
endereçadas por hash, consultáveis por `read_evidence`. São fragmentos do JSON
integral, sem resumos. O debate exige consulta às páginas indicadas em
`required_context_pages`. Acesso respeita papel, fase e barreira. Receipts grandes
também são paginados: somente a entrega completa comprova sua consulta. Página de
contexto não substitui receipt de execução, leitura ou inspeção da fonte.

O limite de entrada é aplicado à requisição RPC efetivamente serializada, incluindo
schema e escape do texto, antes de escrever no pipe. Medições separam entrada lógica,
texto enviado e bytes RPC; esses valores não são tokens. Novos manifestos deixam
`estimated_input_tokens` desconhecido. Amostras oficiais `last` e `total` continuam
distintas; total acumulado da sessão não é entrada de uma única requisição.
Compactação não reinicia relógios, ferramentas, sessões ou exigências de consulta.

## Executar e acompanhar

Selecione o cliente oficial isolado 0.167.0 conforme o
[guia existente](uso-versao-validada.md#cliente-oficial-isolado-01670), somente no
PATH dos processos do auditor. A instalação global permanece independente.
Com autenticação privada já preparada:

```bash
.venv/bin/audit3 doctor --probe-codex
.venv/bin/audit3 financial-confirm ID --account-fingerprint IMPRESSAO_OFICIAL --auto-recharge disabled --extra-credits none --checked-at HORARIO_REAL_ISO_COM_FUSO
.venv/bin/audit3 run --prepared ID
.venv/bin/audit3 status ID
.venv/bin/audit3 report ID
```

Os marcadores financeiros precisam ser substituídos por fatos verdadeiros da mesma
conta. A validade permanece em 30 minutos. Quota consultada é uma observação, não
reserva remota nem garantia atômica de cobrança. Atualizações já recebidas que
bloqueiam uso impedem o próximo despacho. Crédito adicional e recarga continuam
proibidos. A retomada que gerar outro turno exige condições vigentes novamente.

## Recuperar sem editar registros

```bash
.venv/bin/audit3 recover ID
.venv/bin/audit3 status ID
```

O primeiro comando só reconcilia registros locais. Não consulta conta nem inicia
inferência; não exige renovar fatos financeiros para publicar uma resposta já
confirmada. Repita-o após corrigir um problema local de armazenamento. A entrada
lógica da tentativa é imutável: novos receipts e leituras não a substituem. Reserva,
entrada efetiva, resposta confirmada, publicação da fase e índice agregado são
registros distintos. Falha de ledger/evento posterior à confirmação não converte
a resposta em envio ambíguo. Recuperação repetida não duplica fases ou chamadas.

`status` mostra `planning.recovery_pending`, incluindo o `invocation_id`. Quando
há prova de ausência de envio, pode-se autorizar o próximo slot **já existente**:

```bash
.venv/bin/audit3 recover ID --invocation INVOCATION_ID --allow-next-attempt
```

A operação não envia turno, não devolve reservas, não aumenta limites nem concede
tentativa extraordinária. Se os slots acabaram, permanece bloqueada. Uma interrupção
antes da intenção durável de despacho pode ser provada localmente no formato novo.
Uma interrupção depois dessa intenção permanece ambígua sem prova adicional.

Para turno com identificadores oficiais e envio desconhecido:

```bash
.venv/bin/audit3 recover ID --invocation INVOCATION_ID --check-official
.venv/bin/audit3 recover ID --invocation INVOCATION_ID --check-official --allow-next-attempt
```

Essa consulta usa `thread/turns/list` do contrato 0.167.0, com a mesma conta e
sessão; não chama `turn/start`, `thread/start` ou `thread/resume`. Consulta no máximo
dez páginas de um turno, primeiro sem itens. Recupera somente resposta final única
de turno oficialmente concluído, validada novamente contra fonte e obrigações.
Não persiste raciocínio privado. Uma interrupção oficial permite apenas o próximo
slot existente. Estado ativo, não encontrado, item incompatível, identidade divergente
ou evidência insuficiente preserva o bloqueio. Turnos mais antigos que a janela
consultada permanecem desconhecidos. O contrato de consulta foi conferido no schema
gerado pelo cliente local; a recuperação remota foi testada com transporte simulado.

Depois da reconciliação, para continuar trabalho ainda não executado:

```bash
.venv/bin/audit3 resume ID
```

Não use `prepare` como retry nem edite checkpoints autenticados. Tempo medido em
processo usa relógio monotônico. Após encerramento abrupto, eventual cobrança
conservadora do intervalo de parede inclui tempo de indisponibilidade desconhecido
e fica identificada em `clock-recoveries`; não é apresentada como duração medida
dos agentes. Uso de tokens e custo desconhecidos permanecem desconhecidos.

## Resultado e revisão

Relatórios novos usam schema `2.0` e avaliador `scoped-assessment-6`. Históricos
sem os novos registros continuam com schema `1.0`/avaliador 5. Não há migração dos
originais nem fabricação de entradas ausentes; resposta antiga sem entrada durável
pode continuar legível e não ser elegível à recuperação automática.

A entrega por achado inclui decisão, prioridade fundamentada, localização/trecho,
cenário, evidências, ajuste, comportamento a preservar e regressão proposta. Hipótese
exige verificação pendente. A prioridade é avaliação do Juiz, não prova produzida
pelo controlador. Achados exigem contraditório por ID; um projeto correto pode
terminar sem achados. Defeitos encontrados não impedem concluir o escopo.

`report` separa progresso das fases, cobertura, estado operacional, conclusão
revisada e aceitação específica. As políticas existentes de revisão continuam
restritas. Uma revisão narrativa não dispensa lacunas estruturais. Veja
[reprocessamento local](reprocessamento-local.md) para os comandos testados de
`review-completion --template`, `--review` e exportação derivada. Mudança de
evidências invalida a revisão. `completed` não aprova produção nem transforma mock
em execução real.
