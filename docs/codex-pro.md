# Backend Codex e uso da franquia Pro

Para uso da versão validada e consulta da referência encerrada PHP/WordPress,
consulte o [guia consolidado](uso-versao-validada.md). Ele distingue os defaults,
os limites originais do run, as extensões autorizadas e a conclusão revisada.
Os comandos de smoke abaixo são procedimentos de revalidação explícita; não são
uma próxima execução pendente da referência aprovada.

O caminho único é `codex app-server --stdio --strict-config`, chamado por Python
stdlib. Não é Agents SDK, Agents API ou um cliente do endpoint Platform. O SDK Python
público consultado não oferece `dynamicTools` em `thread_start`; sua configuração de
ambiente também mescla o ambiente herdado. Usar o protocolo documentado evita depender
de métodos privados para esses controles. Não se usa `codex exec`, servidor MCP
removido, proxy, cookie ou túnel.

O CLI é fixado em **0.167.0**. Para repetir apenas o contrato local, sem login ou
inferência, execute `.venv/bin/python scripts/verify_codex_contract.py`. `dynamicTools`, `item/tool/call` e perfis de permissões
são experimentais/beta. Os esquemas oficiais gerados pelo binário estão em
`tests/contracts/`; o parser estrito valida a configuração privada sem inferência.
O catálogo incluído anuncia Astra com `max` e `xhigh`; o runtime confere `model/list`
e a resposta efetiva da sessão. A listagem local não prova acesso remoto da conta.
`serviceTierForTurn="default"` é o valor oficial de Standard; rótulos da UI não são
transformados em flags. `ultra` não é Max: pode envolver delegação e não é permitido.

## Autenticação e finanças

1. Execute `audit3 codex-setup`. O comando gera apenas a configuração específica do
   auditor e mostra o comando oficial `login --device-auth`. Execute-o no terminal.
   Não copie o login pessoal nem leia `auth.json` manualmente.
2. Execute `audit3 doctor --probe-codex`. São usados `account/read`, `model/list` e
   `account/rateLimits/read`, sem geração. Exige conta `chatgpt` com `planType`
   `pro`, `prolite` ou `promax`: lista explícita de planos pessoais Pro reconhecidos
   pelo cliente 0.167.0. O rótulo recebido é preservado no diagnóstico e nos registros;
   planos ausentes, desconhecidos ou de outros tipos permanecem bloqueados.
   O resultado contém fingerprint opaco da identidade, sem e-mail ou token.
3. Confira os fatos em **Usage/Billing do Codex ou Settings > Usage do ChatGPT**:
   recarga automática desativada e inexistência de saldo de créditos extras. Não
   compre, resgate ou habilite créditos; nenhum comando do auditor altera faturamento.
4. Para um run preparado, registre a confirmação factual já conferida:

```bash
audit3 financial-confirm ID --account-fingerprint FINGERPRINT_DO_DOCTOR \
  --auto-recharge disabled --extra-credits none \
  --checked-at HORARIO_REAL_ISO8601_COM_FUSO
```

Substitua o marcador pelo horário real informado pelo operador, com data e fuso.
O comando recusa horário ausente, inválido, futuro ou vencido; não usa a hora de
registro para renovar fatos antigos. Isso registra uma declaração factual **do operador**. Não é prova gerada pelo auditor
nem controle atômico de cobrança. O runtime ainda exige resposta oficial
`ordinaryUsageAllowed=true`, saldo `0`, `hasCredits=false`, `unlimited=false` e quota
observável. A declaração vale por 30 minutos e é vinculada à conta. Uma alteração de
conta ou fatos exige nova verificação; se o plano for diferente/desconhecido, bloqueia.
A interface instalada não expõe recarga automática. Essa informação precisa vir da
conferência factual do operador. A autorização de uso da franquia já foi concedida;
não se trata de pedir autorização genérica novamente.

Depois do preflight aprovado, cada entrada do modelo recebe `financial_context`
com os fatos verificados, plano real, horário original da conferência e validade
restante. As instruções do controlador identificam a origem desse contexto. Ele
documenta o cumprimento dos requisitos para usar a franquia incluída; não autoriza
gastos adicionais, não renova o horário e não substitui os bloqueios de código.
O checkpoint registra esse contexto e o hash da entrada efetivamente enviada,
separadamente do hash lógico usado para recuperar saídas já concluídas.

Para diagnosticar somente a conta no mesmo HOME, sem exibir identidade ou consultar
infraestrutura, execute:

```bash
.venv/bin/python scripts/diagnose_codex_account.py --check-policy
```

O resultado mostra apenas autenticação, `planType` e eventual erro com a etapa em que
ocorreu. A opção verifica a condição de conta/plano, sem aprovar finanças ou iniciar
threads/turnos. Sem a opção, mostra os metadados mesmo se o plano não for aceito.
Conta/plano ausentes com consulta bem-sucedida não são falha RPC; formato inválido é
identificado na etapa `interpretation`. Nenhum valor desconhecido vira `pro`.

Login ChatGPT sozinho não prova ausência de consumo extra. Após a franquia, créditos
existentes podem ser usados. Polling de quota, porcentagens, limite de turnos e
cancelamento **não são uma trava financeira atômica**. A ausência de créditos e
recarga desativada precisam continuar verdadeiras durante a execução, inclusive em
outros clientes. Nenhum código promete custo zero nem bloqueio atômico do serviço.
Se os fatos não puderem ser estabelecidos, **o backend real permanece bloqueado**.

## Isolamento do Codex

O HOME/CODEX_HOME privado não herda configurações pessoais. O ambiente do subprocesso
é uma allowlist mínima: sem chaves API, credenciais de outros provedores, proxies,
overrides, NODE_OPTIONS/PYTHONPATH ou IDs de sessão herdados. O executável nativo da
distribuição oficial é usado diretamente; nenhuma segunda linguagem entra no projeto.

A configuração é aceita somente se corresponder à política gerada. Não é sobrescrita
se divergir. `forced_login_method="chatgpt"` é suportado pelo schema instalado e
validado pelo parser. Provedor é `openai`; servidores MCP, plugins, apps, skills,
memória, hooks, shell, imagens, busca, code mode e subagentes estão desativados.
O cwd fica vazio, fora da fonte. Instruções de AGENTS/README do snapshot são dados.

O catálogo local específico usa o controle oficial `model_catalog_json`: mantém
identidade, esforços e capacidade do Astra do catálogo incluído, removendo shell,
apply_patch, ferramentas experimentais locais, Node REPL e code mode. Não troca o
modelo nem endpoints. O catálogo remoto fica desativado para não reintroduzir esses
recursos. `codex debug models` verifica o catálogo efetivo sem inferência.
Perfis de permissão negam leitura/escrita do filesystem e rede de ferramentas;
`config/read` e `thread/start/resume` conferem os controles efetivos. A negação não se
confunde com read-only. A garantia depende do contrato do cliente fixado; a resistência
com agentes reais ainda não foi validada. Itens nativos ou pedidos de aprovação não
previstos causam interrupção e bloqueio, sem autorização automática.

As cinco ferramentas dinâmicas continuam no controlador. Não existe transporte de
rede para ferramentas: `item/tool/call` usa o mesmo stdio. Papel, fase, snapshot,
thread e turn são vinculados pelo controlador, nunca aceitos como autoridade do modelo.
O modelo não recebe Docker nem acesso direto ao filesystem. Três `thread/start`
criam históricos novos; `thread/resume` usa o ID explícito de cada papel, sem fork,
`--last` ou sessões anteriores à investigação cega.

## Checkpoints e limites

A [restrição financeira permanente](../AGENTS.md) vale para novas execuções,
retomadas e contexto compactado. Cada chamada recebe novamente essa regra. A
validade de 30 minutos pertence aos fatos conferidos; a proibição de gastar não
expira. O transporte recusa métodos RPC fora da lista de configuração/consulta e
controle dos turnos, incluindo operações de conta, créditos e faturamento.

Há limite de tempo total, timeout por turno, número de turnos do controlador,
passos de ferramenta e reproduções. `max_calls` conta turnos App Server, não requests
internos do modelo. O cliente Codex pode fazer múltiplas requests e retries internos
finitos num turno; o timeout externo limita a duração, não o custo atômico. Os campos
legados `budget_usd`, `call_reserve_usd`, tarifas API e `max_output_tokens` são apenas
compatibilidade de leitura e não limitam cobrança ou saída do Codex. A saída final é
limitada por bytes; a API não expõe aqui o antigo limite de tokens de saída do Runner.
Não há retry transitório do controlador. Saída inválida admite uma correção, no máximo.

Quota é consultada antes de cada turno; notificações provocam nova leitura oficial
completa, porque a notificação 0.167.0 não contém `ordinaryUsageAllowed`. Falha,
indisponibilidade ou estado desconhecido interrompem o fluxo. Não se espera renovação
em loop e não se muda de provedor. Após renovação, use `resume ID` explicitamente:
conta, fatos financeiros, backend, sessão e snapshot são revalidados.

Antes de enviar turno, registra-se estado `sending`. Resposta final confirmada é
salva atomicamente antes de retornar ao Workflow e pode ser recuperada sem geração
nova. Timeout, cancelamento, perda de transporte ou queda durante envio deixam estado
ambíguo. A retomada não repete esse turno; precisa de revisão explícita dos artefatos.
O programa não decide que um turno remoto ambíguo teve sucesso. Testes confirmados
continuam reutilizados por fingerprint/receipt do executor existente.

### Planejamento de leituras e diagnóstico de rejeições

Cada entrada inclui `controller_turn_limits`: teto efetivo de ferramentas, linhas
por leitura, corte de 16.000 bytes de texto da fonte e prazo por turno. Cada resposta
de ferramenta informa quantos passos restam. O teto conta chamadas dinâmicas,
inclusive buscas, consultas a receipts, erros e continuações de leituras truncadas.
As leituras internas de uma busca não são chamadas dinâmicas adicionais. A chamada
que excede o teto é recusada antes de executar a ferramenta; a reserva e o consumo
desconhecido do turno continuam preservados.

Nos lotes `initial-*`, `initial_read_plan` divide as leituras pelos limites reais
de linhas e bytes. O plano não publica fonte como se tivesse sido consultada, nem
produz inspeções. Pode reutilizar somente intervalos devolvidos por ferramentas
autênticas ao próprio papel, no mesmo run, fonte e etapa cega. Analisar todo o lote
continua obrigatório. O Juiz mantém inspeção cega dirigida, sem cobertura integral
artificial. O plano é um mínimo de consultas, não garantia de análise ou conclusão.

Antes de novas chamadas, o controlador verifica a viabilidade das leituras de todos
os lotes iniciais pendentes. Lotes impossíveis exigem replanejamento explícito;
não há aumento de teto, subdivisão retroativa, reciclagem de slots ou redução de
escopo automática. Para examinar o plano separadamente, sem Docker, cliente,
consulta de conta ou inferência:

```bash
.venv/bin/python scripts/plan_initial_reads.py --run ID \
  --output validation/plano-leituras-novo.json
```

O comando exige arquivo novo fora do Store. Código de saída 2 indica lotes
inviáveis. O resultado considera leituras de fonte; cada turno também inclui no
seu plano os receipts ainda não consultados. Alterações no controlador não tornam
válida, por si só, a versão congelada por um wrapper de execução anterior. A
recuperação precisa registrar e revisar a versão que será efetivamente usada.

Quando o operador autoriza redistribuir trabalho ainda não iniciado, prepare um
mapa versionado sem executar agentes:

```bash
.venv/bin/python scripts/repartition_initial_batches.py --run ID \
  --reviewer 'IDENTIFICACAO_DO_REVISOR' --output validation/distribuicao-candidata.json
```

O mapa `initial-batch-distribution-1` preserva a distribuição original e identifica
os filhos de cada lote. Divide somente lotes sem capacidade suficiente para leitura
e reservas: duas leituras de contexto, duas consultas adicionais de evidência,
duas submissões de teste e consulta dos baselines. São reservas de capacidade,
não obrigações de produzir achados/testes, nem autorização para exceder o limite
global de reproduções. As inspeções exigidas são entregues na resposta estruturada;
o planejamento não as conta como ferramenta nem as fabrica. A divisão é equilibrada
por chamadas reais de leitura, considerando também o corte por bytes.

Após revisar e validar, o mesmo comando com `--apply` e outro arquivo de saída novo
registra o mapa de forma imutável no run. Esse registro é uma ação explícita do
operador, fora das ferramentas dos agentes. Alterações de atribuição em qualquer
fase já iniciada, perda/sobreposição de intervalos, divergência de fonte/configuração,
redução dos contadores ou mudança dos checkpoints protegidos são recusadas.
Fases novas e a barreira recebem o identificador da distribuição; a conclusão e
o relatório exigem todos os lotes efetivos. Nenhum lote é concluído pelo ato de
redistribuir. Runs sem esse registro mantêm seu mapa original.

Uma tentativa extraordinária continua exigindo autorização separada para um único
papel/fase/slot. A autorização pode vincular por hash todas as tentativas e checkpoints
anteriores. O mapa não cria tentativas, não amplia tetos e não renova fatos financeiros.
O tipo do item nativo da segunda interrupção histórica do FAEPA continua desconhecido:
melhorar seu diagnóstico não demonstra que a incompatibilidade foi resolvida.

### Compactação automática de contexto

O contrato 0.167.0 define `contextCompaction` como item de ciclo de vida. O auditor
valida as notificações `item/started` e `item/completed`: sessão e turno atuais,
mesmo ID de item, início único e conclusão correspondente. São obrigatórios
`startedAtMs` no início e `completedAtMs` no fim, conforme os contratos arquivados
em `tests/contracts/ItemStartedNotification.json` e `ItemCompletedNotification.json`.
Os timestamps são metadados do cliente; não ajustam relógios, prazos ou conferências
financeiras. IDs de itens não podem mudar de tipo ou ser reutilizados nessa sequência.

Compactação não consome passos de ferramenta, não devolve leitura, não produz
inspeção/cobertura e não substitui resposta final. Turno sem conclusão de compactação
ou sem resposta final permanece interrompido/ambíguo. Os cinco tools existentes,
o contraditório e a barreira cega mantêm seus contratos. Outros itens nativos e tipos
desconhecidos continuam bloqueados; não se amplia permissão de execução.

A validade factual original e os prazos monotônicos são reconferidos ao consumir
eventos, inclusive quando a fila devolve dados imediatamente. A compactação fica
dentro do mesmo turno, reserva e orçamento acumulado, sem reiniciar contadores ou
liberar slots. O controlador registra somente ciclo de vida e correlação por hash,
sem resumo de compactação, frames ou raciocínio privado.

O texto JSON enviado ao cliente usa serialização sem espaços entre campos. O manifesto
integral permanece no controlador; `agent-manifest-1` fornece o objetivo e as restrições
originais, hashes verificáveis e o catálogo compacto de toda fonte legível. Os metadados
integrais continuam consultáveis com `list_source(offset, limit)`. Depois de uma entrega
comprovada em turno concluído da mesma sessão/papel, entradas posteriores referenciam
o catálogo, sem repeti-lo. Compactação pode exigir nova consulta; referência não é
leitura ou inspeção. O histórico não é apagado, reescrito ou resumido pelo controlador.
Essa redução de bytes não garante evitar compactação: o histórico acumulado continua
sujeito ao cliente oficial. Veja [contexto dos agentes](contexto-dos-agentes.md).

Regressões reproduzíveis, somente locais e sem provocar compactação real:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv/bin/python -m pytest -q tests/test_context_compaction.py
```

A fixture declara os campos reconstruídos: ID sintético, correlações substituídas,
timestamp não preservado no diagnóstico e notificação de conclusão sintética.
O segundo bloqueio histórico continua com tipo desconhecido. A correção local do
terceiro evento não reclassifica os registros anteriores nem recupera sua tentativa.

### Exceção encadeada após um slot extraordinário consumido

`chained-extra-attempt-1` permite somente um slot fixo após a primeira autorização
extraordinária existente. O registro `roles/PAPEL/attempts/FASE-extra-authorization-v2`
é novo e imutável; não substitui a autorização anterior. Exige autorização explícita
para aquele papel/fase/slot e vínculo por hash ao pai, às tentativas/checkpoints
anteriores e às respectivas confirmações oficiais `interrupted`. Estado ativo,
concluído, de outra sessão ou sem evidência oficial é recusado.

A autorização também vincula fonte, configuração, perfil, distribuição, atribuição,
sessão do papel, backend e versão congelada do pacote. O verificador confere os
hashes dos arquivos carregados e preserva o prefixo do ledger e o piso de tempo
acumulado. A versão congelada preserva os mesmos contadores anteriores. Não há
liberação de um slot seguinte por falha, resposta inválida, falta de envio ou timeout.
Uma tentativa válida pode prosseguir para as fases normais, com seus slots originais.

Essa autorização é preparação local do operador, separada da confirmação financeira.
Ela não inicia inferência, não renova seu horário e não altera tetos, modelos, esforço,
serviço ou permissões de ferramenta. Antes da execução continuam obrigatórios o
preflight oficial e os fatos financeiros atuais na mesma conta. Uma nova versão ou
um registro de autorização não transforma correção local em validação real do auditor.

Rejeições do protocolo guardam `runtime-protocol-diagnostic-1` no checkpoint e em
evento autenticado: método, tipo reconhecido no contrato fixado, papel, fase,
índice da tentativa, contagem e identificadores de correlação. Nomes desconhecidos
e identificadores fornecidos pelo par são registrados por hash. Não são gravados
frames, argumentos, texto de itens, raciocínio ou credenciais. Falta histórica do
tipo rejeitado permanece desconhecida; não se deduz o tipo pela proximidade de
outros eventos. Tanto `item/started` quanto `item/completed` rejeitam itens fora
da lista restrita existente; reconhecer um nome para diagnóstico não o autoriza.

Um timeout não libera repetição automática. Quando `thread/read` do cliente oficial
confirma o turno como `interrupted`, uma revisão explícita pode registrar
`attempt-N-interrupted`, vinculada ao mesmo invocation/thread/turn. A retomada
consome somente o próximo slot que já exista no limite configurado, preservando o
checkpoint e o ledger anteriores. Estado ativo, desconhecido ou divergente bloqueia
a recuperação; turno concluído exige recuperação de saída, não repetição. O marcador
não substitui o preflight financeiro nem renova a conferência. Fases já aceitas e
receipts existentes continuam em cache. O diagnóstico de timeout agora registra
papel, fase, operação aguardada, origem do prazo e último evento, sem ampliar limites.

Um ajuste posterior de timeout requer autorização explícita e diagnóstico de
atividade normal interrompida pelo prazo. O registro autenticado
`operational/turn-timeout-authorization` vincula o ajuste ao run, ao hash da
configuração original e ao checkpoint diagnosticado. Só pode elevar esse parâmetro
até 300 segundos; não muda a configuração congelada, slots, tentativas, chamadas,
tempo total ou fatos financeiros. O prazo efetivo continua sendo o menor entre o
limite autorizado, o tempo global acumulado restante e a validade financeira.
Uma interrupção oficial revisada ainda é necessária para consumir um slot que já
exista; esse ajuste não autoriza repetir automaticamente turnos ambíguos.

Na observação intermediária do controlador, `receipt_observation` distingue uma
reprodução executada com receipt ainda oculto pela barreira de reprodução não
executada, execução incompleta e tentativa sem receipt de resultado desconhecido.
Isso não publica evidência para os outros papéis. A aceitação final continua
exigindo o protocolo completo, inspeções e julgamento; a existência de uma
reprodução não aprova um parecer nem substitui essas etapas.

Uma extensão global excepcional para concluir somente `juiz/final` usa o registro
autenticado `operational/global-time-extension-authorization`. O limite original
permanece no config e a reprovação sob esse limite é preservada. A extensão aceita
no máximo 1.500 segundos acumulados e exige snapshot das chamadas, do tempo já
gasto e dos hashes das fases anteriores. O runtime recusa gerar novamente qualquer
outra fase, zerar histórico ou ignorar fase anterior pendente. Não abre slots,
não aumenta chamadas, não muda o limite por turno nem renova fatos financeiros.
O ajuste só existe mediante autorização explícita; não é recuperação automática.

Pareceres iniciais são congelados por hash antes da barreira. Há contestação/réplica
e no máximo uma rodada adicional por nova evidência material. O Juiz faz inspeção cega
antes de conhecer pareceres. Nenhuma mudança pode ser exigida por gosto arquitetural.
Consenso não demonstra defeito.

## Smoke sintético

A fixture `codex-smoke` contém um defeito no estorno e uma proteção correta em outra
camada. O teste exige três IDs distintos, barreira, consultas de fonte pelos três,
receipt Docker real e relatório final com um defeito reconhecido sem acusar o caso
protegido. Não mede qualidade geral nem resistência universal a falsos positivos.

Para o validador, crie um JSON privado de confirmação factual, sem credenciais:

```json
{
  "source": "operator_factual_confirmation",
  "checked_at": "INSTANTE_ISO_UTC_DA_CONFERENCIA",
  "account_fingerprint": "FINGERPRINT_DO_DOCTOR",
  "auto_recharge": "disabled",
  "extra_credits": "none"
}
```

No terminal normal, após login específico e conferência factual:

```bash
.venv/bin/python scripts/validate_pending.py --codex \
  --financial-confirmation /caminho/privado/fatos.json
```

O validador não fabrica os fatos nem renova a data. Sem confirmação, execute somente
`.venv/bin/python scripts/validate_pending.py`: sete casos Docker, smoke não executado.
As imagens locais existentes não precisam de reconstrução para a migração.

## Relatórios e referências

Manifests identificam backend, versão alvo do cliente e modelos; o registro `runtime`
contém configuração efetivamente confirmada. Antes disso, esforço/autenticação e
situação financeira aparecem desconhecidos. Amostras oficiais de tokens são
registradas com sua base (última request e acumulado da thread, sem somá-las como
consumo de turnos). Totais não demonstrados permanecem desconhecidos, sem preço API nem promessa de quantidade fixa de auditorias.

O processo Codex pode manter suas sessões privadas no HOME do auditor. Elas não são
exportadas: exportação inclui evidências, justificativas estruturadas e hashes, não
credenciais, wire frames ou raciocínio privado. O código enviado é processado
remotamente pela OpenAI sob as políticas da conta, mesmo com Docker local.

### Prazo e observação do despacho

Antes de escrever `turn/start`, o transporte reconfere o menor prazo monotônico
global, por turno e financeiro, depois de construir e serializar a requisição.
Também verifica novamente a validade factual do horário financeiro original.
Atrasos de reserva ou persistência não estendem o prazo. Comandos de interrupção
de um turno existente continuam disponíveis depois desse prazo.

Se nenhuma escrita foi tentada, checkpoint e ledger registram `not_sent`.
A reserva continua contando no limite e a retomada não reenvia automaticamente.
`written` comprova apenas a escrita local; `write_uncertain` registra uma falha
durante a tentativa de escrita. Sem resposta final confirmada, ambos preservam
o estado ambíguo e a recuperação explícita já exigida. Nenhum desses estados
converte consumo desconhecido em zero ou renova fatos financeiros.

A regressão local usa somente pipes em memória e relógio controlado:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q tests/test_dispatch_deadline.py
```

Fontes oficiais consultadas em 10 e 11/11/2026:

- [App Server e ferramentas dinâmicas](https://learn.chatgpt.com/docs/app-server)
- [Changelog: suporte a planos Pro Lite e Pro Max](https://learn.chatgpt.com/docs/changelog?date=2026-09-10&index=2)
- [SDK Python e TypeScript](https://learn.chatgpt.com/docs/codex-sdk)
- [Autenticação](https://learn.chatgpt.com/docs/auth)
- [Modelos](https://learn.chatgpt.com/docs/models)
- [Velocidade](https://learn.chatgpt.com/docs/agent-configuration/speed)
- [Permissões beta](https://learn.chatgpt.com/docs/permissions)
- [Franquia e preços](https://learn.chatgpt.com/docs/pricing)
- [Uso de créditos extras](https://help.openai.com/en/articles/12642688-using-credits-for-flexible-usage-in-chatgpt-personal-plans)
- [Código oficial](https://github.com/openai/codex)
