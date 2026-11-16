# Aquisição de arquivos locais e dependências de execução

`prepare --directory` congela os bytes atuais de um diretório revisado, inclusive
arquivos fora do HEAD. Não faz checkout, `git status`, build ou execução da fonte.
Links e arquivos especiais são recusados; limites por arquivo, quantidade e tamanho
total continuam obrigatórios. Use uma cópia privada do escopo autorizado, sem
segredos e resultados históricos desnecessários. Registre separadamente a origem,
os hashes e todas as omissões. Não passe `--ref` com `--directory`.

```bash
.venv/bin/audit3 --store /caminho/privado/store prepare --directory \
  --repo /caminho/privado/copia-revisada --profile /caminho/perfil-operador.json \
  --config /caminho/config.json --requirements /caminho/requisitos.txt \
  --source-review /caminho/revisao-aquisicao.json
```

O perfil é sempre confiável e explícito do operador, fora da fonte recebida.
Nenhuma confirmação financeira é necessária para preparar ou testar localmente.
Inferência continua exigindo todos os controles existentes e fatos atuais.

## Dependências preservadas

O campo opcional `runtime_include` do config contém padrões explícitos, por
exemplo `vendor/**` e `assets/vendor/**`. Só aceita dependências, recursos binários
ou artefatos gerados já excluídos da análise. Não pode ocultar código próprio
classificado como fonte, configurações secretas, chaves ou credenciais.

Os registros ficam com `category: excluded` e `runtime_only: true`. Seus bytes são
preservados no snapshot readonly e verificados antes das execuções e avaliações;
o executor usa exatamente essa árvore. As ferramentas de leitura, busca e
validação de referências dos modelos continuam negando acesso a esses arquivos.
Eles não preenchem investigação cega, cobertura de código próprio ou prova causal.

Essa separação controla a leitura direta e o envio automático de dependências;
não é uma garantia de sigilo contra código de teste dentro do container. Um teste
pode ler bibliotecas que precisa executar e imprimir trechos nos resultados.
Portanto, o runtime não pode conter credenciais ou documentos operacionais reais.
Fonte/runtime e saídas precisam ser revisados conforme o objetivo autorizado.

O relatório apresenta `coverage.runtime_dependencies` separado de omissões reais.
Preservar uma biblioteca não prova sua segurança ou compatibilidade. Versões,
efeitos e dependências necessárias ao objetivo precisam de evidências de testes;
nenhuma revisão narrativa pode dispensar uma falta de execução ou fonte alterada.

## Revisão explícita dos sinais do scanner

O scanner permanece ativo e o comportamento padrão não muda. A revisão opcional
usa `version: source-acquisition-review-1`, identificação em `reviewer`, o objetivo
original em `objective`, `inventory_hash`, `semantic_responsibility: reviewer` e
um mapa `files`. Não é uma lista de nomes ou frases dispensadas.

O hash do inventário é `object_hash` da lista ordenada de objetos `path` e
`sha256` de todos os bytes adquiridos. Cada decisão contém `sha256` do arquivo,
`justification` específica e `matches` com **todos** os sinais atuais. Cada sinal
contém `pattern`, intervalos de caracteres `start`/`end` (fim exclusivo), hash do
trecho em `sha256`, hash da linha em `context_sha256`, `kind` e `justification`.
`audit3.acquisition_review.scanner_matches(text)` fornece os fatos, sem classificar
automaticamente sua interpretação. O revisor deve examinar cada ocorrência.

Os tipos suportados são contatos públicos estáticos de código e exemplos sintéticos
(`public_code_contact`, `synthetic_example`), metadados de autores de dependências
(`dependency_author_metadata`), exemplos de formato em placeholders
(`input_format_example`) e expressões de código confundidas com atribuições de
segredos (`code_expression`). Tokens, chaves e senhas literais continuam bloqueados.
Não use esses tipos para liberar contas, dados pessoais, documentos ou credenciais
reais. Não transforme um dado sensível em exemplo apenas escolhendo um rótulo.

A máquina confere hashes, proveniência, todos os intervalos e condições do tipo.
O revisor responde pela pertinência semântica: por exemplo, confirmar que o e-mail
é um contato estático publicável no código, não uma conta privada de operação.
Texto livre sozinho não basta e o mecanismo não comprova essa interpretação por
análise semântica automática. Se houver dúvida, o arquivo permanece excluído e a
lacuna continua bloqueando o escopo correspondente.

A revisão é armazenada autenticada e vinculada ao manifest por hash. Mudança de
arquivo, inventário, objetivo, sinal ou contexto exige nova revisão. Isso não
modifica os bytes, não altera pareceres antigos nem transforma runs históricos em
execuções da implementação nova. Configs e manifests antigos mantêm a serialização
quando os campos opcionais não são usados.
