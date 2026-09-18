# Demonstração da linguagem

Roteiro para a apresentação de 20 slides e aproximadamente 12 minutos. A demonstração
ao vivo acompanha os slides 12 e 14. Os exemplos e o compilador são os mesmos do marco
acadêmico `5a56802`; o material não depende de funcionalidades futuras.

## Preparação, antes da apresentação

1. Na raiz do repositório, executar `poetry run poe gate`.
2. Abrir a pasta no VS Code, com a extensão NetSec instalada.
3. Abrir os quatro exemplos `.netsec`, `src/netsec/core/compiler.py` e
   `src/netsec/runtime.py` para perguntas sobre implementação.
4. Iniciar o Docker e executar `docker compose -f lab/compose.yaml up -d`.
   Na primeira preparação, acrescentar `--build`. Não gastar o tempo da fala baixando
   dependências ou construindo a imagem.
5. Executar `poetry run netsec lab-test` antes do ensaio para confirmar que o ambiente
   está funcionando. Guardar a pasta de evidências indicada pelo comando.

## Sequência curta ao vivo

### 1. Editor e programa válido

Abrir `examples/02_policy.netsec`. Mostrar `admin_port`, seu tipo, hover e ida à declaração.
Digitar temporariamente `int broken = true;` em um bloco válido, observar `E_TYPE` e
desfazer essa edição. Não salvar alterações acidentais no exemplo original.

```sh
poetry run netsec check examples/02_policy.netsec
poetry run netsec run examples/02_policy.netsec --scenario examples/scenario.json
```

O primeiro comando compila sem tocar na rede. O segundo usa dados simulados explícitos.
Explicar `mode: simulate`, a ação aplicada e os registros de cada instrução.

### 2. Rejeição semântica

```sh
poetry run netsec check examples/04_rejected.netsec
```

Resultado esperado: saída 2 e `E_FIREWALL_CONFLICT` em linha 12, coluna 5. A sintaxe é
válida. Dois grupos diferentes apontam para `192.0.2.10` e pedem ações opostas em TCP/22.
O objeto de diagnóstico conserva também a posição da regra anterior.

### 3. Rede e firewall reais

```sh
poetry run netsec lab-test
```

O teste redefine apenas as regras gerenciadas pela NetSec nos containers de laboratório.
Depois comprova conectividade inicial, bloqueio de TCP/23, preservação de SSH e HTTP e
reaplicação com `unchanged`. O firewall do Windows não é alterado. A porta 23 é uma fixture
TCP para o teste, não uma instalação completa de Telnet.

Abrir `summary.json` na pasta retornada pelo comando e mostrar as quatro verificações.
Se Docker estiver indisponível durante a apresentação, usar as evidências da preparação,
dizendo explicitamente que são de uma execução anterior. Não chamar a simulação de
teste real e não apresentar uma gravação como execução ao vivo.

## Comandos para a arguição

```sh
poetry run netsec tokens examples/03_scopes.netsec
poetry run netsec ast examples/03_scopes.netsec
poetry run netsec compile examples/03_scopes.netsec
poetry run netsec evaluate
```

`tokens` mostra posições, `ast` mostra a estrutura e `compile` exibe as instruções
após resolução de nomes e expansão do fluxo estático. `evaluate` mede os 25 erros
semânticos deliberados e 10 controles. O conjunto sintético não prova completude.

## Perguntas que cada integrante deve saber responder

- Por que uma string com formato de IP não é uma variável do tipo `ip` automaticamente?
- Qual é a diferença entre erro léxico, sintático, semântico e falha de execução?
- Onde o compilador implementa precedência e escopos?
- Por que dois grupos com nomes diferentes ainda podem entrar em conflito?
- Como `if` e `repeat` funcionam sem depender do resultado de um check?
- Qual parte do experimento usa simulação e qual parte observa pacotes reais?
- Por que `report "success"` não comprova que uma ação anterior funcionou?
- O que acontece se um host falha depois de outro ter recebido uma regra?

## Depois da demonstração

```sh
docker compose -f lab/compose.yaml stop
```

Esse comando para somente o laboratório identificado no arquivo Compose. Não remover
imagens, volumes, containers de outros projetos ou evidências para limpar a apresentação.
