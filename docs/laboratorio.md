# Laboratório real de rede

## Ambiente

Docker Desktop com containers Linux no Windows, ou Docker Engine + Compose no Linux.
O Compose cria uma rede interna e três containers identificados por rótulo:
`netsec-language-probe`, `netsec-language-web01` e `netsec-language-web02`.
Não publica portas no Windows, não monta o socket Docker nos containers e não altera
regras de firewall do computador. Somente os alvos recebem a capability NET_ADMIN.

A imagem contém Python 3.12, a NetSec, OpenSSH e nftables. O servidor HTTP e o listener
TCP/23 são fixtures do laboratório. TCP/23 não implementa um servidor Telnet completo.
SSH é fornecido por OpenSSH, sem habilitar autenticação por senha ou login root.

O subnet padrão é `172.30.249.0/24`. Se conflitar com uma rede existente, altere
o Compose, o inventário e os três programas de demonstração em conjunto.

## Executar

Na raiz do repositório:

```sh
docker compose -f lab/compose.yaml up -d --build
poetry run netsec lab-test
```

O teste:

1. Confere rótulo, estado e IP dos containers selecionados.
2. Limpa apenas regras identificadas pela NetSec nesses alvos, para repetir o experimento.
3. Verifica que TCP/23, SSH e HTTP respondem nos dois hosts.
4. Aplica bloqueio TCP/23 e permissão TCP/22; verifica SSH e HTTP.
5. Reaplica e exige que as regras retornem `unchanged`.
6. Exige timeout nas conexões TCP/23 depois do bloqueio.

A limpeza inicial é própria do comando de teste. `run` não remove políticas previamente
aplicadas por outros programas, exceto ao substituir uma regra gerenciada oposta para
a mesma tripla IP/porta/protocolo.

Os resultados são gravados em `data/processed/lab-<timestamp>-<id>/`, sem sobrescrever
execuções anteriores. `summary.json` deve conter quatro valores verdadeiros. O teste
encerra com código diferente de zero se qualquer evidência falhar.

## Demonstração por etapas

Em um laboratório recém-criado:

```sh
poetry run netsec run lab/before.netsec --mode docker --inventory lab/inventory.json
poetry run netsec run lab/protect.netsec --mode docker --inventory lab/inventory.json
poetry run netsec run lab/protect.netsec --mode docker --inventory lab/inventory.json
poetry run netsec run lab/after.netsec --mode docker --inventory lab/inventory.json
```

A última execução retorna código 1 **intencionalmente**: o check tenta abrir a porta
bloqueada e registra timeout. O comando `lab-test` interpreta essa falha de conectividade
como a evidência esperada e retorna 0 quando todo o experimento passa.

Para parar sem apagar os containers:

```sh
docker compose -f lab/compose.yaml stop
```

Para recomeçar os containers parados:

```sh
docker compose -f lab/compose.yaml start
```

Se o comando Docker não estiver no PATH, passe seu caminho com
`--docker-executable` a `run` ou `lab-test`. O código não contém caminhos particulares
de um computador.

## Limitações operacionais

Regras pertencem à tabela `inet netsec`, chain `input`. Mudanças de uma regra são
transações nftables no alvo, mas não existe transação que envolva todos os hosts.
Políticas de outras tabelas ainda podem bloquear um tráfego permitido pela NetSec.
O adaptador não é um administrador remoto genérico: Windows Firewall, equipamentos
físicos, credenciais SSH e instalação de pacotes em servidores não foram implementados.

A rede é interna, mas o build precisa baixar imagem e pacotes. A suíte unitária não
depende desse laboratório; o job de integração no CI executa a demonstração real.
