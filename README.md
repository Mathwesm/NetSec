# NetSec

Esta é a **linha profissional 0.3**, em `feat/professional-platform`.
A apresentação de 20 slides, os quatro apresentadores e o roteiro da disciplina ficam
preservados em `feat/academic-presentation`.

Comece pelo [guia profissional passo a passo](docs/profissional.md): instalação, interface
Windows/UAC, firewall nativo, SSH, DNS, funções e recuperação após falhas.
O [guia de serviços e automação](docs/servicos-e-automacao.md) cobre classes, módulos,
HTTP/DNS Linux, jobs persistentes Windows/Linux, paralelismo e assinatura opcional.

Também inclui [VPN WireGuard Linux](docs/vpn.md), com manifesto tipado, prévia offline,
chave privada por variável de ambiente e verificação de handshake. O módulo é um comando
de recursos (`netsec vpn`), separado da gramática `.netsec`.

Linguagem com tipos explícitos para inventários por IP, verificações de rede e políticas
de firewall. Possui compilador e executor próprios, diagnósticos com arquivo/linha/coluna
e extensão para VS Code. Um programa inteiro é validado antes de qualquer ação de rede.

```netsec
port admin = port(22);
group servers {
    host "server01" address "192.0.2.10";
}
play "security_check" targets servers {
    check port admin protocol tcp;
    check service "ssh";
    firewall deny port 23 protocol tcp;
    firewall allow port admin protocol tcp;
    report "Security checks completed.";
}
```

O compilador rejeita duas regras opostas para a mesma combinação de IP, porta e protocolo,
inclusive quando o IP aparece em grupos diferentes. A linguagem também oferece expressões
com precedência, `if/else`, `repeat` e escopos lexicais.

## Instalação

Necessário: Python **3.12** e Poetry **2.4.1**. Para desenvolver a extensão e executar o
portão completo, use Node.js **24**. Docker só é necessário para o laboratório real.
VS Code é necessário apenas para usar a extensão.

```sh
git clone --branch feat/professional-platform https://github.com/Mathwesm/NetSec.git
cd NetSec
poetry install
npm --prefix editor/vscode ci --ignore-scripts
poetry run pre-commit install
```

No PowerShell, use `$env:PYTHONUTF8='1'` se o terminal tiver problemas de acentuação.
O código abre arquivos explicitamente em UTF-8. `.env.example` mostra configurações
opcionais; copiar para `.env` não é obrigatório. Não há credencial necessária para os exemplos.

## Primeiro programa: simulação reproduzível

```sh
poetry run netsec run examples/01_audit.netsec --scenario examples/scenario.json
poetry run netsec run examples/02_policy.netsec --scenario examples/scenario.json
poetry run netsec run examples/03_scopes.netsec --scenario examples/scenario.json
poetry run netsec run examples/07_classes_modules.netsec --scenario examples/scenario.json
```

Os IPs `192.0.2.0/24` dos exemplos são dados de documentação, não máquinas acessadas pela
simulação. Respostas vêm explicitamente do cenário; o executor não inventa resultados.
O JSON identifica `mode: simulate`. Para gravar, acrescente `--output` com um caminho novo.
Arquivos existentes nunca são sobrescritos.

## Inspecionar cada fase

```sh
poetry run netsec tokens examples/01_audit.netsec
poetry run netsec ast examples/01_audit.netsec
poetry run netsec check examples/01_audit.netsec
poetry run netsec compile examples/01_audit.netsec
poetry run netsec check examples/04_rejected.netsec
```

O último comando deve falhar com `E_FIREWALL_CONFLICT`: é o exemplo de programa com sintaxe
válida e política inválida. `compile` exibe o plano de instruções próprio da NetSec;
`run` compila e entrega esse plano ao executor. Os comandos de inspeção não acessam a rede.

Saídas: **0** sucesso; **1** execução com observação que falhou; **2** entrada inválida,
erro de compilação ou impossibilidade de iniciar. Em `probe`, o transporte retorna 0 para
uma observação concluída, e o campo JSON `success` informa a conectividade; esse comando
é usado internamente entre os processos do laboratório.

## Rede real e firewall

Para um arquivo com checks e reports direcionados aos seus IPs explícitos:

```sh
poetry run netsec run meu_inventario.netsec --mode network --timeout 2
```

O modo `network` faz sondas reais a partir da máquina local. O modo `local` administra
nftables/NetSecurity; `ssh` administra servidores Linux autenticados. Ambos exigem
`--apply` para regras de firewall. `preview` é estritamente offline e `doctor` é somente
leitura. O adaptador `docker` continua disponível para o laboratório original:

```sh
docker compose -f lab/compose.yaml up -d --build
poetry run netsec lab-test
docker compose -f lab/compose.yaml stop
```

O teste prova conectividade inicial, bloqueio de TCP/23, preservação de SSH/HTTP e
idempotência. Evidências ficam em uma pasta nova de `data/processed/`.
Veja [o roteiro do laboratório](docs/laboratorio.md), inclusive o significado da falha
esperada de conectividade depois do bloqueio.

## Autocomplete e diagnósticos no VS Code

```sh
npm --prefix editor/vscode run package
code --install-extension editor/vscode/netsec-language-0.3.0.vsix
code .
```

Abra a raiz do repositório e um arquivo `.netsec`. A extensão oferece cores, snippets,
nomes visíveis com tipo, campos/métodos após `.`, imports, hover, ir à declaração e erros
do compilador no painel Problems.
Ela analisa o conteúdo ainda não salvo; não executa rede ao digitar. Usa por padrão
`poetry run netsec editor`, configurável em `netsec.command` e `netsec.arguments`.

## Testes e avaliação acadêmica

```sh
poetry run poe gate
poetry run netsec evaluate
```

O portão executa Ruff, mypy estrito, pytest, detecção de segredos e testes/tipos do editor.
A suíte Python usa entradas sintéticas, `tmp_path` e substitutos para rede e processos.
O laboratório é uma verificação de integração separada. O CI executa o portão em Windows
e Linux, além do laboratório em Linux. Dependabot verifica dependências semanalmente.

`evaluate` mede **25 programas com erros semânticos e 10 controles válidos**. Cada caso
roda 10 vezes. O JSON registra diagnósticos esperados/observados e tempo mediano; um
Markdown resume a matriz de resultados. Cada execução usa um diretório novo, e
`data/processed/latest.txt` aponta para a avaliação concluída mais recente.

## Organização e material da disciplina

- [Especificação, EBNF, tokens e decisões](docs/especificacao.md).
- [Validação profissional 0.3, desempenho e limites](docs/validacao-0.3.md).
- [Arquitetura e guia de estudo para a arguição](docs/arquitetura.md).
- [Datas e critérios das entregas](docs/entregas.md).
- [Laboratório e reprodução da demonstração](docs/laboratorio.md).
- [Resultados da validação local](docs/validacao-2026-09-18.md).
- `src/netsec/core/`: lexer, parser, tipos e compilador.
- `src/netsec/runtime.py` e `services/`: executor e adaptadores.
- `editor/vscode/`: extensão; `tests/`: regressões e comportamentos.

## Limitações atuais

Condições são estáticas; não dependem do resultado dos checks. Declarações são imutáveis.
Há funções e métodos puros tipados, classes imutáveis e imports relativos. Não há herança,
funções com efeitos de rede no corpo, recursão ou tratamento de exceções na NetSec.
O compilador informa o primeiro erro, sem recuperação para listar todos de uma vez.

Checks verificam TCP, identificação SSH e HTTP/HTTPS; não constituem um scanner completo
de vulnerabilidades. HTTPS exige certificado válido para o IP. UDP genérico é recusado;
regras UDP são permitidas. DNS A/AAAA é verificado contra um resolvedor explícito. Firewall
Windows nativo e Linux nativo/SSH estão implementados. Há testes separados de CRUD e de
bloqueio real de tráfego, inclusive com cliente Windows de IP distinto. Não há transação distribuída:
o diário registra instruções concluídas, e reaplicar converge as regras e repete os checks.
Não há alteração de roteador, DNS do sistema, NAT ou política padrão de firewall.

O uso padrão é manual. `automation install --apply` habilita explicitamente jobs persistentes
via systemd ou Task Scheduler. Alertas Telegram são opcionais e exigem credenciais no
ambiente do serviço. HTTP/DNS e VPN são provisionados no Linux; no Windows, há firewall,
checks e jobs de políticas. Não há certificado de assinatura incluído no instalador.
Logs operacionais ficam em `logs/netsec.log`, em JSON, com rotação; não incluem código-fonte
nem conteúdo dos reports. Diários de execução contêm dados operacionais e exigem proteção.
O artigo final, as referências da disciplina e a revisão entre integrantes são entregas
acadêmicas separadas; os arquivos do projeto fornecem implementação e evidências para elas.
