# Primeiros passos: instalar, executar e entender os resultados

Este guia usa a **versão acadêmica**. Não é necessário acesso de administrador para
compilar, simular ou usar o editor. O teste de firewall real ocorre dentro do laboratório
Linux do Docker, sem alterar o firewall do Windows.

## 1. Preparar as ferramentas

| Ferramenta | Para que serve | Necessária quando |
|---|---|---|
| Git | Baixar o projeto e escolher a branch | Sempre |
| Python 3.12 | Executar o compilador e a linguagem | Sempre |
| Poetry 2.4.1 | Instalar dependências isoladas e reproduzíveis | Sempre |
| Node.js 24 | Construir e testar a extensão | Desenvolvimento do editor / portão completo |
| VS Code | Autocomplete, tipos e diagnósticos | Opcional |
| Docker com engine Linux e Compose | Laboratório de firewall real | Opcional |

Instalar as ferramentas pelos distribuidores oficiais. Poetry pode ser instalado com
`pipx install poetry==2.4.1` quando pipx já estiver disponível. Não instalar os pacotes do
projeto com `pip install` avulso. Conferir antes de continuar:

```sh
git --version
python --version
poetry --version
node --version
docker version
docker compose version
```

Python deve ser da série 3.12. Se houver várias versões no Windows, localizar a 3.12 com
`py -0p` e selecionar seu caminho com `poetry env use CAMINHO_DO_PYTHON_312`.
No Linux, quando disponível, usar `poetry env use python3.12`.

## 2. Baixar a versão acadêmica

```sh
git clone --branch feat/academic-presentation https://github.com/Mathwesm/NetSec.git
cd NetSec
poetry install
```

Os comandos seguintes partem da raiz, onde está `pyproject.toml`. No PowerShell:

```powershell
$env:PYTHONUTF8 = '1'
```

Não é necessário ativar o ambiente virtual manualmente. `poetry run` seleciona o ambiente.
Não é obrigatório criar `.env` para os exemplos.

## 3. Executar os três exemplos válidos

```sh
poetry run netsec run examples/01_audit.netsec --scenario examples/scenario.json
poetry run netsec run examples/02_policy.netsec --scenario examples/scenario.json
poetry run netsec run examples/03_scopes.netsec --scenario examples/scenario.json
```

| Exemplo | O que demonstra | Resultado esperado |
|---|---|---|
| `01_audit.netsec` | Inventário, portas, serviços e report | `success: true`, modo simulate |
| `02_policy.netsec` | Tipos de porta/protocolo e firewall | Regras aplicadas no cenário, sem firewall real |
| `03_scopes.netsec` | Rede, precedência, if, repeat e escopo | Checks HTTP e valor externo preservado |

Os IPs `192.0.2.x` são de documentação. O cenário informa as respostas e não acessa esses
endereços pela rede. Ler o campo `mode` evita confundir simulação com execução real.

## 4. Ver cada fase do compilador

```sh
poetry run netsec tokens examples/03_scopes.netsec
poetry run netsec ast examples/03_scopes.netsec
poetry run netsec check examples/03_scopes.netsec
poetry run netsec compile examples/03_scopes.netsec
```

Tokens conservam posição. AST mostra estrutura. `check` valida o programa. `compile`
mostra instruções já resolvidas. Nenhum desses quatro comandos executa sondas ou firewall.

## 5. Ver um erro semântico deliberado

```sh
poetry run netsec check examples/04_rejected.netsec
```

Esperado: `E_FIREWALL_CONFLICT` na linha 12, coluna 5 e código de saída 2. Esse resultado
é o teste correto, não uma instalação quebrada. Há sintaxe válida e regras contraditórias
para o mesmo IP/porta/protocolo. No PowerShell, consultar `$LASTEXITCODE`; no shell Linux,
consultar `$?` imediatamente após o comando.

## 6. Instalar o editor e executar a qualidade

```sh
npm --prefix editor/vscode ci --ignore-scripts
poetry run pre-commit install
poetry run poe gate
npm --prefix editor/vscode run package
code --install-extension editor/vscode/netsec-language-0.1.0.vsix
code .
```

Abrir a raiz e um `.netsec`. Marcar a pasta como confiável somente após conferir seu
conteúdo. Se `code` não estiver no PATH, usar no VS Code “Extensions: Install from VSIX”.
Se o compilador não for localizado, verificar `poetry run netsec --help` no terminal da
mesma pasta. `netsec.command` e `netsec.arguments` permitem ajustar a extensão.

## 7. Testar firewall Linux real

Iniciar o Docker Desktop em modo Linux no Windows, ou o daemon Docker no Linux:

```sh
docker compose -f lab/compose.yaml up -d --build
poetry run netsec lab-test
docker compose -f lab/compose.yaml stop
```

A primeira construção pode baixar imagens e dependências. O teste precisa indicar
`success: true` e uma pasta nova em `data/processed/`. Abrir o `summary.json` dessa pasta:
as quatro verificações devem ser `true`. TCP/23 deve funcionar antes e sofrer timeout
depois do bloqueio. SSH e HTTP precisam continuar acessíveis. Reaplicar não duplica regras.

O comando de parada afeta somente o laboratório descrito nesse Compose. Não executar
limpezas globais do Docker. Ver [laboratório](laboratorio.md) para detalhes.

## 8. Avaliar e guardar resultados

```sh
poetry run netsec evaluate
poetry run netsec compile examples/02_policy.netsec --output data/manual/plan-01.json
```

O arquivo de saída deve ser novo. O executor não sobrescreve uma evidência existente.
O corpus tem 25 erros e 10 controles e mede somente esses casos, não toda situação possível.

## Problemas comuns

| Sintoma | Verificação |
|---|---|
| Poetry recusa Python | Selecionar Python 3.12, não 3.13/3.14 |
| Arquivo de exemplo não encontrado | Executar a partir da raiz do repositório |
| `Simulation requires --scenario` | Passar o JSON explícito mostrado no exemplo |
| Docker não conecta | Iniciar o daemon e confirmar engine Linux em `docker version` |
| Container não está rodando | Executar o `compose up` antes do `lab-test` |
| Porta 23 falha após a política | Esse é o bloqueio esperado no teste |
| `network` recusa firewall | Esse modo só faz sondas; usar o laboratório acadêmico |
| Arquivo de saída já existe | Escolher outro nome, preservando a execução anterior |

Para a fala em equipe, seguir [divisão dos apresentadores](equipe-apresentacao.md) e
[demonstração](demonstracao.md). Evolução nativa/remota pertence à branch profissional.
