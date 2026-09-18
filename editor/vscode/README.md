# NetSec para VS Code

Suporte a arquivos `.netsec`: cores, snippets, autocomplete de nomes e tipos,
hover, navegação para declaração e erros do próprio compilador com linha e coluna.

Abra a **raiz do projeto NetSec**, execute `poetry install` e instale o VSIX.
O comando padrão é `poetry run netsec editor`. Para um compilador já instalado,
configure `netsec.command` e `netsec.arguments`.

A extensão analisa o texto ainda não salvo. Não executa verificações de rede
nem aplica firewall ao digitar. Exige um workspace confiável para iniciar o compilador.

## Desenvolvimento

```sh
npm ci
npm run check
npm test
npm run package
```

O pacote gerado pode ser instalado com `code --install-extension netsec-language-0.1.0.vsix`.
