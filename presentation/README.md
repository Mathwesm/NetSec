# Apresentação acadêmica da NetSec

20 slides, em português, com notas de fala em todos os slides. A identidade visual
reproduz a referência `NetSec Apresentacao_v.pdf`: azul-marinho `0B1324`, ciano `10BCD8`,
roxo `7B6FF0`, títulos Arial, corpo Calibri e código Courier New.

O PDF de referência não contém masters editáveis. O deck reconstrói o padrão visual
com texto, tabelas, diagrama e gráfico editáveis. Ícones rasterizados usam Font Awesome
Free via react-icons. A atribuição e os links de fontes ficam nas notas.

## Gerar uma nova versão

```sh
npm --prefix presentation ci --ignore-scripts
npm --prefix presentation run check
node presentation/build.cjs data/presentation-build/revision-01
node presentation/verify.cjs data/presentation-build/revision-01/NetSec_Apresentacao_Academica.pptx
```

O diretório final do comando deve ser novo. O gerador recusa reaproveitá-lo para evitar
sobrescrever um resultado. Ele produz um PowerPoint, um roteiro de fala Markdown e um
manifesto privado para conferência. As dependências de slides não entram no runtime Python.

## Versão entregue

- [PowerPoint de 20 slides](outputs/2026-09-18/NetSec_Apresentacao_Academica.pptx).
- [Notas de fala em Markdown](outputs/2026-09-18/Roteiro_de_fala.md).

O roteiro soma 11 minutos e 15 segundos, deixando aproximadamente 45 segundos para
transições em uma apresentação de 12 minutos. As notas também estão dentro do PowerPoint.

`image-size` tem override para 2.0.4 devido aos avisos GHSA-w3rx-r6r6-pgpr e
GHSA-5p2g-fcmc-qvqq. O gerador fornece geometria explícita para imagens e não usa
parsers ICNS/JXL/HEIF. `npm audit` deve continuar sem alertas.

## Conferência visual

O arquivo `Dockerfile.qa` prepara LibreOffice e Poppler em uma imagem de apoio, sem
modificar a instalação do computador. Construir com:

```sh
docker build -f presentation/Dockerfile.qa -t netsec-presentation-qa:local presentation
```

Renderizar o PPTX para PDF em um diretório de trabalho montado e converter as páginas
com `pdftoppm`. Conferir todos os slides, inclusive tabelas, gráfico e notas. O container
não precisa de NET_ADMIN, rede do laboratório ou acesso ao socket Docker.

Os resultados apresentados pertencem ao marco acadêmico `5a56802`, validado em
18/09/2026. Alterar números exige executar novamente os testes ou a avaliação e
atualizar as fontes. A linguagem e o firewall Windows não foram ampliados nesta branch.

O [roteiro da demonstração](../docs/demonstracao.md) separa preparação, fala e comandos.
A [evolução profissional](../docs/evolucao.md) está planejada em branch própria.
