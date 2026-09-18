# Entregas e critérios da disciplina

Base: apresentação da atividade final 2026/2 fornecida à equipe. Em divergência com o
cronograma inicial da NetSec, considerar as datas oficiais abaixo.

| Data | Entrega | Material |
|---|---|---|
| 13/10/2026 | Domínio e propósito | Introdução da especificação |
| 20/10/2026 | Especificação | `docs/especificacao.md`; revisar extensão de 3 a 5 páginas |
| 10/11/2026 | Léxico e sintático | Comandos `tokens` e `ast`, erros localizados |
| 24/11/2026 | Rascunho do artigo | Linguagem executando e avaliação medida |
| 01/12/2026 | Revisão por pares | Participação e resposta da equipe |
| 08/12/2026 | Implementação final | Três exemplos, programa rejeitado, testes e README |
| 12/12/2026 | Artigo final | 4 a 6 páginas, sem referências; duas colunas |
| 15/12/2026 | Demonstração | 12 minutos de apresentação e 8 de arguição |

## Artigo a ser redigido pela equipe

Usar ACM sigconf no Overleaf ou o modelo Word fornecido pelo professor. Seções:
introdução, linguagem, implementação, avaliação, limitações e conclusão. Incluir pelo
menos cinco referências, sendo duas da bibliografia da disciplina, além do link do
repositório e instruções de reprodução.

O projeto entrega o experimento do eixo B: programas inválidos e controles válidos.
Executar `poetry run netsec evaluate`; guardar o JSON e interpretar os resultados.
A especificação de casos é visível em `src/netsec/evaluation.py`. Acertar todos os
casos preparados não prova que todos os erros possíveis são detectados.

## Demonstração sugerida

1. Explicar inventários e o problema de políticas contraditórias (2 min).
2. Escrever um grupo e play ao vivo; mostrar autocomplete; executar cenário (3 min).
3. Mostrar tokens, árvore e erro de conflito entre grupos com o mesmo IP (3 min).
4. Mostrar métricas do corpus e resultados do laboratório (3 min).
5. Explicar condições estáticas, limites de serviço e firewall restrito ao laboratório (1 min).

A nota é individual. Cada integrante deve entender as fases e fazer contribuições
identificáveis; a avaliação não se resume à existência dos arquivos.
