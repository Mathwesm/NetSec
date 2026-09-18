# Divisão dos 20 slides: quatro apresentadores e um operador

Usar os nomes abaixo como papéis até a equipe definir os integrantes. A divisão mantém
blocos de assunto completos, em vez de repartir cinco slides por pessoa sem considerar
a demonstração. As notas completas continuam no PowerPoint e no roteiro de fala.

| Pessoa | Slides | Assunto | Tempo de fala |
|---|---|---|---|
| Apresentador 1 | 1 a 5 | Propósito, programa, arquitetura, tokens e gramática | 2min30s |
| Apresentador 2 | 6 a 10 | AST, precedência, tipos, escopos, conflito e executor | 2min55s |
| Apresentador 3 | 11 a 14 | Modos, VS Code, laboratório e demonstração ao vivo | 3min10s |
| Apresentador 4 | 15 a 20 | Resultados, avaliação, qualidade, limites e conclusão | 2min40s |
| Operador | Todos | Avançar slides, acompanhar cronômetro e controlar a projeção | Sem bloco de fala |

Total de fala: **11min15s**. Reserva: **45s** para três transições, troca de tela e pequenos
atrasos. Limite planejado: **12 minutos**. A arguição tem mais oito minutos, conforme
a atividade. Todos precisam compreender o projeto, inclusive o operador.

## Apresentador 1: o que estamos construindo

1. NetSec: nome, domínio e escopo acadêmico.
2. Problema e objetivo: políticas contraditórias para o mesmo IP.
3. Programa completo: tipo, grupo, host e play.
4. Arquitetura: texto, tokens, AST, semântica, plano e executor.
5. Tokens e gramática: posição de erro e estrutura EBNF.

**Transição:** “Agora que vimos a estrutura do programa, vamos acompanhar como o
compilador decide se esse programa faz sentido.”

## Apresentador 2: como a linguagem funciona

6. AST e precedência: por que `1 + 2 * 1` vale 3.
7. Tipos de domínio: por que `port(22)` difere de um inteiro comum.
8. Escopos: variável interna não modifica a externa, fluxo resolvido na compilação.
9. Erro semântico: grupos diferentes podem apontar para a mesma tripla IP/porta/protocolo.
10. Plano e executor: instruções próprias, preflight e resultados por ação.

**Transição:** “Esse plano já está validado. Vamos mostrar onde ele executa e o que
acontece na rede de verdade.”

## Apresentador 3: demonstração

11. Diferenciar `simulate`, `network` e `docker`.
12. Mostrar autocomplete e diagnóstico no VS Code.
13. Identificar probe e dois servidores do laboratório.
14. Executar os comandos do [roteiro de demonstração](demonstracao.md).

O apresentador 3 deve operar o terminal e narrar os resultados. O operador dos slides
continua responsável pelo cronômetro e por voltar ao deck, sem ter de explicar código
enquanto navega. Combinar os sinais “editor”, “terminal” e “voltar ao slide 15”.

Docker e editor já devem estar prontos antes da apresentação. Se o laboratório não
responder dentro do tempo, mostrar a evidência preparada e identificá-la como uma
execução anterior. Não gastar a fala instalando ferramentas ou corrigindo ambiente.

**Transição:** “Vimos as ações e a rejeição do conflito. Agora vamos analisar os
resultados medidos e os limites dessa versão.”

## Apresentador 4: evidências e fechamento

15. Antes e depois: porta 23 bloqueada, SSH e HTTP preservados.
16. Corpus: 25 erros semânticos, 10 controles, limites do conjunto sintético.
17. Qualidade: testes, tipos, cobertura e CI.
18. Limitações reais, sem prometer firewall Windows ou servidores remotos no marco acadêmico.
19. Conclusão: benefício demonstrado e evolução profissional separada.
20. Referências: deixar aberto para a arguição.

## Checklist do operador

- Usar a apresentação acadêmica, não exemplos experimentais da branch profissional.
- Abrir o deck antes do início e verificar projeção, fonte e modo de notas.
- Mostrar o próximo slide somente após o sinal combinado.
- Avisar discretamente a passagem de 9min e 11min.
- Manter o slide 14 disponível durante a demonstração e voltar ao 15 ao sinal.
- Ter a pasta de evidências e o roteiro abertos como apoio, sem janelas com credenciais.
- Não avançar automaticamente durante perguntas.

## Ensaio

Fazer uma rodada com cronômetro, incluindo a troca para editor/terminal. Cada pessoa
deve conseguir responder perguntas de outro bloco. A distribuição de fala não substitui
contribuições e compreensão individuais exigidas pela disciplina.
