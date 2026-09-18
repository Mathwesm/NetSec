# Validação de 18/09/2026

Ambiente local: Windows, Python 3.12.10, Node.js 24.18.0 e Docker Engine Linux 29.7.2.
Resultados obtidos por execução; não são estimativas.

## Portão de qualidade

`poetry run poe gate` concluiu com código 0:

| Verificação | Resultado |
|---|---|
| Ruff, formatação e lint | Aprovado |
| mypy estrito | Nenhum erro em 20 arquivos de código |
| pytest | 61 testes aprovados |
| Cobertura da suíte unitária sobre `src/` | 84% |
| Detector de segredos | Nenhum alerta |
| TypeScript sobre a extensão JavaScript tipada | Nenhum erro |
| Testes Node do cliente do editor | 4 aprovados |

A cobertura não inclui a execução separada do laboratório e do editor. Trechos de CLI,
integração de processos e a ferramenta de qualidade são exercitados também por essas
execuções externas à medição unitária; isso não transforma cobertura em prova de correção.

## Avaliação semântica: eixo B

`poetry run netsec evaluate` executou cada caso 10 vezes e registrou sua mediana de tempo.

| Métrica | Resultado |
|---|---:|
| Programas com erro deliberado | 25 |
| Controles válidos | 10 |
| Erros detectados | 25 |
| Erros que escaparam | 0 |
| Falsos positivos | 0 |
| Controles aceitos | 10 |
| Códigos de diagnóstico exatamente correspondentes | 35/35 |

Todos os casos inválidos passam pelo parser antes da medição: o experimento mede
rejeições semânticas. O corpus inclui fronteiras de porta, tipos, IP/CIDR, escopo,
repetição e contradição de política. A precisão neste conjunto preparado não estima
a distribuição de erros de outros usuários e não prova completude da análise.

## Rede real

`poetry run netsec lab-test` concluiu com código 0. Não usou respostas simuladas:

| Evidência | Resultado |
|---|---|
| TCP/23, SSH e HTTP inicialmente acessíveis em dois hosts | Aprovado |
| Aplicação de bloqueio TCP/23 e permissão TCP/22 | Aprovado |
| SSH e HTTP disponíveis depois da política | Aprovado |
| Reaplicação de regras retorna `unchanged` | Aprovado |
| TCP/23 não estabelece conexão depois do bloqueio | Timeout em ambos os hosts |

As sondas partiram do container de teste; as regras foram aplicadas no nftables dos
containers-alvo. O firewall do Windows não foi modificado. A integração revelou um
problema de conversão LF/CRLF ao enviar regras do Windows para o Linux; o envio passou
a usar bytes UTF-8, com teste de regressão.

Também foram reproduzidos e corrigidos: leitura lenta que podia estender o prazo da
sonda, substituição de política oposta gerenciada em execução anterior e expressão
excessivamente profunda que podia causar um erro de recursão do Python.

## VS Code real

O teste `editor/vscode/test/integration.js` foi executado em um processo do VS Code
com perfil temporário e concluiu com código 0. Verificou uma sugestão `admin` com tipo
`port`, navegação para sua declaração e diagnóstico `E_TYPE` na posição correta de
um documento ainda não salvo. O VSIX foi empacotado e instalado localmente.

## Limites da validação

Não foram testados roteadores físicos, firewall do Windows, autenticação administrativa
remota ou uma implantação de produção. O HTTPS tem teste de falha TLS na suíte, mas
o laboratório não hospeda um certificado válido para IP; não foi demonstrado HTTPS
real nesse cenário. A extensão foi verificada no VS Code instalado no Windows; a
compatibilidade com outros editores não foi implementada.

Os três programas válidos de `examples/` executaram no cenário fornecido. O quarto
foi corretamente rejeitado em `examples/04_rejected.netsec:12:5` com
`E_FIREWALL_CONFLICT`. As evidências completas permanecem em `data/processed/`,
fora do versionamento; os comandos documentados permitem reproduzir o experimento.
