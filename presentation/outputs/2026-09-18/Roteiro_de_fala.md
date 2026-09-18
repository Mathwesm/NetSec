# NetSec: roteiro de fala

Duração planejada: 675 segundos.

## 1. NetSec

Tempo sugerido: 15 segundos.

Apresente a NetSec como uma linguagem específica de domínio. O objetivo desta demonstração é explicar como o código escrito pelo usuário passa por um compilador próprio e chega a uma ação observável. O escopo validado de firewall é o laboratório Linux, não uma implantação de produção.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/README.md
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/especificacao.md

## 2. Problema e objetivo

Tempo sugerido: 30 segundos.

Use um exemplo concreto: dois grupos podem apontar para o mesmo servidor, enquanto um play permite a porta 22 e outro a bloqueia. O diferencial acadêmico é detectar essa contradição antes de tocar na rede. Situe o público sem prometer provisionamento, roteamento ou monitoramento contínuo já implementados.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/especificacao.md

## 3. Um programa completo

Tempo sugerido: 45 segundos.

Leia o programa de cima para baixo. admin tem tipo port, e o construtor port(22) valida o domínio. O IP pertence ao bloco reservado para documentação, portanto este exemplo deve rodar em simulação. Explique que report é uma mensagem escrita pelo autor, não uma prova automática de sucesso. A prova está nos registros de execução. O código completo equivalente está nos exemplos do repositório.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/examples/02_policy.netsec
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/especificacao.md

## 4. Arquitetura do compilador

Tempo sugerido: 30 segundos.

Explique a separação entre sintaxe, significado e execução. A AST ainda pode representar um programa semanticamente inválido. A verificação de tipos e a expansão de grupos, condições e repetições produzem um plano próprio. Não usamos um analisador semântico pronto nem eval ou exec para executar NetSec. Pydantic cuida das fronteiras de dados, não das regras de tipos da linguagem.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/lexer.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/parser.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/compiler.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/runtime.py

## 5. Tokens e gramática

Tempo sugerido: 30 segundos.

Aponte que espaços e comentários não viram comandos, mas as posições são preservadas. A regra EBNF define a estrutura de declaração e a relação entre play, grupo e bloco. O exemplo usa os nomes da especificação; a implementação chama o token de identificador NAME. Um erro de ponto e vírgula é sintático. Um inteiro fora do intervalo de port é semântico.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/lexer.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/parser.py
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/especificacao.md

## 6. AST e precedência

Tempo sugerido: 35 segundos.

Explique a árvore com o operador mais externo na raiz. O parser usa uma tabela de precedência: multiplicação tem nível 6, adição nível 5. Há também operadores lógicos, comparações e o operador de pertinência in. A avaliação resolve 3 durante a compilação. O diagrama é uma projeção da expressão, não a serialização completa de todos os campos da AST.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/parser.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/values.py
https://github.com/Mathwesm/NetSec/blob/5a56802/examples/03_scopes.netsec

## 7. Tipos e validação de domínio

Tempo sugerido: 30 segundos.

Mostre que tipos de domínio são diferentes de um inteiro ou string genéricos. O construtor port valida os limites. O contexto check port 22 admite o literal por uma regra contextual documentada, mas port admin = 22 é rejeitado. As regras próprias de tipos estão em values.py. A biblioteca ipaddress valida somente os formatos de endereços e redes.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/values.py
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/especificacao.md
https://docs.python.org/3.12/library/ipaddress.html

## 8. Escopos e fluxo estático

Tempo sugerido: 40 segundos.

Este slide contém um trecho, não um programa completo. trusted é a rede declarada no exemplo 03, e current_host é o IP predefinido no play. Um bloco interno pode sombrear passes sem mudar a variável externa. Ambos os ramos de if são tipados, mas apenas o selecionado integra o plano. A condição não lê o resultado de um check. A repetição aceita de zero a cem iterações.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/examples/03_scopes.netsec
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/compiler.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/values.py

## 9. Erro semântico: conflito por IP

Tempo sugerido: 40 segundos.

Execute o exemplo 04. O parser aceita a sintaxe. A análise semântica normaliza os IPs e compara a tripla IP, porta, protocolo ao longo do plano inteiro. A segunda política contradiz a primeira e gera E_FIREWALL_CONFLICT na linha 12, coluna 5. O objeto de diagnóstico também conserva a posição relacionada da regra anterior. O programa termina antes de iniciar qualquer ação. As instruções exibidas são recortes dos dois plays do exemplo.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/examples/04_rejected.netsec
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/compiler.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/model.py

## 10. Plano e executor próprios

Tempo sugerido: 30 segundos.

À esquerda está uma projeção dos campos de uma instrução, omitindo source e message para caber. À direita está o despacho de _execute_instruction, reformatado sem mudar sua lógica. Antes do loop, preflight valida todos os alvos. O executor mantém registros por instrução, inclusive quando um adaptador falha. Não existe execução de strings Python nem delegação do fluxo da NetSec a outra linguagem.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/core/compiler.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/runtime.py

## 11. Ambientes de execução

Tempo sugerido: 25 segundos.

Diferencie resultado simulado de observação real. network não modifica firewall. docker exige inventário, label de propriedade e correspondência entre IP e container. Uma porta aberta não comprova que o serviço é seguro. SSH verifica o banner, HTTP verifica uma resposta HTTP e HTTPS também exige certificado válido para o IP. UDP genérico não é uma sonda suportada, embora regras UDP sejam aceitas.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/runtime.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/services/probes.py
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/services/docker.py

## 12. Edição no VS Code

Tempo sugerido: 30 segundos.

Abra o exemplo no editor e mostre autocomplete e ir à declaração. Introduza temporariamente int broken = true para mostrar o erro. O quadro representa o conteúdo e a sugestão, não é uma captura de tela. A integração real foi testada no VS Code: completion tipada, navegação e E_TYPE em documento não salvo. A extensão usa APIs diretas do VS Code, não um servidor LSP nesta versão. Reverta a edição de demonstração ao terminar.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/editor.py
https://github.com/Mathwesm/NetSec/blob/5a56802/editor/vscode/extension.js
https://github.com/Mathwesm/NetSec/blob/5a56802/editor/vscode/test/integration.js
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/validacao-2026-09-18.md
https://code.visualstudio.com/api/language-extensions/programmatic-language-features

## 13. Laboratório Linux

Tempo sugerido: 30 segundos.

Identifique a origem da observação: as sondas saem do probe, não do próprio servidor. Os dois alvos têm nftables e capacidade NET_ADMIN no namespace de rede do container. A porta 23 usa uma fixture TCP em texto simples, não um servidor Telnet completo. O ambiente usa IPs explícitos e não publica portas. O firewall do Windows permaneceu intocado. Este teste usa o kernel Linux do ambiente Docker e comprova comportamento real de pacotes nesse laboratório.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/lab/compose.yaml
https://github.com/Mathwesm/NetSec/blob/5a56802/lab/Dockerfile
https://github.com/Mathwesm/NetSec/blob/5a56802/lab/server.py
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/laboratorio.md

## 14. Demonstração ao vivo

Tempo sugerido: 105 segundos.

Reserve cerca de 1 minuto e 45 segundos. Antes da fala, inicie o laboratório com docker compose -f lab/compose.yaml up -d e abra o VS Code. Execute check, depois a simulação. No segundo comando, a quebra visual não deve ser copiada como dois comandos separados: use uma única linha. Mostre o código de saída 2 e E_FIREWALL_CONFLICT do exemplo inválido. Rode lab-test para obter evidências novas. O comando redefine apenas regras gerenciadas nos alvos do laboratório e testa a reaplicação. Se a inicialização do Docker consumir o tempo da apresentação, mostre os arquivos de evidência da execução anterior, identificando-os como execução gravada. Não apresente uma simulação como teste real. O roteiro completo está em docs/demonstracao.md.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/laboratorio.md
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/lab_validation.py
https://github.com/Mathwesm/NetSec/blob/5a56802/examples/02_policy.netsec
https://github.com/Mathwesm/NetSec/blob/5a56802/examples/04_rejected.netsec

## 15. Resultados da rede

Tempo sugerido: 35 segundos.

Mostre a comparação antes e depois. O teste considera timeout na porta 23 o comportamento esperado do drop aplicado. SSH e HTTP continuam disponíveis. O teste também exige unchanged na segunda aplicação das mesmas regras. A execução local e o job Linux do GitHub Actions tiveram sucesso. Isso valida esse cenário controlado, sem provar compatibilidade com qualquer firewall ou ambiente de produção. O JSON bruto fica em data/processed, fora do Git.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/validacao-2026-09-18.md
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/lab_validation.py
https://github.com/Mathwesm/NetSec/actions/runs/35370618495

## 16. Avaliação semântica

Tempo sugerido: 35 segundos.

O experimento separa sintaxe de semântica: cada caso inválido passa pelo parser antes de avaliar a rejeição. São 25 programas com erro deliberado e 10 controles. Todos tiveram o diagnóstico ou aceitação esperados. Cada caso roda dez vezes e o relatório guarda a mediana de tempo, embora o gráfico mostre apenas contagens. O conjunto cobre tipos, fronteiras, escopo, IP/CIDR e conflitos. Zero falhas neste conjunto sintético não estima a precisão em uso real nem prova que todo erro possível é detectado.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/src/netsec/evaluation.py
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/validacao-2026-09-18.md

## 17. Qualidade e tecnologias

Tempo sugerido: 25 segundos.

Os 61 testes Python e quatro testes Node são executáveis e passaram novamente durante a preparação. A cobertura unitária registrada é 84% de src, sem contar as integrações separadas. O VS Code também teve um teste real de integração, e o laboratório validou o firewall. Não confunda CI Windows com aplicação do Windows Firewall: o job Windows valida compilador, runtime e editor. O código é organizado em src e as dependências Python são fixadas no lock do Poetry.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/pyproject.toml
https://github.com/Mathwesm/NetSec/blob/5a56802/.github/workflows/ci.yml
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/validacao-2026-09-18.md
https://github.com/Mathwesm/NetSec/actions/runs/35370618495

## 18. Limites da versão acadêmica

Tempo sugerido: 25 segundos.

Defenda as escolhas de escopo. Tipagem explícita, ausência de módulos e funções mantêm o foco nos requisitos obrigatórios. O compilador apresenta o primeiro erro e ainda não faz recuperação de múltiplos diagnósticos. O firewall Windows e servidores remotos não foram implementados. A sessão Windows atual não está elevada. A automação atual é um programa disparado manualmente; grupos e plays não significam que já existe coordenação distribuída de servidores.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/README.md
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/especificacao.md
https://github.com/Mathwesm/NetSec/blob/feat/academic-presentation/docs/evolucao.md

## 19. Conclusão e evolução

Tempo sugerido: 30 segundos.

Conclua retomando o objetivo: a NetSec transforma um programa tipado em verificações e regras observáveis. A entrega acadêmica preserva uma base demonstrável. A branch feat/professional-platform foi separada para evolução futura, ainda sem novos adaptadores. Os resultados esperados dessa evolução são uso por profissionais de redes, políticas com prévia, privilégio explícito, auditoria e testes em servidores. Isso é um plano, não um resultado medido. O artigo, as referências obrigatórias da disciplina e a revisão entre integrantes continuam sendo entregas separadas.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/README.md
https://github.com/Mathwesm/NetSec/blob/feat/academic-presentation/docs/evolucao.md
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/entregas.md

## 20. Referências e reprodução

Tempo sugerido: 10 segundos.

Deixe este slide disponível durante a arguição. Os títulos têm links clicáveis. As notas de cada slide identificam os arquivos de implementação que sustentam as afirmações. A referência visual é NetSec Apresentacao_v.pdf, fornecida pela equipe. Os critérios acadêmicos vêm da apresentação oficial atividade_final_apresentacao (1).pptx. Os ícones usam Font Awesome Free via react-icons, licença CC BY 4.0 para os glifos. Estas referências técnicas não substituem as duas referências da bibliografia da disciplina exigidas para o artigo final.

Fontes:
https://github.com/Mathwesm/NetSec/blob/5a56802/README.md
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/entregas.md
https://github.com/Mathwesm/NetSec/blob/5a56802/docs/validacao-2026-09-18.md
https://github.com/Mathwesm/NetSec
https://github.com/Mathwesm/NetSec/actions/runs/35370618495
https://docs.python.org/3.12/library/ipaddress.html
https://code.visualstudio.com/api/language-extensions/programmatic-language-features
https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
https://fontawesome.com/license/free
