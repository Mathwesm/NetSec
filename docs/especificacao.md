# Especificação da NetSec 0.2

## Propósito e público

A NetSec é uma linguagem específica de domínio para estudantes, administradores de redes
e profissionais de segurança descreverem inventários por IP, verificações de conectividade,
serviços e políticas de firewall. Seu diferencial é verificar a coerência dessas políticas
antes de executá-las: grupos diferentes podem representar o mesmo IP, e uma contradição
entre permitir e bloquear o mesmo endpoint deve ser recusada antes de qualquer ação.
A implementação usa Python 3.12; lexer, parser, análise semântica e executor são próprios.

## Programa completo, comentado linha a linha

```netsec
port admin = port(22);                   // Declare a domain port explicitly.
network lan = network("192.0.2.0/24");   // Declare a canonical network.
int passes = 1 + 2 * 1;                 // Multiplication precedes addition: 3.
group servers {                         // Declare an inventory name.
    host "one" address "192.0.2.10";     // Validate and canonicalize the IP.
}                                       // Close the inventory.
play "audit" targets servers {           // Execute once per host in this group.
    if current_host in lan {            // Test membership using domain types.
        repeat passes {                 // Expand a bounded repetition.
            check port admin protocol tcp; // Test TCP connectivity.
        }                               // Close the repetition scope.
        check service "ssh";            // Require an SSH identification banner.
        firewall deny port 23 protocol tcp; // Declare a blocking policy.
        firewall allow port admin protocol tcp; // Preserve the declared admin port.
        report "Audit completed.";      // Produce source-linked output.
    } else {                            // Select the alternative at compile time.
        report "Host outside network."; // Emit a message for this alternative.
    }                                   // Close the conditional scope.
}                                       // Close the automation.
```

O comando `run` primeiro compila o programa inteiro; somente após sucesso entrega o
plano validado ao executor. O exemplo usa IPs reservados para documentação e roda com
o cenário de `examples/scenario.json`. O laboratório real possui inventário próprio.

## Tipos, nomes e escopos

| Tipo | Exemplo | Regra |
|---|---|---|
| `int` | `int count = 3;` | Inteiro; operações produzem no máximo 512 bits |
| `bool` | `bool enabled = true;` | Não é intercambiável com inteiro |
| `string` | `string label = "audit";` | Unicode entre aspas duplas, escapes JSON |
| `ip` | `ip node = ip("::1");` | IPv4 ou IPv6 canônico; sem identificador de zona |
| `network` | `network lan = network("192.0.2.0/24");` | CIDR canônico, sem bits de host |
| `port` | `port admin = port(22);` | Intervalo inclusivo 1..65535 |
| `protocol` | `protocol transport = tcp;` | `tcp` ou `udp` |

Toda declaração informa o tipo. Verificar o tipo resultante de uma expressão não introduz
inferência de tipos nas declarações. Nomes são imutáveis, sensíveis a maiúsculas, e visíveis
após sua declaração. Redeclaração no mesmo escopo é erro; sombreamento em bloco interno é
permitido. Blocos `play`, `if`, `else` e `repeat` delimitam escopos; os valores locais
não escapam. Cada host inicia uma instância do escopo do play. `current_host` é um
nome predefinido de tipo `ip` dentro desse escopo.

Grupos pertencem ao escopo global, contêm apenas hosts e precisam ser declarados antes
do play. Identificadores de variáveis e grupos compartilham o espaço global. Nomes de
plays são únicos. Em um grupo, não se repetem rótulos nem IPs canônicos; grupos diferentes
podem compartilhar um IP. Hosts são processados na ordem declarada.

Para preservar os slides originais, `host ... address "192.0.2.10"` valida a string como
IP nesse contexto. `check port 22` e `firewall ... port 22` validam o inteiro como porta.
Fora desses contextos, a construção do tipo é explícita: `port admin = 22;` é rejeitado.

## Gramática EBNF

Terminais estão entre aspas; chaves indicam repetição e colchetes, opcionalidade.

```ebnf
program       = { declaration | function | group | play | report } ;
declaration   = type, IDENTIFIER, "=", expression, ";" ;
function      = "fn", IDENTIFIER, "(", [ parameters ], ")", "->", type, "=", expression, ";" ;
parameters    = type, IDENTIFIER, { ",", type, IDENTIFIER } ;
arguments     = expression, { ",", expression } ;
type          = "int" | "bool" | "string" | "ip" | "network" | "port" | "protocol" ;
group         = "group", IDENTIFIER, "{", host, { host }, "}" ;
host          = "host", STRING, "address", expression, ";" ;
play          = "play", STRING, "targets", IDENTIFIER, block ;
block         = "{", { statement }, "}" ;
statement     = declaration | check | firewall | report | conditional | repeat ;
check         = "check", ( "port", expression, "protocol", expression
                        | "service", expression
                        | "dns", expression, "expect", expression ), ";" ;
firewall      = "firewall", ( "allow" | "deny" ), "port", expression,
                "protocol", expression, ";" ;
report        = "report", expression, ";" ;
conditional   = "if", expression, block, [ "else", block ] ;
repeat        = "repeat", expression, block ;
expression    = disjunction ;
disjunction   = conjunction, { "or", conjunction } ;
conjunction   = equality, { "and", equality } ;
equality      = comparison, { ( "==" | "!=" ), comparison } ;
comparison    = addition, { ( "<" | "<=" | ">" | ">=" | "in" ), addition } ;
addition      = product, { ( "+" | "-" ), product } ;
product       = unary, { ( "*" | "/" | "%" ), unary } ;
unary         = ( "not" | "+" | "-" ), unary | primary ;
primary       = INTEGER | STRING | "true" | "false" | "tcp" | "udp"
              | IDENTIFIER, [ "(", [ arguments ], ")" ] | "(", expression, ")"
              | type, "(", expression, ")" ;
```

O parser aceita uma árvore um pouco mais ampla: grupo vazio e construções no bloco errado
são recusados na análise semântica, com mensagens específicas. Funções `fn` são puras e
retornam uma expressão tipada. Corpos são verificados mesmo sem chamada; parâmetros não
são substituídos por valores artificiais para essa verificação. Chamadas usam escopo
léxico, tipos exatos e aridade exata. Funções precisam ser declaradas antes do uso;
recursão e definições aninhadas são recusadas. O limite é 32 chamadas aninhadas e 100.000
avaliações por compilação. Não há atribuição posterior, imports ou exceções de usuário.
O texto acumulado das instruções expandidas é limitado a 1.000.000 de caracteres, para
que repetições de reports não gerem relatórios desproporcionais ao arquivo de entrada.

`check dns "app.test" expect ip("192.0.2.10");` consulta o IP do host atual como servidor
DNS na porta 53 e compara o conjunto de respostas A/AAAA com o endereço esperado.
Nomes ASCII/punycode são normalizados sem sufixos implícitos do sistema operacional.
O plano da linha profissional usa `format_version: 2`; planos da versão 1 não são aceitos
como versão 2. O agente SSH recebe fonte e recompila, não executa planos externos.

## Tokens e precedência

| Categoria | Forma / valores |
|---|---|
| Identificador | `[A-Za-z_][A-Za-z_0-9]*`, exceto palavras reservadas |
| Inteiro | `[0-9]+`, até 100 dígitos por literal; sinal é operador separado |
| String | Aspas duplas, escapes JSON, sem quebra de linha literal |
| Comentário | `//` até o fim da linha; descartado |
| Espaço | Espaço, tabulação, CR e LF; descartados, preservando posições |
| Delimitadores | `{` `}` `(` `)` `;` `=` `,` `->` |
| Operadores | `+` `-` `*` `/` `%` `==` `!=` `<` `<=` `>` `>=` `and` `or` `not` `in` |
| Palavras do domínio | `group host address play targets check port protocol service dns expect firewall allow deny report fn` |
| Controle e tipos | `if else repeat int bool string ip network true false tcp udp` |
| Fim | Token EOF com a posição imediatamente após o texto |

Da menor para a maior precedência: `or`; `and`; igualdade; comparação/pertinência;
adição/subtração; produto/divisão/resto; unários. Operadores binários são associativos à
esquerda. A divisão inteira arredonda para menos infinito: `-7 / 2 == -4`.
Aritmética e ordenação exigem inteiros; igualdade exige tipos idênticos; `in` exige IP
à esquerda e rede à direita. Expressões não fazem I/O; ambos os operandos lógicos são
validados e avaliados. Não há concatenação implícita de strings.

## Verificação semântica principal

As regras são indexadas pela tripla **(IP canônico, porta, protocolo)** em todo o plano.
Duas ações opostas para a mesma tripla são erro, inclusive entre grupos e plays diferentes.
Repetir a mesma regra é permitido. Protocolos diferentes não formam conflito.
Os dois ramos de uma condição precisam estar bem tipados; apenas o ramo selecionado
integra a política. Condições e contagens dependem de valores imutáveis conhecidos na
compilação; não consultam os resultados de checks.

Passa:

```netsec
group nodes { host "one" address "192.0.2.10"; }
play "protect" targets nodes {
    firewall deny port 23 protocol tcp;
    firewall allow port 22 protocol tcp;
}
```

É rejeitado, apesar de sintaticamente válido:

```netsec
group nodes { host "one" address "192.0.2.10"; }
play "conflict" targets nodes {
    firewall allow port 22 protocol tcp;
    firewall deny port 22 protocol tcp;
}
```

O diagnóstico `E_FIREWALL_CONFLICT` informa arquivo, linha e coluna da segunda regra,
além da posição da regra anterior. Outros diagnósticos cobrem tipo incorreto, IP inválido,
porta fora do intervalo, nome inexistente, redeclaração, serviço não suportado e uso fora
do contexto. A tabela de símbolos e essas decisões pertencem ao projeto. `ipaddress`
é usado apenas para representar/validar formatos de IP e rede; não analisa programas.

## Execução e limites

O compilador gera instruções próprias `report`, `check_port`, `check_service`, `allow`
e `deny`, com tipos já validados e origem preservada. Resolve grupos, seleciona ramos
estáticos e expande repetições. O executor visita essas instruções em ordem, sem
`eval`, `exec`, transpilar para Python ou reutilizar um executor de outra linguagem.

Há três adaptadores: cenário determinístico, sondas reais na máquina local e laboratório
Docker com nftables. Uma porta aberta comprova conectividade TCP; `check service "ssh"`
valida o banner, e HTTP/HTTPS validam a resposta HTTP. HTTPS também valida o certificado
contra o IP. Isso não identifica vulnerabilidades nem garante a configuração segura do
serviço. UDP genérico é recusado porque ausência de resposta não comprova porta aberta;
regras UDP de firewall são suportadas.

Cada tentativa de sonda tem prazo total, até duas tentativas com backoff e jitter.
Falhas de um alvo ficam no resultado e não apagam os demais. Código de saída: 0 para
sucesso, 1 para observações com falha, 2 para erro de entrada/compilação/preflight.
Reaplicação de firewall preserva o estado; regras opostas anteriores gerenciadas pela
NetSec são substituídas atomicamente. Não há transação distribuída entre hosts: uma
interrupção pode deixar parte do inventário alterada; reaplicar converge as regras e
repete checks e reports. A retomada é por reaplicação, sem checkpoint do índice.

Limites: 1 milhão de caracteres, 128 hosts por grupo, repetição de 0 a 100, 10 mil
instruções expandidas e limites explícitos de profundidade. Para o laboratório, só são
aceitos containers identificados por rótulo de propriedade e IP conferido por inspeção.

## Decisões e exclusões

1. **Parser escrito à mão:** facilita explicar precedência, posições e árvores na
   arguição; custa manter a gramática sincronizada com os testes.
2. **Tipos explícitos e valores imutáveis:** permitem validar toda a política antes de
   executar. Condições reativas a sondas ficam fora desta versão.
3. **Plano intermediário e adaptadores:** permitem testar a linguagem sem depender da
   rede e demonstrar o mesmo modelo com ações reais.

Foram considerados e excluídos: funções recursivas, pelo custo de pilha e terminação;
inferência de tipos, pelo veto inicial da atividade e menor transparência didática; e
módulos/imports, pelo custo de resolução entre arquivos. Closures e exceções na linguagem
também ficam fora do núcleo. A extensão do editor não acrescenta construções à linguagem.

## Evidências exigidas pela disciplina

| Requisito | Evidência do projeto |
|---|---|
| Propósito | Inventário, verificações e políticas de redes |
| Tipo do domínio | `ip`, `network`, `port`, `protocol` |
| Nomes e escopo | Declarações explícitas, grupos e blocos |
| Dois níveis de precedência | Sete níveis documentados e testes de resultados |
| Controle/repetição | `if/else`, `repeat` e aplicação por host |
| Semântica própria | Detecção de políticas contraditórias por IP efetivo |
| Saída | Reports e resultados JSON associados à origem |

O eixo de avaliação escolhido é B: 25 programas com erros semânticos deliberados e
10 controles válidos, com contagem de detecções, escapes, falsos positivos e mediana
do tempo de compilação. Os resultados vêm de execução, não de números estimados.
