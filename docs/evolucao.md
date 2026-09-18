# Versão acadêmica e evolução profissional

## Linhas de trabalho

| Branch | Finalidade | Estado inicial |
|---|---|---|
| `feat/netsec-language` | Implementação acadêmica reproduzível | Compilador, executor, editor e laboratório testados no commit `5a56802` |
| `feat/academic-presentation` | Apresentação, roteiro de demonstração e material de estudo | Derivada da implementação acadêmica, sem mudar a linguagem |
| `feat/professional-platform` | Evolução futura para equipes de redes e servidores | Separada no mesmo commit, ainda sem adaptadores novos |

Não é necessário outro repositório neste momento. As branches compartilham o núcleo da
linguagem e permitem revisar mudanças sem comprometer a demonstração da disciplina.
A branch profissional não é uma promessa de compatibilidade de produção nem uma versão
já entregue. A apresentação distingue o que funciona hoje do que ainda será construído.

## Prioridades da evolução profissional

1. **Linux nativo primeiro:** nftables, inventário local validado, prévia de política,
   verificação de privilégios, aplicação explícita e reconciliação apenas das regras
   gerenciadas pela NetSec. Testes em máquina ou namespace descartável.
2. **Windows nativo:** adaptador NetSecurity, diagnóstico de sessão administrativa,
   regras identificadas por proprietário e testes de idempotência. Elevação via UAC
   pertence ao administrador, não ao compilador. Não desativar o firewall global.
3. **Execução remota:** inventário autenticado, SSH no Linux, validação de chaves de host,
   limites de tempo e retorno por servidor. Não confundir grupos atuais com uma
   implementação distribuída existente.
4. **Automação operacional:** agendamento externo, trilha de auditoria, alertas,
   retomada e comportamento explícito diante de falhas parciais. Política de rollback
   e proteção do acesso administrativo precisam de testes antes de uso real.
5. **Linguagem para operadores:** mensagens compreensíveis, documentação de cenários,
   contratos de adaptadores estáveis e testes de aceitação com profissionais de redes.

## O que a versão acadêmica não deve prometer

- Um check de TCP ou um banner SSH não comprova ausência de vulnerabilidades.
- `report` imprime o texto declarado. O sucesso real está nos registros de execução.
- `if` e `repeat` são resolvidos na compilação. Não reagem ao resultado de uma sonda.
- O firewall real validado atua em containers Linux explicitamente inventariados.
- Não há administração remota autenticada, Windows Firewall, rollback distribuído
  ou serviço autônomo de produção implementados no marco acadêmico.

Qualquer evolução pode reaproveitar testes e correções do núcleo, mas uma mudança na
semântica da linguagem exige especificação, exemplos e regressões correspondentes.
