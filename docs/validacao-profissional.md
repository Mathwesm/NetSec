# Validação profissional — 18/09/2026

## Evidência local já executada

- Ruff format/check: aprovado.
- mypy estrito: verificação explícita para Windows e Linux.
- pytest: 139 testes após integrar a VPN e o escopo de parâmetros no autocomplete.
- Detecção de segredos: zero achados.
- Extensão VS Code: verificação de tipos e quatro testes aprovados.
- Laboratório profissional: seis verificações de integração aprovadas, com dois servidores.
- Compilador Windows empacotado: validou o exemplo de funções sem Poetry/Python externo.
- Interface Tk: construção e atualização da janela verificadas sem executar política.

O laboratório real provou: TCP/23 alcançável antes, regra aplicada via SSH autenticado,
SSH/HTTP preservados, reaplicação `unchanged`, TCP/23 sem resposta após o bloqueio, remoção
das regras selecionadas e conectividade restaurada. Consultas DNS A/AAAA passaram nos
dois servidores, com resposta conferida. Evidência:
`data/processed/professional-20260918T180711056197Z-5bae964c/evidence.json`.

Foi detectada uma diferença real no nftables 1.0.6: comentários de tabela/cadeia aparecem
na saída textual, mas não no JSON. Um teste reproduziu a falha antes da correção; a
correção verifica as marcas reais pela saída textual quando ausentes no JSON. Não
removeu a verificação de propriedade para fazer o teste passar.

## Windows e limites da evidência

O diagnóstico nativo local encontrou NetSecurity e perfis habilitados, mas processo sem
privilégio de administrador. Nenhuma regra do firewall do computador de desenvolvimento
foi alterada. O CI possui um teste separado para o ciclo de vida de regra Windows em
runner elevado e descartável. No commit `d20a717`, os cinco jobs passaram:
[CI 35379157821](https://github.com/Mathwesm/NetSec/actions/runs/35379157821).
Isso inclui qualidade em Windows/Linux, dois laboratórios e Windows nativo/instalador.

O teste Windows restringe a regra a loopback/porta alta e verifica criação, atualização,
idempotência e remoção. Não mede bloqueio de tráfego externo. O instalador é construído
em job próprio; a instalação local do compilador Inno Setup foi bloqueada pelo ambiente.
Não há assinatura comercial do instalador nem teste manual de consentimento UAC realizado.

## WireGuard Linux

O teste real `validate_vpn.py` criou dois peers, verificou estado `unchanged` na
reaplicação, realizou HTTP no endereço da VPN e confirmou handshake nos dois lados.
As interfaces foram removidas ao fim. Evidência pública local:
`data/processed/vpn-20260918T181935059086Z-05389aee/evidence.json`.
As chaves privadas permaneceram dentro dos containers e não fazem parte do relatório.

Dois testes de regressão foram escritos e observados falhando antes das correções:
DNS simulado ignorando bloqueio UDP anterior e endpoint IPv6 com zona permitindo conteúdo
extra de configuração. Ambos agora são cobertos. A VPN nativa Windows, IPv6 fim a fim,
roteamento entre LANs, NAT e persistência após reboot não foram testados/implementados.

Nenhum teste foi feito contra servidores de produção, roteadores físicos, GPO corporativa
ou uma frota distribuída com falhas de energia/rede. Reaplicar reconcilia estado; não há
transação global. Recursos em desenvolvimento não contam como validação concluída.
