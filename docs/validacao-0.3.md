# Validação profissional 0.3 — 19/09/2026

Resultados observados, não estimativas de recursos futuros. O relatório de 18/09 é
histórico; este documento registra a ampliação da linguagem e dos testes de implantação.

## Linguagem e qualidade local

- 186 testes Python aprovados no Windows: tipos, funções/classes, imports, conflitos,
  limites de expansão/composição, paralelismo, erros de I/O e regressões nativas.
- Ruff format/check, mypy estrito para Windows e Linux: aprovados.
- Scanner de segredos: zero achados; seis testes do editor e verificação TypeScript aprovados.
- `07_classes_modules.netsec`: quatro instruções executadas com sucesso no cenário explícito.
- `08_servers.netsec`: cinco instruções validadas, incluindo HTTP/DNS e checks em portas próprias.
- Testes PowerShell de metadados/ACLs usam descritores em memória e caminhos temporários;
  são exclusivos do Windows e ficam explicitamente pulados no portão Linux.

Antes das correções, foram observados testes falhando para: autorização parcial de recursos
após falha do preflight, revisão reparada não reutilizada, travessia de diretórios Windows,
SIDs sem tradução para nome de conta e caminho de EnvironmentFile com quoting incorreto.

## Integração real em máquinas descartáveis

| Área | O que foi medido | Resultado |
|---|---|---|
| Firewall Windows | Cliente de IP distinto → allow → deny → allow; IP de origem conferido | Acesso, bloqueio e restauração confirmados |
| Windows instalado | Setup por usuário e por máquina; CLI e abertura da interface | Passou |
| Task Scheduler | Execução como SYSTEM, código zero, resultado persistido, gatilho boot e reinstalação | Passou; reinstalação `unchanged` |
| HTTP/DNS Linux | Conteúdo HTTP exato, resposta DNS, reaplicação, serviço interrompido | Passou; serviço recuperado |
| systemd | Job executado, timer/unit habilitados e evidência persistida | Passou |
| VPN persistente | Criação pelo job, interface parada e execução de reparo, dois resultados persistidos | Passou |
| SSH/Linux e WireGuard | Política aplicada em dois servidores, tráfego bloqueado/restaurado, HTTP no túnel e handshakes | Passou |

Execuções rastreáveis:

- [CI 35421364578](https://github.com/Mathwesm/NetSec/actions/runs/35421364578):
  qualidade Windows/Linux, rede Docker, SSH/VPN e instalação/tarefa Windows, cinco jobs verdes.
- [Professional deployment 35421463913](https://github.com/Mathwesm/NetSec/actions/runs/35421463913):
  HTTP/DNS, systemd, job VPN e firewall Windows externo, dois jobs verdes.

Os workflows publicam os artefatos `windows-scheduler-evidence`,
`windows-external-firewall-evidence`, `systemd-services-evidence` e
`professional-network-evidence`. Em desenvolvimento, cópias estão sob `data/artifacts/`,
fora do Git. Nenhuma regra de firewall ou tarefa agendada foi aplicada no computador pessoal.
Os recursos dos testes foram removidos nos ambientes descartáveis; a chave efêmera do
job VPN foi apagada da VM, não incluída nos artefatos.

## Desempenho medido

`poetry run python lab/professional/benchmark.py`, Windows/Python 3.12:

- 128 hosts e 2.560 instruções: mediana de **6,58 ms**, em 20 compilações.
- 24 checks HTTP locais, com atraso controlado de 50 ms: **1,402 s** com um worker;
  **0,174 s** com oito workers, aproximadamente oito vezes mais rápido nesse cenário.
- Evidência: `data/processed/benchmark-20260919T040646976808Z-50eedb63/measurements.json`.

Isso mede compilação e concorrência de I/O numa carga específica. Não é SLA, benchmark de
rede WAN, JIT, nem prova de capacidade ilimitada de servidores. Writes continuam ordenados.

## Não coberto

- Reboot real da máquina: foram testados os gatilhos/configuração de boot, execução pelo
  agendador e recuperação de serviço/interface, sem reiniciar o runner.
- Assinatura Authenticode confiável: o build suporta assinatura, mas não há certificado.
  O pacote entregue é **não assinado**. Não se afirma que o Windows reconhecerá editor verificado.
- Consentimento UAC manual, Windows com GPO corporativa, IPv6 fim a fim, NAT e roteadores físicos.
- Envio real de alerta Telegram, por falta de credenciais configuradas; recurso é opcional.
- VPN e provisionamento HTTP/DNS nativos no Windows: os backends desses recursos são Linux.
- Recuperação transacional entre servidores e cargas reais de produção. Reaplicação reconcilia
  recursos gerenciados, mas não oferece rollback distribuído.

A NetSec 0.3 é uma DSL executável de redes com limites explícitos, não uma linguagem de
propósito geral nem uma certificação de segurança de produção.
