# VPN WireGuard com NetSec

## O que este módulo faz

Cria uma interface WireGuard Linux `nswg0`…`nswg99`, configura o endereço da VPN e os peers,
verifica se o estado já corresponde à configuração e remove somente interfaces marcadas
como propriedade da NetSec. Não executa scripts de terceiros a partir do manifesto.

É um módulo de recursos da CLI, **não uma nova instrução da gramática `.netsec`**.
A configuração é JSON validado, com campos explícitos e sem chave privada. Requer Linux
com WireGuard no kernel, `wireguard-tools`, `iproute2` e root/NET_ADMIN. No Windows é possível
validar/visualizar o manifesto; criar túneis Windows não está implementado.

## Passo a passo entre dois servidores

1. Em cada servidor, gere sua própria chave com `wg genkey`, armazenando-a no gerenciador
   de segredos da sua infraestrutura ou em arquivo local acessível apenas ao administrador.
2. Derive a chave pública com `wg pubkey`, pela entrada padrão. Troque **apenas as públicas**.
3. Escolha uma sub-rede de VPN que não se sobreponha às interfaces existentes.
4. Crie um manifesto local para cada máquina. Substitua a chave pública abaixo pela do peer:

```json
{
  "interface": "nswg0",
  "address": "10.66.0.1/24",
  "listen_port": 51820,
  "mtu": 1420,
  "peers": [
    {
      "public_key": "SUBSTITUA_PELA_CHAVE_PUBLICA_DO_OUTRO_SERVIDOR",
      "allowed_ips": ["10.66.0.2/32"],
      "endpoint_address": "192.0.2.20",
      "endpoint_port": 51820,
      "keepalive": 25
    }
  ]
}
```

O placeholder é intencionalmente inválido: o validador impede aplicá-lo. No outro servidor,
inverta `.1`/`.2`, use a chave pública do primeiro e o endereço real alcançável do primeiro
como endpoint. IPs `192.0.2.*` são exemplos de documentação, não servidores disponíveis.
Se o firewall bloquear UDP/51820, crie a regra necessária explicitamente; o módulo VPN
não abre portas de firewall por conta própria.

```sh
poetry run netsec vpn check data/tunnel.json
poetry run netsec vpn preview data/tunnel.json
# Disponibilize NETSEC_WG_PRIVATE_KEY no ambiente do processo privilegiado.
poetry run netsec vpn up data/tunnel.json --apply
poetry run netsec vpn up data/tunnel.json --apply
poetry run netsec vpn status data/tunnel.json
```

A segunda aplicação deve retornar `unchanged` quando o estado público corresponder ao
manifesto. A chave privada é tratada como `SecretStr` e enviada a `wg` pela entrada padrão:
não é argumento de processo, parte do manifesto, do plano ou da saída JSON. Não use uma
chave privada literal em scripts versionados, terminal compartilhado ou relatórios.

Teste um serviço através do endereço VPN, depois consulte `status`: handshake vazio não
comprova conexão. O status mostra o horário UTC do último handshake, não uma garantia
de disponibilidade futura. Para remover:

```sh
poetry run netsec vpn down data/tunnel.json --apply
```

## Validações e limites

- Interface precisa ter o prefixo reservado e a marca de propriedade; um nome igual sem
  marca é recusado. A NetSec não assume controle de VPNs existentes.
- Chaves têm base64 canônico de 32 bytes; peers duplicados e endereços sobrepostos falham.
- Zonas IPv6 são recusadas, inclusive para impedir conteúdo extra na configuração nativa.
- Cada peer recebe IPs `/32` ou `/128` pertencentes à sub-rede da interface.
- Não há rota padrão, full-tunnel, NAT, encaminhamento entre LANs, alteração de DNS do
  sistema ou configuração de roteadores externos. IPv4 e IPv6 são aceitos pelo modelo;
  a integração real atual mede IPv4.
- Mudança do endereço de uma interface existente exige remoção explícita e recriação.
  Não há rollback de uma configuração anterior: falha numa interface existente exige
  inspeção/reconciliação. Se uma criação nova falhar durante a configuração, a interface
  recém-criada é removida.
- A configuração não sobrevive automaticamente a reboot. Integração com systemd/secrets
  manager e operação contínua precisam de política de implantação própria.

## Reprodução da evidência real

```sh
docker compose -f lab/professional/compose.yaml up -d --build
poetry run python lab/professional/validate_vpn.py
docker compose -f lab/professional/compose.yaml stop
```

O teste gera chaves dentro dos containers de laboratório, troca só as públicas, cria
dois peers, verifica reaplicação idempotente, faz HTTP no IP do túnel e exige handshake
nos dois lados. Remove as interfaces ao terminar. Evidências públicas ficam em uma nova
pasta `data/processed/vpn-<UTC>-<id>/`. O tráfego HTTP usa o túnel WireGuard; Docker é usado
apenas para provisionar e observar os namespaces de laboratório.

Referência: [WireGuard — configuração nativa](https://www.wireguard.com/quickstart/).
