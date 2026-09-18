# NetSec profissional — guia de uso

## 1. Instalar e validar sem privilégios

```sh
git clone --branch feat/professional-platform https://github.com/Mathwesm/NetSec.git
cd NetSec
poetry env use python3.12
poetry install
npm --prefix editor/vscode ci --ignore-scripts
poetry run pre-commit install
poetry run poe gate
poetry run netsec check examples/05_functions.netsec
poetry run netsec preview examples/05_functions.netsec
```

No Windows, se `python3.12` não existir no PATH, use `poetry env use python` com Python
3.12 instalado. Compilar, validar e visualizar não exigem administrador e não acessam a
rede. Exemplos `192.0.2.*` são endereços de documentação: adapte antes de executar rede real.

Pré-requisitos: Python 3.12, Poetry 2.4.1; Node 24 para desenvolvimento/VS Code. Linux
nativo requer `nftables` e `iproute2`. SSH requer cliente OpenSSH, chave privada local,
`known_hosts` verificado e NetSec da mesma versão instalada nos destinos. As dependências
Python ficam no `poetry.lock`; não instale pacotes avulsos com pip.

## 2. Windows: interface, pasta de instalação e UAC

```powershell
poetry run netsec-desktop
```

A interface permite escolher `.netsec`, validar, ver a prévia, consultar diagnóstico,
aplicar e remover regras. Não executa política ao abrir. O botão de administrador solicita
consentimento pelo UAC e abre outra janela: a janela original continua sem privilégios.
Cancelar o UAC gera uma mensagem, não uma tentativa de contornar a restrição.

O instalador gerado pelo CI fica no artefato **netsec-windows**. Escolha a pasta e entre
instalar para o usuário atual ou para todos. O executável inclui Python e dependências;
o usuário final não precisa instalar Poetry/Python. O instalador não modifica o PATH nem
habilita execução automática. Instalação para todos pode exigir UAC, mas não eleva cada
execução do programa. O pacote ainda não possui assinatura comercial de código.

Build reproduzível com Inno Setup 6 disponível:

```powershell
./packaging/windows/build.ps1 -Compiler 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
```

Sem `-Compiler`, gera os dois pacotes de executáveis, sem o Setup. Cada build usa uma pasta
nova em `dist/windows-<UTC>/`. A distribuição instalada possui `NetSec-Desktop.exe` e
`cli/NetSec.exe`. O launcher preserva os diagnósticos do compilador. Logs e diários da
interface ficam em `.netsec` dentro da pasta do usuário.

## 3. Firewall nativo local

```sh
poetry run netsec doctor
poetry run netsec preview politica-local.netsec
poetry run netsec run politica-local.netsec --mode local --apply --fail-fast
poetry run netsec firewall-remove politica-local.netsec --mode local --apply
```

O IP da regra deve pertencer à própria máquina. Em Linux, execute o comando instalado
com root/sudo ou em namespace com `NET_ADMIN`. No Windows, abra a interface elevada ou
um terminal como administrador. O bridge usa `RemoteSigned` somente no processo filho;
não altera a política global do PowerShell e não supera restrições de Group Policy.

Linux usa uma tabela `inet netsec_native`, marcada como propriedade da NetSec. A regra
é comparada ao estado desejado e corrigida se houver divergência. Troca de uma regra é
atômica dentro da transação nftables. Windows usa NetSecurity, grupo `netsec-managed-v1`,
nomes estáveis e regras de entrada em PersistentStore. Regras de outros programas,
políticas padrão e perfis não são removidos/desativados. Uma colisão sem marca de
propriedade é recusada. A remoção seleciona endpoints do arquivo, não apaga o firewall.

Bloquear 22/3389/5985/5986 exige `--allow-management-port`, disponível **somente localmente**.
Esse override não torna seguro bloquear a própria sessão remota. No Windows todos os
perfis devem estar habilitados para execução pelo adaptador local.

Importante: `allow` não anula um `drop` de outra cadeia Linux nem uma regra Block/GPO do
Windows. Aplicar uma regra não comprova conectividade. Teste de outro host após a mudança.

## 4. Dois ou mais servidores via SSH

Crie um inventário local, fora do Git público, por exemplo `data/ssh.json`:

```json
{
  "targets": {
    "192.0.2.10": {
      "user": "netsec",
      "port": 22,
      "identity_file": "data/keys/netsec_ed25519",
      "known_hosts_file": "data/keys/known_hosts",
      "sudo": true
    }
  }
}
```

Caminhos são relativos ao diretório de execução. Confirme fingerprints por canal
independente antes de cadastrar `known_hosts`; não aceite automaticamente a primeira chave
vista na rede. O programa usa StrictHostKeyChecking, BatchMode, sem senha interativa,
sem encaminhamento e ignora configurações locais que introduzam proxies/comandos.

O destino deve encontrar `netsec` no PATH não interativo. Com `sudo: true`, deve permitir
`sudo -n -- netsec agent`; configure uma conta/chave dedicada com comando forçado e
privilégio restrito. Não conceda sudo genérico. Instale código privilegiado em diretório
não gravável pela conta de automação. O agente controla o firewall local, portanto a
autorização SSH é uma fronteira de segurança real.

```sh
poetry run netsec run politica.netsec --mode ssh --inventory data/ssh.json --apply --fail-fast
poetry run netsec firewall-remove politica.netsec --mode ssh --inventory data/ssh.json --apply
```

Antes da primeira ação, todos os destinos de firewall passam por compilação e preflight
remotos. A porta SSH configurada no inventário também é protegida. O controlador faz
os checks externos; o agente só recebe fonte JSON e aplica a instrução compilada correta.
Há timeout em cada processo/conexão. Falhas de escrita/SSH **não são repetidas cegamente**:
o estado pode ter mudado antes de cair a resposta; inspecione o diário e reexecute para
reconciliar. Não há atomicidade entre máquinas nem rollback distribuído automático.

## 5. Funções e DNS

```netsec
fn app_port(int base, int offset) -> port = port(base + offset);
fn belongs(ip endpoint, network subnet) -> bool = endpoint in subnet;
```

Veja `examples/05_functions.netsec` e `examples/06_dns.netsec`. Funções são puras, com
parâmetros e retorno explícitos, sem efeitos de rede. Aritmética/domínios inválidos
falham antes da execução. `check dns` verifica A/AAAA contra o IP do host como resolvedor,
não usa automaticamente o DNS da máquina. NXDOMAIN, ausência de resposta, timeout e
endereço inesperado não são tratados como sucesso. Isso não é auditoria DNSSEC.

## 6. Laboratório real e evidências

```sh
docker compose -f lab/professional/compose.yaml up -d --build
poetry run python lab/professional/validate.py
docker compose -f lab/professional/compose.yaml stop
```

São três containers em rede interna, sem portas publicadas, sem acesso ao socket Docker
por montagem. Dois destinos têm NET_ADMIN e um controlador sem essa capacidade usa SSH
com chave efêmera. Host keys são obtidas pelo canal Docker confiável. A chave autorizada
tem comando forçado, sem PTY/forwarding. Credenciais ficam somente nos containers.

O teste mede porta 23 acessível → política aplicada → inacessível por timeout → remoção →
acessível, com SSH/HTTP preservados e reaplicação idempotente. Também verifica DNS A/AAAA.
Evidências vão para uma pasta nova em `data/processed/professional-<UTC>-<id>/`.

Windows nativo é testado no runner descartável do CI com
`poetry run python lab/professional/validate_windows.py --apply`: criação, reaplicação,
mudança de ação e remoção de regra restrita a loopback/porta alta. **Não comprova bloqueio
de tráfego Windows**, pois loopback não representa tráfego de outra máquina. A sessão
local de desenvolvimento não está elevada, e seu firewall não foi alterado.

## 7. Falhas, diários e limites

O módulo [WireGuard Linux](vpn.md) acrescenta criação, reconciliação, status e remoção de
VPNs por manifesto tipado. As chaves não pertencem ao código `.netsec` nem ao manifesto.

Execuções `local`/`ssh` retêm plano e registros JSONL por instrução em uma pasta exclusiva.
`--journal-root` seleciona outro diretório. `--fail-fast` para no primeiro resultado ruim;
sem a opção, resultados individuais são registrados e a execução prossegue. `--output`
nunca sobrescreve um arquivo existente. Códigos: 0 sucesso, 1 observação/ação falhou,
2 entrada inválida ou preflight impedido. O diário pode conter IPs e reports: trate-o como
dado operacional local, não publique indiscriminadamente.

Não há classes/herança, módulos de usuário, agendamento autônomo, roteamento/NAT global,
gestão de equipamentos proprietários nem transação distribuída. A NetSec continua uma
DSL de redes, não um substituto geral para Python ou para uma plataforma de configuração
com décadas de maturidade. Funções e integrações são verificáveis; recursos futuros não
são anunciados como prontos.

Referências de implementação: [nftables](https://netfilter.org/projects/nftables/manpage.html),
[NetSecurity](https://learn.microsoft.com/en-us/powershell/module/netsecurity/),
[OpenSSH](https://man.openbsd.org/ssh_config),
[dnspython](https://dnspython.readthedocs.io/en/stable/resolver-class.html),
[Inno Setup](https://jrsoftware.org/ishelp/topic_setup_privilegesrequiredoverridesallowed.htm).
