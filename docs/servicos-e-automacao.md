# Serviços e automação profissional

## 1. Classes, módulos e grupos

`examples/07_classes_modules.netsec` importa `examples/lib/server.netsec`. Classes possuem
campos explicitamente tipados, construtor posicional e métodos puros. Objetos são imutáveis;
use composição de classes, não herança. O compilador verifica também métodos não chamados.

```netsec
class Server {
    ip endpoint;
    port management;
    fn belongs(network subnet) -> bool = self.endpoint in subnet;
}
Server node = Server(ip("192.0.2.10"), port(22));
report node.belongs(network("192.0.2.0/24"));
```

Imports são relativos ao arquivo importador, restritos à pasta do arquivo principal.
Não leem URLs ou pacotes do sistema. Cada módulo é incluído uma vez; ciclos, símbolos
duplicados e symlinks que saem do projeto são recusados. Até 64 módulos e 1 milhão de
caracteres no conjunto. Declarações importadas compartilham o escopo global, sem aliases.
O controlador envia ao agente SSH o conjunto completo das fontes, que é recompilado no
destino. Ambos precisam usar a mesma versão da NetSec.

```sh
poetry run netsec check examples/07_classes_modules.netsec
poetry run netsec compile examples/07_classes_modules.netsec
```

## 2. Subir HTTP e DNS de verdade no Linux

Requisitos: Linux com systemd, `iproute2`, `nginx` e `dnsmasq-base`. O backend foi
desenhado para Ubuntu/Debian. Instale os pacotes pelo gerenciador da distribuição;
a NetSec não instala silenciosamente pacotes do sistema. Para firewall, instale também
`nftables`. Para VPN, `wireguard-tools` e suporte WireGuard no kernel.

```netsec
group local { host "local" address "127.0.0.1"; }
play "local_stack" targets local {
    server http "site" port 18080 response "<h1>NetSec is running</h1>";
    server dns "resolver" port 15353 record "app.netsec.test" address current_host;
    check service "http" port 18080;
    check dns "app.netsec.test" port 15353 expect current_host;
}
```

Valide e veja a prévia sem privilégios. Em uma instalação administrativa confiável,
rode como root o executável `netsec` efetivamente instalado:

```sh
netsec check examples/08_servers.netsec
netsec preview examples/08_servers.netsec
sudo /path/to/installed/netsec run examples/08_servers.netsec --mode local --apply
```

O caminho `/path/to/installed/netsec` é um placeholder: substitua pelo executável da
sua instalação. Não use código modificável por usuários comuns em jobs root.

O HTTP usa nginx, servindo um conteúdo estático, sem interpolar esse conteúdo em
diretivas. O DNS usa dnsmasq para o registro exato declarado, sem upstream, DHCP ou
alteração do DNS do sistema. Não é um painel de hospedagem nem um servidor DNS recursivo.
Portas opcionais em `check service` e `check dns` permitem verificar esses endpoints.

Cada recurso cria sua própria unit `netsec-srv-<nome>-<identificador>.service`, habilitada
no boot. O processo servidor usa `DynamicUser`, restrição de escrita e somente a
capacidade de bind a portas baixas. Configurações ficam em revisões de `/etc/netsec/services`.
Serviços e configurações globais existentes de nginx/dnsmasq não são substituídos.
A NetSec verifica protocolo e disponibilidade após iniciar o serviço.

Reaplicar retorna `unchanged` quando configuração e execução já correspondem ao desejado.
Serviço parado é reiniciado. Revisões alteradas são preservadas e substituídas por uma
nova revisão íntegra. A remoção desabilita e para apenas as units marcadas pela NetSec:

```sh
sudo /path/to/installed/netsec server-remove examples/08_servers.netsec --mode local --apply
```

Units removidas ficam arquivadas com sufixo `.retired`; revisões são conservadas. A
remoção não apaga conteúdos de outros programas nem limpa automaticamente o histórico.
Para implantação remota, use `run --mode ssh --inventory ... --apply`, com os mesmos
pré-requisitos no destino. Todos os destinos passam por preflight antes das ações.

### Instalação Linux protegida para jobs root

Em uma VM Ubuntu 24.04 dedicada, o seguinte roteiro instala a aplicação em diretório
administrativo. Revise o código/branch antes: tudo instalado como root entra na base de
confiança da máquina. Não copie um ambiente virtual de usuário para um serviço privilegiado.

```sh
sudo -i
apt-get update
apt-get install -y python3.12 python3.12-venv pipx git nginx dnsmasq-base nftables iproute2 wireguard-tools
pipx install poetry==2.4.1
git clone --branch feat/professional-platform https://github.com/Mathwesm/NetSec.git /usr/local/lib/netsec
cd /usr/local/lib/netsec
export POETRY_VIRTUALENVS_IN_PROJECT=true
/root/.local/bin/poetry env use /usr/bin/python3.12
/root/.local/bin/poetry install --only main --no-interaction
.venv/bin/netsec check examples/08_servers.netsec
.venv/bin/netsec preview examples/08_servers.netsec
```

O executável para substituir os placeholders deste guia será
`/usr/local/lib/netsec/.venv/bin/netsec`. O clone exige um destino ainda inexistente:
nunca apague uma instalação existente para repetir o roteiro. Para desenvolvimento sem
privilégios, use o clone normal do README, não esta instalação administrativa.
Volte ao usuário comum com `exit` após configurar. Os pacotes do sistema são requisitos
explícitos; Poetry continua gerenciando todas as dependências Python da aplicação.

## 3. Criar um job persistente

O manifesto fixa uma cópia das fontes e módulos. Editar o `.netsec` original não muda
um job instalado: gere outro manifesto, revise e reinstale explicitamente.

```sh
netsec automation bundle examples/08_servers.netsec --name local-stack --mode local --interval 300 --output data/jobs/local-stack.json
netsec automation check data/jobs/local-stack.json
netsec automation preview data/jobs/local-stack.json
sudo /path/to/installed/netsec automation install data/jobs/local-stack.json --apply
sudo /path/to/installed/netsec automation status data/jobs/local-stack.json
sudo /path/to/installed/netsec automation remove data/jobs/local-stack.json --apply
```

No Linux, o job instala uma service `oneshot` e um timer. O intervalo mínimo é 60 segundos;
máximo, 12 horas. Há ativação no boot, atraso aleatório e proteção contra sobreposição
do mesmo job. A execução tem limite de cinco minutos. A instalação verifica proprietário
e permissões do interpretador, código e configurações: tudo privilegiado precisa estar
sob controle de root, sem ancestrais graváveis por usuários comuns.

O job reaplica o estado desejado e repete os checks; não pula instruções com base num
resultado antigo. Isso permite recuperar uma execução parcial sem pressupor que a rede
continua no mesmo estado. Não há transação distribuída nem rollback entre máquinas.

Resultados por execução ficam em `/var/lib/netsec/jobs/<nome>/`: `run_id`, horário UTC,
duração, quantidade de instruções, falhas, resultado final e diário por instrução.
Falhas não viram sucesso silencioso. `automation execute <manifesto> --apply` permite
executar e depurar o mesmo job manualmente, com saída não zero quando ele falha.

Para jobs SSH, gere o bundle e configure no JSON `mode: "ssh"` com `inventory` no formato
do [guia profissional](profissional.md). Use caminhos absolutos para chave e `known_hosts`:
o diretório de trabalho do serviço não é o terminal interativo. Manifestos passam pela
mesma validação antes de instalação. Não copie chaves privadas para o JSON.

## 4. Tarefas no Windows

Instale o pacote **para todos os usuários em Program Files**, abra o terminal como
administrador e use `cli/NetSec.exe`. Compilar e verificar não requer elevação; instalar
uma tarefa SYSTEM requer. Instalação por usuário continua disponível para uso interativo.

```powershell
& 'C:\Program Files\NetSec\cli\NetSec.exe' automation bundle .\audit.netsec --name network-audit --mode network --interval 300 --output .\data\audit-job.json
& 'C:\Program Files\NetSec\cli\NetSec.exe' automation install .\data\audit-job.json --apply
& 'C:\Program Files\NetSec\cli\NetSec.exe' automation status .\data\audit-job.json
& 'C:\Program Files\NetSec\cli\NetSec.exe' automation remove .\data\audit-job.json --apply
```

`audit.netsec` deve conter seus próprios IPs e checks; use `--mode local` apenas para
políticas destinadas ao firewall desta máquina. O job usa conta SYSTEM, gatilho de boot,
repetição e limite de execução, sem senha gravada e sem abrir janela. Manifestos e
histórico ficam em `%ProgramData%\NetSec\jobs`, com ACL restrita. Executáveis graváveis
por usuários comuns e caminhos com reparse points são recusados. Nenhuma tarefa é
instalada automaticamente ao abrir a interface ou instalar o aplicativo.

Provisionamento HTTP/DNS e criação de VPN continuam específicos do Linux. Jobs Windows
aceitam políticas `network`/`local`, não inventário SSH nem arquivo de segredos.

## 5. VPN e alertas

Um job Linux com `kind: "vpn"`, `tunnel` no formato de [VPN](vpn.md) e `secrets_file`
absoluto pode reconciliar o túnel após o boot. O arquivo de ambiente deve ser propriedade
de root e ter permissão `0600`; a unit o lê via `EnvironmentFile`. A chave privada fica
em `NETSEC_WG_PRIVATE_KEY`, nunca no manifesto público. Faça primeiro o teste manual
do túnel e do roteamento. Remover o job desabilita a automação, mas não desmonta o túnel;
para isso, use `netsec vpn down` explicitamente.

Estrutura do job (o campo `tunnel` deve receber seu manifesto já validado, não o placeholder):

```json
{
  "name": "office-vpn",
  "kind": "vpn",
  "interval_seconds": 300,
  "secrets_file": "/etc/netsec/office-vpn.env",
  "tunnel": "SUBSTITUA_PELO_OBJETO_DO_MANIFESTO_VPN"
}
```

Use `automation check`, `preview` e `install --apply` como no exemplo de políticas. O
arquivo de ambiente contém `NETSEC_WG_PRIVATE_KEY=<sua-chave-local>`; crie-o por seu
mecanismo de implantação de segredos, sem versionar e sem copiar a chave para logs.
Não são aceitos padrões glob ou quebras de linha no caminho desse arquivo.

Alertas de falha usam Telegram quando `alert_on_failure: true`. Configure
`TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID` no ambiente real do serviço (não apenas no terminal
interativo). A mensagem contém nome do job e `run_id`, não chave, fonte nem inventário.
O envio tem timeout e retry com backoff/jitter. Sem configuração de credenciais, não há
notificação Telegram; logs, diário e status não zero continuam disponíveis. No Windows,
as credenciais precisam estar disponíveis para a conta SYSTEM.

## 6. Desempenho e verificação

`run --workers 8` paraleliza lotes consecutivos de checks. Alterações de firewall,
provisionamento e reports preservam barreiras de execução; resultados continuam em
ordem de fonte. `--fail-fast` usa execução serial para não disparar checks após a falha.
Até 32 workers; jobs usam quatro por padrão. Não há threads ilimitadas ou repetição
automática de escritas cujo resultado seja incerto.

```sh
poetry run python lab/professional/benchmark.py
```

O benchmark mede compilação de 128 hosts/2.560 instruções e compara 24 checks HTTP
reais em loopback, com latência controlada de 50 ms. Números variam por máquina e não
representam SLA de produção. Cada medição vai para uma nova pasta de evidências.

Testes privilegiados vivem nos workflows `CI` e `Professional deployment`, executados
em máquinas descartáveis. O teste Windows de tráfego usa um cliente em contêiner Windows
com IP distinto e verifica conexão permitida → bloqueada → restaurada. O servidor
confirma o IP de origem; loopback não é contado como evidência de filtragem.
O teste de job VPN cria a interface a partir do serviço, derruba a interface e confirma
sua recuperação, mantendo a chave somente num arquivo temporário protegido da VM.
O teste de tráfego criptografado entre dois peers é separado. Consulte o
[relatório da versão 0.3](validacao-0.3.md) para resultados e limites do que foi medido.

## 7. Assinatura do instalador

O pacote funciona sem assinatura, mas não pode exibir um editor publicamente verificado
sem certificado de assinatura de código confiável. Não é possível obter essa confiança
apenas mudando o código ou criando um certificado autoassinado.

Com seu certificado no store do usuário de build e SignTool do Windows SDK disponível:

```powershell
./packaging/windows/build.ps1 -Compiler 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' -CertificateThumbprint '<thumbprint-do-seu-certificado>'
```

O script assina CLI, interface e instalador com SHA-256, timestamp e verificação de
confiança. A chave privada não é exportada nem passa por argumentos. Sem certificado,
o build continua explicitamente não assinado.

Referências: [systemd timers](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html),
[Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page),
[SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).
