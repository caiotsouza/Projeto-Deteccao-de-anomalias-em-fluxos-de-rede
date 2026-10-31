# LAB07 TCP connect / r1 — tentativa preservada, inferência não executada

## 1. Resultado executivo

A tentativa de reconhecimento foi recebida, preservada e auditada offline.
O comando executado examinou **15 portas**, não as 16 planejadas: faltou 5985.
Nmap 7.99 concluiu com exit success em 5,56 s e classificou as 15 portas como
filtered, reason no-response. O PCAP em hn2 contém 39 pacotes SYN somente no
sentido Kali→Windows, sem payload e sem respostas TCP observadas.

A V4 gerou nove registros que representam 18 dos 39 pacotes. Os outros 21
grupos de um único pacote não foram representados nesse CSV. As 60 features
dos nove registros passaram no contrato estrutural, mas a cobertura é parcial.
**Nenhum modelo foi carregado para inferência e nenhuma predição foi gerada.**
Não pontuar apenas esses registros como se fossem a varredura completa.

## 2. Evidências recebidas e preservadas

Recebidos ZIP `986da696-6f6d-49db-b266-be1d148a04fd.zip`, scan.nmap,
scan.gnmap, scan.xml e screenshot do terminal. O processamento leu os quatro
arquivos de dados, sem executar os comandos contidos neles. Cópias e recibos
foram preservados em pasta nova `data/lab/lab07_tcp_connect/r1/`.

`scan_validation.json` registra os hashes originais, o PCAP e a configuração
recebida. `extraction_audit.json` registra CSV, manifesto, contrato e cobertura.
O ZIP tem apenas um JSON e um PCAP, sem diretórios, com CRC conferido. A leitura
XML não carrega o stylesheet declarado, não busca DTD e rejeita entidades e
declarações externas. Os arquivos de texto e XML concordam quanto ao comando
e aos estados das portas.

As imagens anteriores registraram switches privados, WAN desconectada, IPs e
regra temporária restrita. Isso não é monitoramento contínuo, nem prova de que
cada pacote foi efetivamente permitido pelo ruleset durante o scan. Logs do
OPNsense ainda são necessários para essa correlação.

## 3. Plano versus execução

| Item | Observação |
| --- | --- |
| Tipo | TCP connect (-sT), sem NSE, detecção de versão ou exploração |
| Origem observada no PCAP | 172.31.60.10 |
| Único alvo | 172.31.50.161 |
| Portas executadas | 21,22,23,25,53,80,110,135,139,143,443,445,3389,8000,8080 |
| Porta ausente do plano | 5985 |
| Portas fora do escopo | Nenhuma observada |
| Resultado Nmap | 15 filtered / no-response |
| Tempo Nmap | 5,56 s |
| Parâmetros delimitadores | max-rate 10, scan-delay 100ms, max-retries 1, host-timeout 120s |
| Declaração de host ativo no XML | reason=user-set |

O reason user-set corresponde ao uso de -Pn, que omite a descoberta prévia.
A mensagem Host is up não comprova uma resposta do alvo neste ensaio. Os nomes
ftp, ssh, http etc. vêm da tabela de portas (XML method=table), não provam que
esses serviços estejam instalados. Fonte: [Nmap — descoberta](https://nmap.org/book/man-host-discovery.html).

Filtered descreve a visão do scanner, não identifica por si só onde ocorreu
o bloqueio. Não declarar que o firewall Windows ou o OPNsense foi a causa sem
correlação adicional. Fonte: [Nmap — estados de portas](https://nmap.org/book/man-port-scanning-basics.html).

## 4. Observação independente do PCAP

| Medida | Resultado |
| --- | ---: |
| Pacotes TCP/IPv4 | 39 |
| Kali→Windows | 39 |
| Windows→Kali | 0 |
| Flags TCP | SYN apenas (valor 2) nos 39 pacotes |
| Payload TCP | 0 bytes |
| Grupos de endpoints/5-tuplas | 30 |
| Primeiro pacote UTC | 2026-10-26T01:48:19.593732+00:00 |
| Último pacote UTC | 2026-10-26T01:48:23.995383+00:00 |
| Intervalo da captura | 4,401651 s |
| Registros de pacote truncados | 0 |

Todas as 15 portas executadas aparecem na captura, com dois ou três pacotes
por porta. Os 30 grupos não são conexões estabelecidas. Há SYNs repetidos e
mais de uma porta de origem em tentativas para o mesmo destino. Não chamar
39 pacotes de 39 ataques ou assumir um segmento por porta.

O filtro recebido corresponde a lab07_tcp_connect_r1, hn2, IPv4/TCP, host
Windows, porta vazia, snaplen 65535, teto 10000. A janela do PCAP coincide com
a do scanner com tolerância explícita de 1 s, pois XML registra segundos inteiros.
Isso não é uma prova independente de sincronização dos relógios.

Ausência de resposta TCP em hn2 não estabelece recebimento no Windows, causa
do silêncio ou ausência de ICMP: a captura filtrou TCP. Contador de drops não
fornecido. Um próximo passo diagnóstico pode correlacionar logs do firewall e,
se necessário, uma nova coleta na LAN, sem alterar esta tentativa.

## 5. Extração parcial e decisão de não inferir

A imagem existente V4 do commit `98a5ebad0df579cc8b43eedd3421b3ae87699901`
executou sem rede, PCAP somente leitura e saída nova. O acesso ao pipe Docker
falhou na sandbox; a execução autorizada fora dela concluiu sem instalação/build.

| Cobertura | Resultado |
| --- | ---: |
| Grupos presentes no PCAP | 30 |
| Grupos representados pelo CSV | 9 |
| Grupos não representados | 21, todos com um único pacote |
| Pacotes no PCAP | 39 |
| Pacotes somados no CSV | 18 |
| Pacotes não representados | 21 |
| Registros CSV | 9 (10 linhas contando o cabeçalho) |

Os nove registros correspondem a grupos com dois SYNs, sem pacotes backward;
contagens e durações foram cruzadas com as respectivas 5-tuplas do PCAP.
As features são finitas e passam no schema de 60 campos, mas isso não resolve
a omissão dos grupos restantes. A observação demonstra falta de cobertura
nesta tentativa; não pretende generalizar o comportamento de toda versão da
V4 em qualquer cenário.

O estado foi registrado como partial_extraction_inference_not_performed.
Não se criaram linhas artificiais para grupos de um pacote, não se preencheram
NaN/inf, não se descartaram linhas para produzir uma taxa favorável e não se
mudou o contrato/modelo. Nenhum resultado IF/LOF é apresentado para este piloto.

## 6. Implementação, testes e arquivos

Foram criados `validate_lab07_scan.py` e `audit_lab07_extraction.py`, separados
dos validadores e consolidados HTTP. O primeiro valida o escopo real e preserva
desvios; o segundo compara a cobertura da V4 com o PCAP. Nenhum executa Nmap,
carrega modelos ou grava no MongoDB.

Passaram 49 testes selecionados: os 39 anteriores e dez novos. Os novos cobrem
portas fora do escopo, ranges/duplicatas, alvo/parâmetros incorretos, formatos
divergentes, logs vazios, entidades XML externas, desvio explícito, user-set
sem comprovação de host, cobertura parcial e CSV inconsistente/duplicado.
Os hashes dos modelos joblib foram conferidos com o registro operacional, sem
carregá-los. A matriz HTTP anterior permaneceu separada e inalterada.

Diretório de evidências: `data/lab/lab07_tcp_connect/r1/`, com `input/`,
`scanner_logs/`, `scan_validation.json`, `extracted/` e `extraction_audit.json`.
Os arquivos de saída não sobrescrevem tentativas anteriores. Para reproduzir a
importação é necessária pasta nova; se Downloads não mantiver mais os originais,
usar as cópias preservadas, conservando seus hashes e a procedência.

## 7. Próximo passo delimitado

Não repetir automaticamente a varredura. No OPNsense, consultar os logs com
origem 172.31.60.10 e destino 172.31.50.161, na janela UTC 01:48:19–01:48:24
de 26/10/2026 (22:48:19–22:48:24 de 25/10 em Brasília). A interface pode
exibir outro fuso; conferir antes de correlacionar.

Registrar Pass/Block, interface e regra associada. Pass não comprova recebimento
final no Windows; Block não comprova qual regra sem consultar o registro. Se
os logs não estiverem mais disponíveis, registrar essa limitação, sem inventar
causa. Não desabilitar globalmente Windows Firewall ou ampliar a regra any/any.

Uma nova tentativa, se necessária, deve ter pasta/job novos e comando corrigido
com 5985, mantendo r1 como piloto com desvio. A extensão do extrator ou do
contrato para grupos de um pacote precisa de decisão metodológica própria,
testes e comparação; não será uma correção silenciosa dos dados.

## 8. Evidência posterior: logs permitem tráfego na entrada e saída

Foram recebidas sete screenshots do Live View na janela local 22:48:20–24.
Cópias sem alteração, conferidas por SHA-256 contra as imagens recebidas,
ficam em `data/lab/lab07_tcp_connect/r1/firewall_evidence/`. São evidências
visuais parciais, não exportação integral dos logs nem contagem de todos os
pacotes. O recibo original do PCAP foi preservado, sem reescrever seus campos.

Os registros visíveis mostram Pass na entrada KALI sob a regra LAB07 e Pass
na saída LAN, para as mesmas tuplas Kali→Windows. Exemplos incluem
172.31.60.10:45728 → 172.31.50.161:445, :55136 → :53 e :39090 → :3389,
que coincidem com grupos do PCAP/CSV. Isso evidencia que a política OPNsense
permitiu esses fluxos e sua saída LAN; não comprova recebimento final no Windows,
resposta do host ou causa do silêncio em todas as tentativas.

O rótulo de saída let out anything from firewall host itself não muda o endereço
de origem observado: as linhas mantêm 172.31.60.10. Não interpretar o nome da
regra como prova de que a varredura foi originada pelo firewall.

As linhas vermelhas visíveis são UDP 172.31.60.10:55624 → 172.31.60.1:53,
Default deny/state violation. Não são o TCP para 172.31.50.161 do ensaio; não
explicam automaticamente seus resultados filtered. Não atribuir a origem dessas
requisições DNS ao Nmap, que foi executado com -n. Esse tráfego não consta no
PCAP restrito a TCP, mas aparece nos logs mais amplos. Não é necessário liberar
DNS ou reconectar WAN para diagnosticar o piloto.

Próximo diagnóstico é somente leitura no Windows-LAB: perfil de rede ativo,
política efetiva do firewall, configuração de log de descartes e listeners nas
16 portas do plano. Firewall do Windows é uma hipótese, não causa comprovada;
um perfil habilitado não prova que ele descartou aqueles SYNs. Inventário atual
também não reconstrói automaticamente o estado do host no momento passado.

```powershell
Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, LogBlocked, LogFileName | Format-List
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in @(21,22,23,25,53,80,110,135,139,143,443,445,3389,5985,8000,8080) } | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort
```

Nenhuma regra do Windows foi criada, removida ou desabilitada. Não foi feita
nova varredura, nem inferência sobre a extração parcial. Se os logs Windows
não existirem, não há registro retroativo a recuperar: uma próxima coleta
delimitada poderá exigir evidência no próprio host ou na LAN, em sessão nova.

Referências: [política efetiva do firewall](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile),
[listeners TCP](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection),
[limites dos logs do OPNsense](https://docs.opnsense.org/manual/logging_firewall.html).

## 9. Consulta posterior no Windows e diagnóstico proposto

A screenshot seguinte mostra interface Ethernet em perfil Public, firewall
habilitado e DefaultInboundAction Block nos três perfis. LogBlocked está False
em todos. Listeners observados: 0.0.0.0:135 e [::]:135 (PID 1008),
172.31.50.161:139 (PID 4) e [::]:445 (PID 4). O último não comprova sozinho
escuta IPv4 em 445. A consulta atual não reconstitui automaticamente o estado
do host no momento da varredura anterior.

O conjunto de evidências torna a filtragem do Windows uma hipótese forte,
mas DefaultInboundAction Block pode ter exceções. Não equivale a uma linha
de descarte desses SYNs. Como LogBlocked estava False, habilitá-lo agora não
produz registros retroativos da primeira tentativa.

Foi proposto habilitar somente o log de descartes do perfil Public, sem mudar
Enabled, ação padrão, categoria de rede ou permissões. A configuração prévia
False está documentada. O comando a executar no Windows-LAB como administrador:

```powershell
Set-NetFirewallProfile -Name Public -LogBlocked True
Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, LogBlocked, LogFileName | Format-List
```

Somente se a política efetiva confirmar LogBlocked True, um teste diagnóstico
novo e separado pode consultar exclusivamente TCP 135 (listener IPv4 observado),
mantendo WAN desconectada, regra OPNsense restrita e Windows Firewall habilitado.
Uma pasta nova, por exemplo `/tmp/lab07-diag135-r1`, deve preservar a saída:

```bash
mkdir /tmp/lab07-diag135-r1
nmap -n -Pn -sT -p 135 --max-rate 1 --max-retries 0 --host-timeout 20s -oA /tmp/lab07-diag135-r1/scan 172.31.50.161
```

Se mkdir falhar por pasta existente, parar sem sobrescrever. Esse diagnóstico
de uma porta não substitui r1 e não deve ser processado pelo validador fixo
do comando original nem incluído no conjunto HTTP/modelos. Retransmissões TCP
do sistema operacional não são controladas integralmente pelo max-retries.
Após o teste, conferir as linhas recentes do log Windows, inclusive seu cabeçalho
Fields, para correlacionar horário, DROP TCP, origem Kali, destino Windows e
porta de destino 135. Um descarte correspondente confirma filtragem pelo
Windows para o teste novo, não retroativamente para todos os pacotes antigos.
Sem linha correspondente, manter a causa em aberto e revisar logging/captura.

Nenhuma dessas alterações ou sondagens foi executada pelo assistente nesta
etapa. Após guardar os registros, o valor anterior pode ser restaurado com
Set-NetFirewallProfile -Name Public -LogBlocked False, sem apagar o arquivo.
Fonte: [Microsoft — log de pacotes descartados](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging).

## 10. Resultado visual do diagnóstico TCP 135

As duas screenshots seguintes mostram a execução pelo usuário do comando
diagnóstico de uma porta, com max-retries 0 e host-timeout 20s. Nmap 7.99
reportou TCP 135 filtered e duração 1,02 s, com aviso de que atingiu o limite
de retransmissão configurado em zero. A mensagem Host is up continua decorrente
de -Pn, não comprovação de resposta do alvo.

O Get-Content do pfirewall.log retornou somente as linhas de cabeçalho Version,
Software, Time Format e Fields, sem linha DROP ou outra ocorrência. Não foi
enviada junto a confirmação efetiva de LogBlocked True. O cabeçalho indica um
arquivo de log existente, mas não demonstra que o perfil ativo registrou o
teste ou que os SYNs alcançaram o Windows. Não há evidência suficiente para
atribuir a filtragem ao Windows neste diagnóstico.

Próximo passo: reconferir perfil ativo, LogBlocked/LogAllowed/caminho na
ActiveStore e horário/última escrita do arquivo, somente leitura. Não repetir
a mesma varredura, aumentar retries, abrir portas ou desabilitar firewall
apenas para preencher o log. Se LogBlocked True estiver efetivo e ainda faltar
evidência, considerar captura nova na LAN e no próprio Windows com um único
teste delimitado, registrando previamente os instrumentos e os horários.
Os pacotes do diagnóstico novo não foram fornecidos em PCAP/XML nesta etapa;
somente as imagens foram interpretadas. A extração parcial do piloto original
e a decisão de não executar inferência permanecem inalteradas.

Uma screenshot posterior confirmou Public ativo e LogBlocked True efetivo;
arquivo de log 521 bytes, LastWriteTime 23:25:38, consultado às 23:28:30.
Isso confirma a configuração, não um descarte. Foi preparado o roteiro
`LAB07_DIAG135_CAPTURE.md`, com captura filtrada na LAN e NIC do Windows,
uma única sondagem TCP 135 e pasta/job novos r2. Ainda não executado pelo
assistente; não abre portas nem desabilita proteção.
