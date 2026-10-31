# Diagnóstico TCP 135 — captura na LAN e no Windows

Estado: roteiro preparado, não executado pelo assistente. Não é repetição do
piloto de 16 portas nem ensaio de inferência. Um único teste de conectividade
será usado para verificar o recebimento de SYNs, mantendo WAN desconectada,
regra OPNsense restrita e Windows Firewall habilitado, sem liberar serviços.

Atualização: a tentativa foi executada pelo usuário e seus seis arquivos foram
recebidos. Há SYN na LAN, mas a captura Windows é inconclusiva; consultar
`LAB07_DIAG135_R2_RESULTS.md`. Não repetir automaticamente o roteiro abaixo.

## Evidência que motivou o roteiro

A screenshot posterior confirma interface Public e política efetiva com
Enabled True, DefaultInboundAction Block e LogBlocked True para Public.
Domain/Private mantêm LogBlocked False. O arquivo pfirewall.log tem 521 bytes,
LastWriteTime 25/10/2026 23:25:38; relógio consultado às 23:28:30. Tamanho e
última escrita não comprovam linha DROP. O diagnóstico anterior segue sem
causa demonstrada; não afirmar recebimento no Windows com base no Pass do
OPNsense ou no reason user-set do Nmap.

## 1. Preparação do Windows-LAB

Usar PowerShell como administrador dentro da VM. Consultar antes:

```powershell
pktmon status
pktmon filter list
```

Se existir captura ativa ou filtros de outra atividade, parar o procedimento
e enviar a saída. Não executar stop em captura de terceiros nem filter remove
sem nome. Se pktmon/opção não estiver disponível, consultar ajuda da versão;
não instalar programas ou reconectar WAN automaticamente.

Se estiver parado e sem filtros, criar pasta nova e filtro específico:

```powershell
New-Item -ItemType Directory -Path C:\TCC\LAB07_DIAG135_r2 -ErrorAction Stop
Get-NetAdapter | Select-Object Name, Status, MacAddress
pktmon filter add LAB07_TCP135 -i 172.31.60.10 -t TCP -p 135
pktmon start --capture --comp nics --pkt-size 0 --file-size 16 --file-name C:\TCC\LAB07_DIAG135_r2\windows.etl
```

Se a pasta já existir ou qualquer comando falhar, parar sem sobrescrever.
O filtro combina IP Kali, TCP e porta 135, sem distinção de origem/destino;
a presença de filtros extras ampliaria a captura por OR, por isso a checagem
prévia é necessária. Capturar só NICs busca evidência no adaptador; não garante
relatório de toda causa de descarte no restante da pilha. Tamanho máximo 16 MB,
modo padrão circular; o ensaio curto e restrito deve ser parado prontamente.
Não analisar contadores de componentes como número de pacotes únicos sem
considerar duplicações de observação e direção.

## 2. Preparação do Kali, sem sondagem ainda

```bash
mkdir /tmp/lab07-diag135-r2
```

Se já existir, parar. Não reutilizar a pasta r1 do diagnóstico anterior.

## 3. Iniciar a captura LAN do OPNsense

Criar novo job `lab07_diag135_r2_lan`, interface hn1 [LAN], IPv4 only,
protocolo TCP, host 172.31.60.10, porta 135, Packet Length 65535, Count 1000,
sem promiscuous/inversões. Esta interface é LAN, não hn2/KALI do primeiro
piloto. O filtro cobre tentativas e respostas dessa comunicação. Iniciar o job
e confirmar que pktmon iniciou antes de prosseguir. Não misturar HTTP de
exportação com a captura.

## 4. Uma única sondagem

No Kali, executar uma vez:

```bash
nmap -n -Pn -sT -p 135 --max-rate 1 --max-retries 0 --host-timeout 20s -oA /tmp/lab07-diag135-r2/scan 172.31.50.161
```

Parâmetros iguais ao diagnóstico anterior, porta única, destino fixo, saída
nova. Max-retries do Nmap não controla integralmente retransmissões do kernel.
Nenhum listener ou regra de entrada Windows será modificado. Parar se alvo
ou isolamento divergir. Não repetir em loop nem usar esse teste para forçar
alerta nos modelos.

## 5. Encerrar e exportar

Após o Nmap terminar, aguardar cinco segundos, parar a captura no OPNsense e
baixar seu ZIP. No Windows, encerrar apenas a captura pktmon iniciada acima:

```powershell
pktmon stop
pktmon etl2txt C:\TCC\LAB07_DIAG135_r2\windows.etl --out C:\TCC\LAB07_DIAG135_r2\windows.txt
Get-Content -LiteralPath "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Tail 40
```

Guardar ETL original e TXT. Não substituir ETL apenas por conversão PCAPNG:
essa conversão pode perder informações de propagação/descarte, e registros de
drop não entram por padrão. Se conversão falhar, preservar ETL e enviar erro.
Após confirmar encerramento, remover somente o filtro criado para este teste,
se a versão aceitar `pktmon filter remove LAB07_TCP135`; conferir a ajuda se
houver erro. Não remover todos os filtros indiscriminadamente.

Evidências: ZIP LAN, windows.etl, windows.txt e os três scan.nmap/xml/gnmap.
Transferir logs do Kali pela rota HTTP conhecida somente com capturas paradas,
usando `/tmp/lab07-diag135-r2` como raiz, pasta Windows nova e WAN desconectada.

## 6. Interpretação pendente

- SYN na LAN e na NIC do Windows: evidência de chegada ao adaptador. Isso não
  comprova entrega à aplicação ou causa exata do silêncio; correlacionar direção,
  MACs, timestamps e eventuais registros de descarte.
- SYN na LAN sem registro Windows: revisar filtros/componentes, integridade da
  captura e MAC/ARP antes de atribuir culpa ao firewall do Windows.
- Sem SYN na LAN: revisar captura e encaminhamento antes de inferir falha do host.
- DROP correspondente no log: confirma filtragem Windows para o teste novo,
  não retroativamente para toda a primeira varredura.

Não alterar o recibo nem a extração parcial LAB07/r1. Nenhuma inferência,
retreinamento, calibração ou gravação de banco faz parte deste diagnóstico.

Fontes oficiais:

- [Pktmon e captura filtrada](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon)
- [Parâmetros de início](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start)
- [Filtros](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-filter-add)
- [Conversão para texto](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2txt)
- [Limites de conversão PCAPNG](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap)
