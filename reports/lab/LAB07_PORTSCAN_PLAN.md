# LAB07 — piloto de varredura TCP controlada

Estado: **planejado, não executado**. Nenhuma captura de ataque foi recebida,
nenhuma regra foi alterada e nenhum comando de varredura foi executado nesta
etapa. A matriz benigna LAB03–LAB06/r1–r3 permanece congelada e separada.

**Atualização posterior:** o piloto r1 foi executado pelo usuário e recebido.
Foram examinadas 15 portas (faltou 5985), com resultados filtered/no-response.
O PCAP tem 39 SYNs; a extração V4 representou somente 18 pacotes em nove
registros. Não houve inferência. Consulte `LAB07_TCP_CONNECT_R1_RESULTS.md`.
As instruções abaixo preservam o plano original, não uma confirmação de que
todas as condições planejadas foram cumpridas. Próximo passo: correlação dos
logs, não repetição automática.

## 1. Objetivo e escopo

Observar a resposta dos modelos a uma atividade controlada de reconhecimento
de portas, sem exploração, autenticação, força bruta, malware ou negação de
serviço. O piloto não tem como objetivo comprometer o Windows ou demonstrar
que um alerta equivale a um ataque detectado corretamente.

| Item | Plano inicial |
| --- | --- |
| Identificador | lab07_tcp_connect_r1 |
| Emissor | Kali-LAB, 172.31.60.10 |
| Único destino | Windows-LAB, 172.31.50.161 |
| Técnica | TCP connect scan, Nmap -sT |
| Portas TCP | 21,22,23,25,53,80,110,135,139,143,443,445,3389,5985,8000,8080 |
| Quantidade de portas | 16 |
| Teto de probes controlados pelo Nmap | --max-rate 10; não é teto de todo pacote TCP gerado pelo SO |
| Espaçamento adicional | --scan-delay 100ms |
| Retransmissões do Nmap | --max-retries 1; não controla toda retransmissão do kernel |
| Limite de tempo por host | --host-timeout 120s; preservar execução interrompida/incompleta |
| Scripts / versões / exploração | Não executar NSE, -sV, -O ou -A |
| Escopo excluído | Outros IPs, sub-redes, rede doméstica, host pessoal, internet e gateways |

A escolha de 16 portas é um piloto de baixo volume, não um conjunto otimizado
para gerar alertas. Pode produzir poucos segmentos e nenhum alerta. Não ampliar
automaticamente o volume nem reajustar limiares em função do resultado.

O TCP connect utiliza conexões do sistema operacional e pode completar handshake
em portas abertas. Não é o mesmo cenário que SYN half-open. Nenhuma porta ou
serviço precisa ser aberto no Windows apenas para aumentar o resultado: registrar
se o destino responde, rejeita ou filtra é parte da observação.

## 2. Gate de isolamento — primeiro passo obrigatório

O tipo Private do Hyper-V separa o host do segmento virtual, mas uma VM roteadora
com WAN conectada ainda pode encaminhar tráfego para fora. Portanto, o teste
não depende apenas do nome LAB-ATAQUE ou da existência de um switch privado.

No PowerShell do computador que hospeda as VMs, conferir somente leitura:

```powershell
Get-VMNetworkAdapter -VMName "Windows-LAB","Kali-LAB","OPNsense-LAB" |
    Select-Object VMName, Name, SwitchName, MacAddress

Get-VMSwitch |
    Where-Object { $_.Name -in @("LAB-LAN", "LAB-ATAQUE") } |
    Select-Object Name, SwitchType
```

O filtro após listar os switches evita passar um array ao parâmetro Name,
que na instalação do usuário aceita uma única string (erro observado na
primeira conferência). Não altera comutadores nem conexões.

Esperado: Windows tem somente adaptador em LAB-LAN; Kali somente LAB-ATAQUE;
ambos os switches são Private. Se existir outro adaptador, conexão externa,
Default Switch, compartilhamento/NAT alternativo ou ponte, interromper e revisar.

Depois de registrar a configuração, no Hyper-V, desconectar **somente o
adaptador WAN da VM OPNsense-LAB**: Configurações → adaptador associado a LAB-WAN
→ Comutador virtual = Não conectado → Aplicar. Identificar pelo SwitchName/MAC,
não pela posição na lista, pois há três adaptadores com nomes semelhantes.
Não excluir LAB-WAN, não desabilitar o adaptador físico/Wi-Fi do host e não
desconectar os adaptadores LAN ou KALI do OPNsense. Preferir a VM desligada se
a interface não permitir a alteração; iniciar depois para os testes locais.

Reconferir o comando de adaptadores: a WAN deve ter SwitchName vazio, enquanto
as duas interfaces privadas permanecem conectadas. Não reconectar a WAN durante
a coleta. O Windows deve continuar administrando OPNsense por 172.31.50.1.

No Kali, conferir sem gerar varredura:

```bash
ip -br address
ip route
nmap --version
```

Esperado: IP 172.31.60.10/24 e rota via 172.31.60.1. Essa rota default pode
continuar existindo com WAN desconectada; sozinha não comprova acesso externo.
Se Nmap não estiver disponível, parar: não reconectar internet ou instalar
pacotes automaticamente. No Windows-LAB conferir `ipconfig`; IP esperado
172.31.50.161 e gateway 172.31.50.1. Se mudou, revisar o plano antes de agir.

**Evidências recebidas na preparação:** screenshots mostram LAB-LAN e LAB-ATAQUE
como Private, WAN do OPNsense com SwitchName vazio, Windows somente em LAB-LAN
e Kali somente em LAB-ATAQUE. Kali tem 172.31.60.10/24, gateway 172.31.60.1 e
Nmap 7.99; Windows confirmou 172.31.50.161/24 e gateway 172.31.50.1. Essas são
observações das imagens, não monitoramento contínuo. Manter a WAN desconectada.
O gate de regra TCP/captura permanece pendente antes da execução.

## 3. Gate de firewall — revisão antes da coleta

As regras anteriores de ICMP Kali→Windows e TCP Windows→Kali:8000 não comprovam
permissão TCP Kali→Windows. Obter captura da lista de regras da interface KALI
e revisar também regras flutuantes/grupos que possam prevalecer.

Se for necessária permissão, planejar uma regra temporária e identificada:

- Interface KALI; direção In; IPv4; TCP; ação Pass; Quick; Log habilitado.
- Origem exclusivamente 172.31.60.10/32; porta de origem any (porta efêmera).
- Destino exclusivamente 172.31.50.161/32; portas de destino somente a lista
  de 16 portas do plano, por alias de portas devidamente conferido.
- Gateway None e keep state; não criar regra de retorno any/any na LAN.
- Nome sugerido `LAB07 - Kali para Windows - TCP portas piloto`.

A screenshot das regras KALI recebida mostra duas regras manuais de ICMP:
Kali→gateway e Kali→Windows. Não mostra regra manual TCP para o piloto; outras
regras automáticas/flutuantes não foram integralmente auditadas por essa imagem.
Foi orientada a criação manual do alias `LAB07_TCP_PORTS`, tipo Ports, com
16 entradas individuais: 21,22,23,25,53,80,110,135,139,143,443,445,3389,5985,8000,8080.
Não configurar como intervalo contínuo entre a primeira e a última porta.
Salvar/aplicar o alias e depois selecionar esse alias na porta de destino da
regra. Se a interface apresentar campos From/To, usar o mesmo alias nos dois,
não os números 21 e 8080 como limites. Origem permanece com porta any.

Após salvar/aplicar, solicitar imagem da regra TCP e confirmação das entradas
do alias antes de executar. Nenhum alias/regra foi criado automaticamente
pelo assistente; o estado de aplicação ainda precisa ser conferido.

**Conferência posterior pelas imagens:** a regra manual TCP KALI→Windows usa
origem 172.31.60.10/32 e destino 172.31.50.161/32, com alias LAB07_TCP_PORTS.
A edição do alias mostra exatamente as 16 portas individuais do plano,
habilitado e tipo Port(s). A edição da regra mostra Log marcado, keep state e
Gateway None. As imagens de edição não provam aplicação no ruleset ativo:
salvar e aplicar antes da coleta. As regras flutuantes/automáticas não foram
integralmente auditadas; usar os logs para verificar o tratamento real.

O próximo passo orientado é criar `/tmp/lab07-r1` com `mkdir` sem -p: se já
existir, parar e não executar novamente sobre a mesma pasta. Iniciar o job novo
antes do comando Nmap previsto neste plano. Preservar scan.nmap, scan.xml e
scan.gnmap, além do ZIP do OPNsense. Esses arquivos não são os manifestos HTTP.
Depois do scan e espera de cinco segundos, parar/baixar a captura antes de
exportar arquivos. A exportação pode usar o servidor temporário já conhecido,
restrito a `/tmp/lab07-r1`, sem reconectar WAN. Interromper o servidor ao fim.

Essa é uma especificação, não uma regra já criada. Confirmar isolamento e a
ordem real antes de orientar a alteração na tela. Manter Windows Firewall
habilitado. Não desabilitar proteção global nem habilitar serviços vulneráveis.
Não limpar globalmente estados do firewall: isso pode afetar administração e
outros fluxos. Eventual estado específico exige revisão e ação delimitada.

Se o OPNsense bloquear, a captura em hn2 mostra tentativas, mas não comprova
que elas chegaram ao Windows. Se todas as portas forem filtered, não declarar
serviços ausentes ou falha do modelo; correlacionar logs e, se necessário,
coleta separada na LAN. A porta administrativa do OPNsense não é alvo.

## 4. Preparação de evidências, ainda sem varredura

Guardar configuração/regras antes e depois, horários UTC, versão Nmap, IPs,
comando exato e eventual código de saída/timeout. Recomenda-se checkpoint ou
backup recuperável das VMs antes do ensaio, verificando espaço em disco.
Não enviar configuração integral contendo senhas ou chaves; screenshots podem
ser limitadas às interfaces/regras necessárias.

O servidor HTTP de exportação e os geradores anteriores devem estar parados
durante a coleta. Não instalar ou atualizar programas durante a captura.
O serviço Windows deve permanecer no estado registrado para a sessão; não
alterar regras/serviços no meio da execução para conseguir portas abertas.

Criar uma pasta nova de evidências no Kali, sem sobrescrever tentativas.
Registrar começo/fim em UTC. Os formatos Nmap normal/XML/grepable (-oA) são
evidências do scanner, não novos rótulos de ground truth das features.
O comando planejado abaixo somente pode ser usado depois dos gates de
isolamento e firewall confirmados, com diretório de saída novo já preparado:

```bash
nmap -n -Pn -sT -p 21,22,23,25,53,80,110,135,139,143,443,445,3389,5985,8000,8080 --max-rate 10 --scan-delay 100ms --max-retries 1 --host-timeout 120s -oA /tmp/lab07-r1/scan 172.31.50.161
```

Não executar nesta fase de preparação. `-n` evita resolução DNS; `-Pn` omite
descoberta prévia do host, não confirma que ele esteja ativo. Não usar sudo
para esse connect scan por necessidade presumida; conferir permissões e versão.
Não alterar o comando para CIDR, múltiplos hosts ou -p-. Os limites do Nmap não
são garantia de número exato de pacotes ou término de todos os timeouts do SO.

## 5. Captura planejada

Novo job OPNsense, sem reutilizar antigos:

| Campo | Valor |
| --- | --- |
| Descrição | lab07_tcp_connect_r1 |
| Interface | hn2 [KALI] |
| Família / protocolo | IPv4 / TCP |
| Host | 172.31.50.161 |
| Porta de captura | Vazia: observar todas as portas TCP do único host-alvo |
| Packet Length | 65535 |
| Count | 10000 |
| Promiscuous / inversões | Desmarcados |

O filtro vazio de porta não autoriza varredura ampla: o alvo e as 16 portas
continuam fixos no scanner e na regra. Iniciar o job antes do scan; finalizar
após término e espera de cinco segundos, baixar ZIP e preservar também falhas.
Se o teto da captura for atingido, a coleta não está automaticamente completa.
Interromper com Ctrl+C se alvo/IP divergir, surgir tráfego fora de escopo,
houver instabilidade significativa ou se perder a confirmação do isolamento.
Não fazer novas tentativas sobre a mesma pasta/job para substituir a falha.

## 6. Validação e modelos — trabalho posterior à captura

O validador HTTP anterior exige GETs, corpos e encerramentos completos; ele
**não é um validador de varredura**. O consolidado HTTP também assume respostas
200. Não aplicar esses programas ao LAB07 nem inserir o novo cenário por padrão
nos resultados benignos como se fosse HTTP normal.

Será necessário validar alvo, portas, origem, horários, respostas TCP e logs do
scanner, distinguindo tentativas, portas, conexões e segmentos V4. RST, ausência
de payload ou handshakes incompletos podem fazer parte do cenário. Portas
filtered não identificam sozinhas qual firewall filtrou.

A V4 pode gerar durações zero e taxas não finitas em fluxos curtos. Se isso
ocorrer, guardar os arquivos e registrar a incompatibilidade; não substituir
inf/NaN por zero ou excluir linhas sem quantificar e justificar. Só executar
inferência quando os registros atenderem ao contrato existente. Nenhuma
mudança no contrato foi feita para o LAB07.

Usar inicialmente os mesmos joblib/limiares, com contexto separado
`planned_activity=port_scan` ou equivalente fora das 60 features. A intenção
do experimento não se converte automaticamente em rótulo positivo para todo
segmento. Alertas também ocorrem nos ensaios benignos: observar alerta durante
scan não prova discriminação, precisão ou recall. Não treinar/calibrar com o
piloto nem concluir desempenho corporativo.

## 7. Encerramento e fontes

Após preservar as evidências e encerrar o scanner, desabilitar a regra temporária
se tiver sido criada e registrar o estado final. Reconexão da WAN deve ser uma
ação separada, somente quando não houver teste ativo, sem alterar a rede do host.
Não apagar logs, checkpoints ou resultados anteriores como parte desta etapa.

Fontes primárias consultadas para o plano:

- [Nmap — técnicas e TCP connect](https://nmap.org/book/man-port-scanning-techniques.html)
- [Nmap — limites de ritmo, retries e timeout](https://nmap.org/book/man-performance.html)
- [Nmap — descoberta e -Pn](https://nmap.org/book/man-host-discovery.html)
- [Nmap — arquivos de saída](https://nmap.org/book/man-output.html)
- [OPNsense — direção, ordem das regras e estados](https://docs.opnsense.org/manual/firewall.html)
- [Microsoft — tipos de switches Hyper-V](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/plan-hyper-v-networking-in-windows-server)

Essas fontes definem o comportamento das ferramentas; não confirmam a
configuração atual das VMs do usuário. Essa confirmação permanece pendente.
