# Diagnóstico TCP 135 / r2 — SYN na LAN, evidência Windows inconclusiva

## 1. Escopo e preservação

Foram recebidos o ZIP LAN `43b2f023-95dc-4706-9fe0-d368c47a0dc7.zip`,
windows.etl, windows.txt e scan (1).nmap/xml/gnmap. O comando diagnóstico foi
executado pelo usuário, não pelo assistente. Não se executou conteúdo dos anexos.
Cópias idênticas e recibo foram preservados em pasta nova
`data/lab/lab07_diag135/r2/`, sem sobrescrever o piloto LAB07/r1 ou as capturas
HTTP. Os seis originais e as cópias conferiam por SHA-256 na reconferência final.

| Evidência | SHA-256 |
| --- | --- |
| ZIP LAN | 6c2bfd7e16787880d8428e8ff69b24bf3e59ea2ea545812ba341dbb689d623b1 |
| windows.etl | 160d1affc4f0afd20577e2cc66436027457ff8e5ac262139ec291f7aa0e6ff58 |
| windows.txt | e13306fc709efd469c493797b20688b02594bdc044b99bc89efb2e071d1d19fc |
| scan (1).nmap | 211b73a937b5fdc0ff5efb300dda0dbb8d975b6f58d17667b77ea223e4572295 |
| scan (1).xml | 943d8c7646570ebaf53910f3bbdc0dfb462b17604bd9d40f212424f7eb3138a6 |
| scan (1).gnmap | acdfe26d5a57201cdbd14158e10e6925520d3053dc55da7329936f45a6eaa2d0 |
| PCAP extraído | f6a3a6db220068d26cce2d1541f2d75682a2ce694d4928cf95466977e8f079fd |

## 2. Scanner e captura LAN

Os três formatos Nmap concordam com o comando diagnóstico delimitado:
alvo 172.31.50.161, TCP connect, somente porta 135, max-rate 1, max-retries 0,
host-timeout 20s, saída /tmp/lab07-diag135-r2/scan. Nmap 7.99 terminou com
exit success, elapsed 1,02 s e estado filtered/no-response. Host ativo tem
reason user-set por -Pn, não comprova resposta.

O ZIP tem apenas JSON e PCAP, nomes seguros e CRC válido. Configuração:
hn1, descrição lab07_diag135_r2_lan, IPv4/TCP, host 172.31.60.10, porta 135,
snaplen 65535, teto 1000, sem promiscuous ou inversões.

| Observação independente | Resultado |
| --- | --- |
| Pacotes | 1 |
| Timestamp UTC | 2026-10-26T02:36:02.322014+00:00 |
| Horário Brasília | 25/10/2026 23:36:02,322014 |
| Origem IP/TCP | 172.31.60.10:54760 |
| Destino IP/TCP | 172.31.50.161:135 |
| Flags / payload | SYN (2) / 0 bytes |
| MAC Ethernet de origem | 00:15:5D:31:50:02 |
| MAC Ethernet de destino | 00:15:5D:01:09:01 |
| TTL | 63 |
| Resposta TCP observada | Nenhuma |
| Registro truncado | Nenhum |

O MAC destino corresponde ao MAC atribuído ao Windows-LAB nas screenshots
anteriores do Hyper-V. Isso é consistente com a destinação esperada, mas um
quadro endereçado a um MAC na LAN não comprova entrega à NIC da VM. Conferir
o MAC atual no guest continua útil. Um pacote não é conexão TCP estabelecida.
Contador de drops da captura não fornecido.

## 3. Evidência do Pktmon e relógios

O TXT enviado está em UTF-16 com BOM. A primeira leitura estrita como UTF-8
falhou antes de criar a pasta de importação; foi adicionado reconhecimento
explícito de BOM UTF-16/UTF-8, sem ignorar bytes nem alterar o original.

Há somente três linhas não vazias, todas de MSNT_SystemTrace: Header e duas
PartitionInfoExtensionV2. Não há linha do provider PktMon ou evento de pacote
no texto fornecido. O cabeçalho declara EventsLost=0 e BuffersLost=0, mas isso
não comprova configuração correta do componente/filtro nem recebimento físico.

Os FILETIMEs StartTime=134374555910726139 e EndTime=134374557967987258
foram convertidos de intervalos de 100 ns desde 1601 UTC, truncados para
microssegundos na apresentação:

| Janela | UTC |
| --- | --- |
| Início declarado do ETL | 2026-10-26 02:33:11,072613 |
| Sondagem Nmap | 2026-10-26 02:36:02–02:36:03 |
| Fim declarado do ETL | 2026-10-26 02:36:36,798725 |

A janela declarada do ETL contém a sondagem; os dados não sustentam dizer
que a captura foi encerrada antes do teste. A comparação não é uma prova
independente de sincronização dos relógios ou funcionamento da captura.

Uma conversão offline adicional, usando pktmon etl2txt disponível no ambiente
de análise, leu a cópia ETL e escreveu windows_redecoded.txt. A ferramenta
retornou exit 0, porém informou **três erros de formatação, zero eventos
formatados**, com erro 0x490 nas três linhas. Portanto essa conversão não é
validação bem-sucedida dos eventos nem prova de ausência de pacotes no ETL.
Não se alterou o original, instalou decoder ou executou captura no host.

## 4. Conclusão permitida

Há evidência de SYN no lado LAN do OPNsense, destinado ao IP/porta e MAC
esperados. Não há evidência utilizável de recebimento pela placa do Windows
ou de descarte pelo Windows Firewall neste conjunto. O estado é
lan_syn_observed_windows_capture_inconclusive, não diagnóstico fechado de
firewall. Não inferir ausência de chegada apenas de um TXT sem pacotes.

A captura/filtro/componentes do Pktmon devem ser conferidos antes de outro
teste. Se necessário depois, usar captura com controle positivo e sessão nova,
sem modificar ou apagar esta tentativa. Não liberar portas nem desabilitar
proteções para fazer o log aparecer.

## 5. Código e testes

Foi criado audit_lab07_diag135.py para preservar os seis arquivos, verificar
ZIP/CRC, cruzar formatos Nmap, auditar o PCAP e analisar os metadados temporais.
O parse_scanner existente ganhou um perfil fechado diag135_r2; seu perfil
pilot original permanece padrão. Um comando recebido nunca é executado.
Não houve carregamento de modelos, extração para inferência, calibração ou banco.

Passaram 55 testes selecionados, os 49 anteriores mais seis novos: perfil
diagnóstico explícito e porta única, rejeição de escopo/perfil incorreto,
encoding BOM, conversão FILETIME/janela, rejeição de cabeçalhos inválidos e
distinção entre linha de provider e comprovação de pacote. A regressão do
piloto e as validações HTTP continuaram passando. Testes não validam sozinhos
o recebimento na infraestrutura do usuário.

Evidências em input/, scanner_logs/, windows_logs/, diagnostic_audit.json e
windows_redecoded.txt dentro de data/lab/lab07_diag135/r2/. Para reproduzir a
importação usar os mesmos seis arquivos e um caminho --output novo, com:

```powershell
.\.venv\Scripts\python.exe -B audit_lab07_diag135.py --archive "received/43b2f023-95dc-4706-9fe0-d368c47a0dc7.zip" --etl "received/windows.etl" --text "received/windows.txt" --normal "received/scan (1).nmap" --xml "received/scan (1).xml" --grepable "received/scan (1).gnmap" --output data/lab/lab07_diag135/r2_recheck
```

## 6. Próxima conferência, somente leitura

No Windows-LAB, PowerShell administrador, registrar:

```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress
pktmon status
pktmon filter list
pktmon list
```

Se disponível, enviar também a saída original de pktmon start dessa tentativa.
A lista atual de filtros pode diferir da configuração durante o teste se
foram removidos após parar; não interpretá-la retroativamente sem esse contexto.
Não executar filter remove geral, não iniciar captura nova nem repetir sondagem
neste passo. Verificar componentes e instrumentação antes de decidir o teste
seguinte. WAN permanece desconectada e firewall habilitado.

Referências: [componentes Pktmon](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-list),
[captura, filtros e análise](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax).
