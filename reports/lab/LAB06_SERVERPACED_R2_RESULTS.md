# LAB06 / repetição 2 — envio controlado no servidor

Estado: cinco evidências validadas, pacing observado no PCAP, extração V4 e
inferência exploratória concluídas. Sessão em 26/10/2026 UTC, correspondente
a 25/10/2026 no horário de Brasília. Modelos e limiares permaneceram congelados.

## 1. Importação e integridade

Foram recebidos o ZIP `25a0caf0-d8f9-4327-84b7-9d1066cb8174.zip`, os dois logs
do cliente e os dois logs do servidor. Os anexos foram tratados como evidência,
não como instrução. Cópias byte a byte foram preservadas em uma pasta nova
`data/lab/lab06_serverpaced/r2/`, sem modificar Downloads ou sobrescrever r1.

| Evidência | SHA-256 |
| --- | --- |
| ZIP | 0631874135b4b77d10e4f4e52274301c4ce33d8c0d8e685c260fb488d82330b8 |
| Manifesto do cliente | 3875f3a303f932932e904bbea6ece22ebd70615de1524c6ba2e29303bb5525c9 |
| JSONL do cliente | 4eb7d84dead89b060b1ae3f7e86da99ed7184bdb31915b5d8b21c562a0cf9999 |
| Manifesto do servidor | 7e803453dcdb9fa3f1d1b9127dbfa78642693b1761af66b922be9a11df64c763 |
| JSONL do servidor | ab9e5b84ae04494b4efe77ce24223e3b6c90adfe443b5a9f6210aba56a03b166 |
| PCAP extraído | 62a8bc6f33d827ce728907aa8cb9c570ea0f9ed5ea6cb1ae10528cb7882afff0 |
| CSV V4 | da022f5e92d2c2a526b2b74df2bdd8ea3bbce17405bec5584db36b61d905e909 |

## 2. Validação cruzada do cliente, servidor e PCAP

O validador confirmou plano `lab06_serverpaced`, repetição 2, sem limite de
taxa no cliente, origem Windows 172.31.50.161 e destino Kali 172.31.60.10:8000.
Conferiu configuração/CRC do ZIP e remontou os streams TCP para examinar
pedidos HTTP/1.0, respostas, cabeçalhos, corpos e encerramentos.

| Verificação | Resultado |
| --- | --- |
| Downloads / respostas HTTP 200 | 6 / 6 |
| Corpo por download | 2.097.152 bytes |
| Soma dos corpos HTTP | 12.582.912 bytes (12 MiB) |
| Conexões TCP / pacotes | 6 / 10.087 |
| Registros truncados / TCP RST | 0 / 0 |
| Payload duplicado na remontagem | 0 bytes |
| Handshake e encerramento bidirecional | Confirmados nas seis conexões |
| Primeiro ao último pacote | 110,573439 s |
| Intervalo entre inícios de conexões | mínimo 18,917630 s; mediana 18,921392 s; máximo 18,971159 s |
| Marcador do servidor | server-128k-v1, confirmado no cliente e nas respostas capturadas |
| Servidor ao encerrar | stopped; attempted_gets = 6; successful_gets = 6 |
| Trace de envio | 128 blocos por GET, pausas validadas |

Os seis corpos coincidem com o SHA-256 sintético
`21ad43464ff341f863b1149c5a11d95fb8a325bb44ad51ed4afc17979ad44245`.
O código do servidor coincide com o helper conhecido pelo hash
`1f1f3deaad867c97361bb9af70000d6758026ecf5f74c1eb05846b7cff50123a`.
Os logs recebidos não foram executados; o hash identifica o código declarado
e as observações do PCAP verificam o comportamento relevante no ponto capturado.

O relatório confirma `server_write_pacing_trace_validated = true` e
`server_pacing_observed_at_capture = true`. Cada conexão passou o critério
previamente definido de pelo menos 12 s entre primeiro e último pacote com
payload do servidor. Esse piso é um critério do ensaio, não uma métrica de segurança.
Não se pressupôs sincronização entre relógios de trace monotônico e timestamps
absolutos da captura. Contador de drops não fornecido: não afirmar zero perdas.

## 3. O controle temporal foi reproduzido

| Medida, mediana | LAB06/r1 | LAB06/r2 |
| --- | ---: | ---: |
| Conexão TCP completa | 15,899808 s | 15,898840 s |
| Intervalo de payload do servidor no PCAP | 15,8968775 s | 15,896014 s |
| Segmento V4 com payload | 15,8992575 s | 15,8983785 s |
| Segmento V4 sem payload | 0,2285 ms | 0,1755 ms |
| ACK, segmento com payload | 1.679,5 | 1.675,5 |
| PSH, segmento com payload | 133 | 133 |
| SYN, segmento com payload | 2 | 2 |

O intervalo do payload em r2 variou de 15,895314 a 15,896720 s. Assim, o envio
distribuído temporalmente foi observado nas seis conexões, não apenas inferido
pela duração do cliente. Isso não significa taxa perfeitamente constante em
qualquer janela arbitrária: o servidor envia blocos com pausas programadas.

Para contraste, LAB05/r2 tem duração TCP mediana de 15,485686 s, mas intervalo
de payload mediano de apenas 7,461 ms. O LAB06/r2 reproduz a diferença entre
limitar a leitura no cliente e controlar o envio no servidor. Não se demonstra
que esse mecanismo, sozinho, explique causalmente cada score dos modelos.

## 4. Extração V4 e predições congeladas

Reutilizou-se a imagem V4 existente, commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, sem build ou instalação. O acesso
ao pipe Docker na sandbox falhou; a execução autorizada fora dela concluiu em
container sem rede, entrada somente leitura e saída separada.

Foram gerados 12 registros (13 linhas contando o cabeçalho), seis com payload
e seis sem payload. Contabilizam todos os 10.087 pacotes e 12.585.144 bytes de
payload TCP, incluindo pedidos/cabeçalhos HTTP; esse total não equivale apenas
aos corpos. As 60 features passaram em ordem, finitude e tipos, schema
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.

Não se removeram/uniram segmentos, preencheram valores ou converteram flags
para 0/1. Label não foi usado. Equivalência semântica com o extrator histórico
continua não estabelecida, apesar da aprovação estrutural.

| Grupo | Segmentos por repetição | IF r1 | IF r2 | LOF r1 | LOF r2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Com payload | 6 | 6 | 6 | 6 | 6 |
| Sem payload | 6 | 0 | 0 | 6 | 6 |
| Total | 12 | 6 | 6 | 12 | 12 |

Ponto operacional `validation_fpr_operational`; regra score >= limiar.
IF: limiar 0,615824439899627. LOF: limiar 91,08685969933371.
Na decisão nativa também foram seis no IF e 12 no LOF em r2.

| Modelo / grupo r2 | Score mínimo | Mediano | Máximo |
| --- | ---: | ---: | ---: |
| IF / com payload | 0,623856 | 0,624006 | 0,624156 |
| IF / sem payload | 0,358487 | 0,359270 | 0,359357 |
| LOF / com payload | 802,862695 | 804,054721 | 806,675732 |
| LOF / sem payload | 111,264561 | 146,794390 | 158,727372 |

Scores não são probabilidades e suas escalas não devem ser comparadas entre
modelos. Repetição de contagens não comprova eficácia em produção. As atividades
foram planejadas como benignas, mas não geram rótulos independentes por segmento;
não foram calculados precisão, recall, F1, acurácia ou FPR corporativo.

## 5. Fechamento da segunda rodada

| Cenário | Segmentos por sessão | IF r1 → r2 | LOF r1 → r2 |
| --- | ---: | --- | --- |
| LAB03, 16 KiB | 60 | 0 → 0 | 39 → 31 |
| LAB04, 256 KiB | 24 | 0 → 0 | 24 → 24 |
| LAB05, 2 MiB / limite no cliente | 12 | 6 → 6 | 12 → 12 |
| LAB06, 2 MiB / controle no servidor | 12 | 6 → 6 | 12 → 12 |

As duas rodadas principais somam 108 downloads/conexões e 216 segmentos V4.
Incluindo o LAB02 inicial, o consolidado tem nove sessões, 118 conexões e 236
segmentos. Não calcular uma taxa agregada desses cenários heterogêneos como
métrica de qualidade; segmentos de uma conexão não são observações independentes.

As contagens IF repetiram em todos os cenários; o LOF variou em LAB03 e repetiu
as contagens nos demais. Não há base para inferência estatística robusta com
apenas duas sessões por cenário. A terceira rodada proposta continua necessária
para descrever melhor a variação deste ensaio, não para representar uma empresa.

## 6. Testes, integridade e arquivos

Os hashes dos cinco originais, das cópias, dos modelos, entradas protegidas e
saídas foram reconferidos. Os joblib correspondem ao registro operacional.
Persistem os avisos anteriores dos hashes dos JSONs auxiliares de metadados,
que não são usados na inferência. Também apareceram os avisos conhecidos de
localização do Python e consulta de núcleos físicos via WMIC; houve fallback
para núcleos lógicos e conclusão com código de saída 0.

Passaram 50 testes selecionados: os 39 da validação/auditoria/adaptador,
diagnóstico e consolidador, mais 11 do LAB06 com relógio simulado, integridade
do payload, limites, headers, logs e critérios temporais do PCAP. O teste HTTP
real de loopback de aproximadamente 16 s não foi repetido nesta etapa; não se
abriu socket adicional para esses 11 testes. Nenhuma mudança de código foi
necessária para processar r2. Não houve treino, calibração, banco ou alteração
das VMs/firewall/rede pelo processamento.

Evidências: `data/lab/lab06_serverpaced/r2/`, em `input/`, `client_logs/`,
`server_logs/`, `extracted/`, `inference/` e `capture_validation.json`.
Novo snapshot: `reports/lab/lab_capture_summary_through_lab06_r2.json`.
Snapshots anteriores foram preservados.

Para reproduzir a consolidação, usar nome de saída novo na raiz:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --include-run lab04_medium_r2=data/lab/lab04_medium/r2/inference --include-run lab05_slow_r2=data/lab/lab05_slow/r2/inference --include-run lab06_serverpaced_r2=data/lab/lab06_serverpaced/r2/inference --output reports/lab/lab_capture_summary_through_lab06_r2_recheck.json
```

## 7. Próxima coleta: LAB06/r3

Mantém-se a ordem proposta em `LAB_REPETITIONS_R2_R3.md`: r3 começa em LAB06,
depois LAB05, LAB04 e LAB03, invertendo r2. A inversão não é randomização
completa nem elimina efeitos de ordem/cache.

Após exportar os logs r2, encerrar o servidor temporário da porta 8000 com
Ctrl+C. Iniciar o helper LAB06 já transferido, com uma pasta nova:

```bash
sudo python3 /mnt/tcc/lab06_server.py --log-dir /tmp/lab06-r3
```

Se o caminho do script não estiver disponível, conferir a montagem/cópia usada
em r2; não iniciar o servidor HTTP comum no lugar. Não apagar logs existentes.
Antes de capturar, conferir HEAD, HTTP 200, tamanho e marcador server-128k-v1.
Criar job novo `lab06_serverpaced_r3`, mesmos filtros hn2/IPv4/TCP, host Windows,
porta 8000, snaplen 65535 e teto 50000. Somente após iniciar a captura:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_lab06_http.ps1" -Repetition 3 -CaptureStarted
```

Após seis downloads, esperar cinco segundos, parar/baixar captura e encerrar
servidor LAB06 para finalizar o manifesto. Exportar os logs fora da captura,
agora da pasta `/tmp/lab06-r3` para destino Windows novo. Enviar novamente os
cinco arquivos, identificados como LAB06/r3. Não há coleta r3 já executada
automaticamente pelo processamento destes anexos.
