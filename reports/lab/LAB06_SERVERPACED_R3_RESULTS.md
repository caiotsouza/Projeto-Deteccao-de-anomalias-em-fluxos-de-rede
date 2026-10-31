# LAB06 / repetição 3 — validação e comparação das três sessões

Captura validada, controle de envio observado no PCAP, extração V4 e inferência
exploratória concluídas. Sessão de 26/10/2026 UTC (25/10/2026 em Brasília).
Modelos, limiares e resultados anteriores preservados.

## 1. Evidências e preservação

Os cinco arquivos recebidos foram tratados como dados, não como instruções.
O manifesto do cliente identifica `lab06_serverpaced`, repetição 3, completed,
seis tentativas bem-sucedidas e nenhum controle de taxa no cliente. O servidor
está stopped, com seis GETs tentados e seis concluídos. Cópias idênticas foram
preservadas em pasta nova `data/lab/lab06_serverpaced/r3/`; Downloads e r1/r2
não foram modificados. Originais e cópias tiveram os hashes reconferidos.

| Evidência | SHA-256 |
| --- | --- |
| dfd0b203-cb60-461d-82f7-5cdfd262dbfb.zip | 28b523ae13acdb5b1addd3347f3d7903a06cc6644b31e36b8da34ee9de6322b3 |
| run_manifest.json do cliente | 070a5a1bd5016b77aa0cc85cb4c5c403e9342f0bfb875331dc1169d492295bf9 |
| requests.jsonl do cliente | d00918149f28e0c1f8f68d55a4fe49242bcd4b8288d9eedaaf444df739a61a30 |
| server_manifest.json | e4a3769ce381c8855ccc6752ba5244a4490a1c1fcb9faef450b5ae4e8f6245c2 |
| server_requests.jsonl | 800b28ac38b95679ce3925d64f42103e24c9fb619bb5023485e06fdfaf357559 |
| PCAP | 9f933004d4d7baf019a6b2b746c7301d59f27c530286ba9704120040caf25008 |
| CSV V4 | ba98d4968ffb3d0ef56ba010301e72a949c0fcdec9737493dd5208d0c0e90910 |

## 2. Validação cruzada

O validador conferiu plano/logs, ZIP/CRC, filtros, endpoints e marcador. Remontou
os streams para confirmar pedidos HTTP/1.0, respostas 200, tamanhos, hashes,
handshakes e encerramentos TCP bidirecionais, antes de carregar os modelos.

| Verificação | Resultado r3 |
| --- | --- |
| Origem / destino | 172.31.50.161 → 172.31.60.10:8000 |
| Downloads / conexões | 6 / 6 |
| Corpo por resposta | 2.097.152 bytes |
| Corpos totais | 12.582.912 bytes (12 MiB) |
| Pacotes | 10.098 |
| Registros truncados / TCP RST | 0 / 0 |
| Payload duplicado na remontagem | 0 bytes |
| Primeiro ao último pacote | 110,619341 s |
| Intervalo entre inícios | mínimo 18,923501 s; mediana 18,938674 s; máximo 18,977299 s |
| Marcador | server-128k-v1, confirmado no cliente e no PCAP |
| Trace do servidor | seis GETs completos, 128 blocos por GET, pausas validadas |
| Pacing observado na captura | true |

Os seis corpos têm hash sintético esperado
`21ad43464ff341f863b1149c5a11d95fb8a325bb44ad51ed4afc17979ad44245`.
O hash declarado do helper do servidor coincide com o código conhecido:
`1f1f3deaad867c97361bb9af70000d6758026ecf5f74c1eb05846b7cff50123a`.
Além dos logs, o PCAP demonstra o comportamento temporal relevante. Cada conexão
passou o piso predefinido de 12 s de intervalo do payload. Esse piso é critério
do ensaio, não métrica de detecção. Não se pressupôs sincronização do relógio
monotônico dos logs com timestamps absolutos. Contador de drops não fornecido:
não afirmar zero perdas ou observação de todo o tráfego das VMs.

## 3. Comparação temporal entre sessões

| Medida | r1 | r2 | r3 |
| --- | ---: | ---: | ---: |
| Pacotes | 10.116 | 10.087 | 10.098 |
| Conexão TCP completa, mediana | 15,899808 s | 15,898840 s | 15,8993945 s |
| Intervalo do payload do servidor, mediana | 15,8968775 s | 15,896014 s | 15,896079 s |
| Segmento V4 com payload, mediana | 15,8992575 s | 15,8983785 s | 15,8989245 s |
| Segmento V4 sem payload, mediana | 0,2285 ms | 0,1755 ms | 0,2115 ms |

Em r3, o intervalo do payload variou de 15,895143 a 15,896707 s nas seis conexões.
O envio distribuído temporalmente foi reproduzido nas três sessões, sem inferir
isso apenas do tempo do cliente. Não significa taxa perfeitamente uniforme em
qualquer janela: há blocos e pausas programadas. As três sessões são pequenas,
correlacionadas e realizadas no mesmo ambiente; não demonstram generalização
para uma rede corporativa ou independência entre os segmentos.

## 4. Extração V4 e decisões congeladas

Reutilizou-se a imagem existente do commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, em container sem rede e PCAP somente
leitura. O acesso ao Docker na sandbox foi negado; a execução autorizada fora
dela concluiu sem build, instalação ou alteração de configuração do daemon.

Foram gerados 12 registros (13 linhas contando o cabeçalho), seis com payload e
seis sem payload. Somam os 10.098 pacotes e 12.585.144 bytes de payload TCP,
incluindo pedidos/cabeçalhos HTTP. As 60 features passaram em ordem, tipos e
finitude, schema
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Não se removeram/uniram segmentos ou preencheram valores; flags não foram
convertidas para 0/1 e Label não foi usado. Aprovação estrutural não estabelece
equivalência semântica com o extrator histórico do CIC-IDS2017.

Ponto operacional `validation_fpr_operational`, regra score >= limiar.
IF: 0,615824439899627. LOF: 91,08685969933371.

| Grupo | Segmentos por sessão | IF r1 / r2 / r3 | LOF r1 / r2 / r3 |
| --- | ---: | --- | --- |
| Com payload | 6 | 6 / 6 / 6 | 6 / 6 / 6 |
| Sem payload | 6 | 0 / 0 / 0 | 6 / 6 / 6 |
| Total | 12 | 6 / 6 / 6 | 12 / 12 / 12 |

Na decisão nativa também foram seis no IF e 12 no LOF em r3. As contagens
operacionais repetiram, embora os scores tenham variado:

| Mediana do score | r1 | r2 | r3 |
| --- | ---: | ---: | ---: |
| IF com payload | 0,624156 | 0,624006 | 0,624156 |
| IF sem payload | 0,358405 | 0,359270 | 0,358200 |
| LOF com payload | 805,961250 | 804,054721 | 805,008351 |
| LOF sem payload | 158,723358 | 146,794390 | 124,283984 |

Scores não são probabilidades, nem têm escala comparável entre modelos. As
taxas de sinalização deste ensaio não são precisão, recall, F1, acurácia ou FPR
de produção. Estabilidade de contagens não resolve a divergência de features
treino/V4 nem prova eficácia. Não se isolou causalmente o efeito de uma feature.

## 5. Testes, integridade e consolidação

Conferiram os hashes dos modelos com o registro operacional, dos cinco originais,
cópias preservadas, entradas protegidas e saídas. Persistem os avisos anteriores
dos JSONs auxiliares com hashes históricos divergentes, que não são usados na
inferência. O runtime também avisou sobre a localização do Python e consulta
WMIC de núcleos físicos; houve fallback para núcleos lógicos e exit code 0.

Passaram 50 testes selecionados: os 39 anteriores de consolidador, diagnóstico,
adaptador, auditoria e validação HTTP, mais 11 do LAB06, sem repetir o teste de
socket HTTP real de loopback. Não houve mudança de código para processar r3,
treino, calibração, banco ou alteração de rede/firewall/VM pelo processamento.

Evidências em `data/lab/lab06_serverpaced/r3/`, pastas `input/`, `client_logs/`,
`server_logs/`, `extracted/`, `inference/` e `capture_validation.json`.
Novo snapshot `reports/lab/lab_capture_summary_through_lab06_r3.json`, com dez
sessões, 124 conexões e 248 segmentos incluindo LAB02. LAB06 sozinho tem três
sessões, 18 downloads e 36 segmentos. Os snapshots anteriores foram preservados.
Não agregar cenários heterogêneos em uma métrica única de qualidade.

Reprodução do consolidado na raiz, com arquivo de saída novo:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --include-run lab04_medium_r2=data/lab/lab04_medium/r2/inference --include-run lab05_slow_r2=data/lab/lab05_slow/r2/inference --include-run lab06_serverpaced_r2=data/lab/lab06_serverpaced/r2/inference --include-run lab06_serverpaced_r3=data/lab/lab06_serverpaced/r3/inference --output reports/lab/lab_capture_summary_through_lab06_r3_recheck.json
```

## 6. Próxima coleta: LAB05/r3

Manter a ordem inversa prevista: LAB06 → LAB05 → LAB04 → LAB03. Após guardar os
logs r3 do LAB06, encerrar seu servidor temporário de exportação com Ctrl+C.
Voltar ao servidor comum, não ao helper de pacing:

```bash
python3 -m http.server 8000 --bind 172.31.60.10 --directory /lab-http
```

Antes de capturar, conferir por HEAD o arquivo `/benign-v1/large_2m.bin`: HTTP
200 e Content-Length 2097152. Nesse cenário não se exige marcador LAB06.
Criar novo job `lab05_slow_r3`, com hn2, IPv4/TCP, host Windows, porta 8000,
snaplen 65535 e teto 50000. Somente após iniciar a captura:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab05_slow -Repetition 3 -CaptureStarted
```

Esperar seis downloads, aguardar cinco segundos, parar/baixar a captura e enviar
ZIP, `run_manifest.json` e `requests.jsonl` dessa sessão. Não enviar os logs de
servidor do LAB06 como se fossem LAB05. As outras sessões r3 ainda não foram
executadas por este processamento.
