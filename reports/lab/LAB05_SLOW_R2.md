# LAB05 / repetição 2 — transferência limitada no cliente

Captura validada, extração V4 e inferência exploratória concluídas. Modelos e
limiares congelados; resultados anteriores preservados. Sessão em 26/10/2026
UTC, correspondente a 25/10/2026 no horário de Brasília.

## 1. Evidências e validação

Recebidos `1ae34db6-7028-42b2-8626-5667c83263a7.zip`, `run_manifest.json` e
`requests.jsonl`. O manifesto identifica `lab05_slow`, repetição 2, seis pedidos
concluídos, teto planejado de 128K no cliente e pausas de três segundos.
Os anexos foram tratados como dados, não como instruções. Os originais em
Downloads não foram modificados; cópias foram preservadas em uma pasta nova:
`data/lab/lab05_slow/r2/`, separada de r1 e dos demais cenários.

| Evidência | SHA-256 |
| --- | --- |
| ZIP | 66c4f543b423e3bfb84383cb6a822f911126a824c6530e186ed3b108785e14b6 |
| Manifesto do cliente | 3ea7983416b9a90ff5d024af88885ed37bd1a25648c68416209a790e08e9b9ca |
| JSONL do cliente | 2e7a6c621b6d224cc7eb9210d8a031e1ebb714f9d6940d1cda8172b31a0d5ec5 |
| PCAP | 64443124e4f5e87e4aa648570c5a3865808d8774f1be7ca99b9afd663ca14df3 |
| CSV V4 | 2d5c101c1469299e9800204d8ae487537b9db4ef21b6b060f85f913e201a9bcf |

O validador conferiu o ZIP/CRC, configuração da captura e plano/logs do cliente.
Reconstruiu os streams TCP para verificar GETs HTTP/1.0, respostas, corpos e
encerramentos. Cada corpo coincide com o arquivo sintético preparado:
`21ad43464ff341f863b1149c5a11d95fb8a325bb44ad51ed4afc17979ad44245`.

| Verificação | Resultado |
| --- | --- |
| Endpoints | 172.31.50.161 → 172.31.60.10:8000 |
| Downloads / respostas HTTP 200 | 6 / 6 |
| Corpo por resposta | 2.097.152 bytes (2 MiB) |
| Corpos totais | 12.582.912 bytes (12 MiB) |
| Conexões TCP / pacotes | 6 / 9.422 |
| Registros truncados / TCP RST | 0 / 0 |
| Bytes duplicados de payload na remontagem | 0 |
| Handshake e encerramento bidirecional | Confirmados nas seis conexões |
| Primeiro ao último pacote | 107,930490 s |
| Intervalos entre inícios | mínimo 18,419993 s; mediana 18,500987 s; máximo 18,530778 s |

Não foi fornecido contador de drops; não se afirma zero perdas. O conteúdo HTTP
foi reconstruído integralmente, mas a captura é filtrada, não uma observação de
todo o tráfego das VMs.

## 2. Extração e inferência

Reutilizou-se a imagem existente V4, commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, sem rede e com PCAP somente para
leitura. Acesso inicial ao Docker falhou por permissão no pipe da sandbox;
a execução autorizada fora dela concluiu, sem build ou instalação.

Foram gerados 12 registros de dados (13 linhas contando o cabeçalho): seis com
payload e seis sem payload. Contabilizam os 9.422 pacotes e 12.584.760 bytes
de payload TCP. O total TCP inclui pedidos/cabeçalhos HTTP e não deve ser
confundido com a soma dos corpos dos downloads.

As 60 features passaram em ordem, finitude e tipos, com schema
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Não houve clipping de flags, imputação, remoção ou união de segmentos nem uso
da coluna Label. Equivalência semântica com o extrator histórico continua não
estabelecida: aprovação estrutural não a substitui.

Ponto `validation_fpr_operational`, regra `anomaly_score >= threshold`:
IF = 0,615824439899627; LOF = 91,08685969933371.

| Grupo | Segmentos por repetição | IF r1 | IF r2 | LOF r1 | LOF r2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Com payload | 6 | 6 | 6 | 6 | 6 |
| Sem payload | 6 | 0 | 0 | 6 | 6 |
| Total | 12 | 6 | 6 | 12 | 12 |

As contagens repetiram r1: IF 50% e LOF 100% de segmentos sinalizados.
Na decisão nativa também foram seis no IF e 12 no LOF. Todas as seis conexões
têm ao menos um segmento sinalizado em ambos os modelos, sem converter esses
grupos em novos rótulos de referência.

Em r2, os scores IF dos segmentos com dados variaram de 0,6477318544634808 a
0,6543431633244603, mediana 0,6515802132600643. Os sem dados tiveram mediana
0,4205574514123074 e ficaram abaixo do limiar. No LOF, as medianas foram
790,3362701258967 com dados e 1146,0643939322097 sem dados, ambas acima do limiar.
Scores não são probabilidades e as escalas não são comparáveis entre modelos.

## 3. Resultado temporal que se repetiu

| Medida (mediana) | r1 | r2 |
| --- | ---: | ---: |
| Conexão TCP completa | 15,489380 s | 15,485686 s |
| Intervalo entre primeiro/último pacote com payload do servidor | 7,2275 ms | 7,461 ms |
| Segmento V4 com payload | 8,525 ms | 8,7465 ms |
| Segmento V4 sem payload | 15,479903 s | 15,4768945 s |
| ACK, segmentos com payload | 1.518,5 | 1.542 |
| PSH, segmentos com payload | 47 | 46,5 |
| SYN, segmentos com payload | 2 | 2 |

Em r2, o intervalo do payload no PCAP variou de 6,116 a 10,141 ms, enquanto as
conexões TCP completas duraram de 15,398487 a 15,494830 s. O envio observado em
hn2 continuou concentrado em milissegundos; a maior parte da duração ficou nos
segmentos posteriores sem payload. Limitar o cliente não demonstrou envio
sustentado de dados no ponto capturado. Não se isolou a causa desse comportamento.

Mesmo com as mesmas contagens de alertas, houve variação em pacotes e features.
Não atribuir causalmente os alertas a duração, tamanho ou flags sem investigação
adicional. A amostra é pequena e correlacionada, restrita a HTTP sintético entre
dois endpoints; não se calcularam precisão, recall, F1, acurácia ou FPR de produção.

## 4. Integridade, testes e reprodução

Foram reconferidos os hashes dos originais, cópias, entradas protegidas e saídas.
Os dois joblib conferem com o registro operacional e ficaram inalterados.
Persistem os avisos anteriores dos JSONs auxiliares de metadados com hashes
divergentes, que não são usados para inferência. O runtime avisou sobre o caminho
do Python e consulta WMIC de núcleos físicos, usando núcleos lógicos e concluindo
com código de saída 0. Nenhum desses avisos foi ocultado por mudança do modelo.

Passaram 39 testes selecionados do consolidador, diagnóstico, adaptador,
auditoria e validação HTTP. Nenhuma alteração no código foi necessária para
processar r2. Não houve gravação no banco, treino, calibração ou alteração de VM,
firewall ou rede.

Evidências em `data/lab/lab05_slow/r2/`: `capture_validation.json`, `input/`,
`client_logs/`, `extracted/` e `inference/`. O novo consolidado preserva os
anteriores e contém oito sessões:
`reports/lab/lab_capture_summary_through_lab05_r2.json`.

Para reproduzir a consolidação, usar um nome de saída novo na raiz do projeto:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --include-run lab04_medium_r2=data/lab/lab04_medium/r2/inference --include-run lab05_slow_r2=data/lab/lab05_slow/r2/inference --output reports/lab/lab_capture_summary_through_lab05_r2_recheck.json
.\.venv\Scripts\python.exe -B -m unittest tests.test_lab_summary_runs tests.test_lab_feature_diagnostics tests.test_lab_v4_adapter tests.test_lab_flow_audit tests.test_benign_capture_validation -q
```

## 5. Próxima coleta: LAB06/r2, controle no servidor

Seguir `LAB_REPETITIONS_R2_R3.md`, seção 6, e `LAB06_SERVER_PACING.md`.
Parar o servidor comum após terminar esta captura. Usar o helper LAB06 já
transferido, com uma pasta de logs nova `/tmp/lab06-r2`. Não reutilizar ou apagar
os logs de r1. Conferir HEAD e marcador `X-TCC-Pacing: server-128k-v1` antes
da captura. Criar novo job `lab06_serverpaced_r2`, mesmos filtros e snaplen.

Executar o cliente dedicado `C:\TCC\run_lab06_http.ps1 -Repetition 2
-CaptureStarted`, não o helper LAB05. Após seis downloads, esperar cinco segundos,
parar/baixar a captura e encerrar o servidor com Ctrl+C para finalizar seu
manifesto. Exportar os logs do servidor somente depois, fora da captura.

Enviar cinco arquivos: ZIP, `run_manifest.json`, `requests.jsonl`,
`server_manifest.json` e `server_requests.jsonl`. Essa coleta não foi iniciada
automaticamente; a observação do envio sustentado ainda precisa ser confirmada
em logs e PCAP de r2, sem presumir os tempos a partir do nome do cenário.
