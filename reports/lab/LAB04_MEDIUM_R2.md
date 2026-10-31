# LAB04 médio / repetição 2 — validação, inferência e comparação

Estado: captura validada e inferência exploratória V4 concluída, sem alteração
dos modelos ou limiares. O cliente registrou a sessão em 26/10/2026 UTC, que
corresponde a 25/10/2026 no horário de Brasília.

## 1. Evidências preservadas

Os arquivos recebidos identificam `lab04_medium`, repetição 2, status completed,
12 tentativas concluídas e reconhecimento de captura iniciada. O ZIP e os logs
foram copiados, sem modificar os originais em Downloads, para uma pasta nova:
`data/lab/lab04_medium/r2/`. Nada foi sobrescrito em r1. O conteúdo dos anexos
foi tratado como dado, não como instrução ou código executável.

| Arquivo | SHA-256 |
| --- | --- |
| df80c68c-553a-494e-98b9-f538314825f3.zip | 0f7ed5c981322dcf96900f3756422848e9df0430b4342c51d42474459befbc38 |
| run_manifest.json do cliente | 2f69aef4dcf9d22d078a718a251bbcaadc75671ae06fb267375c252d0ffd8b34 |
| requests.jsonl do cliente | e2ce86f90b350a861d5ac33b14bbd71260b30ec28c0b064f9a6eb59ef9549432 |
| PCAP | 5ed5c8e742cbd251705c1d5c567ba4e8baf7a110cf945a3afe3adf6c54ae563d |
| CSV V4 | a0e64d205bc69e4ad4ad549bd7e595b5a38d4998c9e12a0714483f672ce80eee |

## 2. Validação independente dos downloads

O validador existente conferiu ZIP/CRC, configuração da captura, plano do cliente,
endpoints e numeração dos logs. Remontou os streams TCP para confirmar pedidos,
respostas, tamanho e hash dos corpos. Isso antecedeu o carregamento dos modelos.

| Verificação | Resultado |
| --- | --- |
| Origem / destino | 172.31.50.161 → 172.31.60.10:8000 |
| Downloads e conexões TCP | 12 / 12 |
| Respostas | 12 × HTTP 200 |
| Corpo por resposta | 262.144 bytes (256 KiB) |
| Soma dos corpos HTTP | 3.145.728 bytes (3 MiB) |
| Pacotes | 2.459 |
| Registros de pacote truncados / TCP RST | 0 / 0 |
| Bytes duplicados de payload na remontagem | 0 |
| Handshake e encerramento bidirecional | Confirmados nas 12 conexões |
| Primeiro ao último pacote | 33,720489 s |
| Intervalo entre inícios de conexões | mínimo 3,039237 s; mediana 3,057364 s; máximo 3,101531 s |
| Contador de drops fornecido | Não |

Os 12 corpos coincidem com o payload sintético original, SHA-256
`c8c95472f06e76d11771f52fe3fdefcbc535340dfe3cd8dcfad010546eee633c`.
Não se afirma zero drops: o contador não foi enviado. A remontagem completa
sustenta a completude HTTP deste ensaio filtrado, não a de todo o tráfego da rede.

## 3. Extração V4 e contrato das features

Foi utilizada a imagem existente V4, commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, sem build ou instalação. A primeira
chamada ao Docker foi bloqueada por permissão no pipe da sandbox; a chamada
autorizada fora dela concluiu. O container executou sem rede e com PCAP somente
para leitura, gravando exclusivamente a saída separada do experimento.

Foram gerados 24 registros (25 linhas se contado o cabeçalho): 12 segmentos
com payload e 12 sem payload. A soma é de 2.459 pacotes e 3.149.448 bytes de
payload TCP. Pedidos e cabeçalhos HTTP explicam a diferença em relação aos
3.145.728 bytes dos corpos, não um download adicional.

Passaram ordem, tipos e finitude das 60 features. Schema canônico:
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Não houve remoção de linhas, união de segmentos, preenchimento de valores,
clipping de flags ou uso de Label. Compatibilidade estrutural não comprova
equivalência dos cálculos V4 com os do extrator histórico do CIC-IDS2017.

## 4. Comparação das decisões operacionais

Mesma regra `anomaly_score >= threshold`, ponto `validation_fpr_operational`:
IF com limiar 0,615824439899627; LOF com limiar 91,08685969933371.

| Grupo | Segmentos por repetição | IF r1 | IF r2 | LOF r1 | LOF r2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Com payload | 12 | 0 | 0 | 12 | 12 |
| Sem payload | 12 | 0 | 0 | 12 | 12 |
| Total | 24 | 0 | 0 | 24 | 24 |

As contagens repetiram o resultado anterior: taxa operacional de sinalização
0% para IF e 100% para LOF. Isso é estabilidade das contagens neste cenário,
não prova de eficácia nem de equivalência das features. O tráfego foi planejado
como benigno, mas não foram calculados precisão, recall, F1 ou FPR de produção.

No ponto nativo, o IF sinalizou os 12 segmentos com payload e o LOF os 24.
Esse resultado também se repetiu, mas não substitui a decisão operacional.

| Score mediano, por modelo e grupo | r1 | r2 |
| --- | ---: | ---: |
| IF / com payload | 0,576574 | 0,571512 |
| IF / sem payload | 0,361636 | 0,361836 |
| LOF / com payload | 104,494309 | 121,772153 |
| LOF / sem payload | 2.099,628203 | 2.303,420162 |

O maior score IF de r2 foi 0,577287571782268, ainda abaixo do limiar operacional.
O menor score LOF foi 93,00495626037866, ainda acima do respectivo limiar.
Scores não são probabilidades; não comparar suas escalas entre os dois modelos.

## 5. Variações observadas

| Medida | r1 | r2 |
| --- | ---: | ---: |
| Pacotes | 2.474 | 2.459 |
| Mediana ACK dos segmentos com payload | 198 | 196 |
| Mediana PSH dos segmentos com payload | 13 | 13 |
| Mediana SYN dos segmentos com payload | 2 | 2 |
| Mediana da duração V4 com payload | 3,2725 ms | 4,819 ms |
| Mediana da duração V4 sem payload | 22,972 ms | 30,9775 ms |
| Mediana da duração TCP completa | 26,547 ms | 38,539 ms |
| Mediana do intervalo de payload do servidor no PCAP | 1,9085 ms | 2,255 ms |

Mesma contagem de alertas não significa scores ou tráfego idênticos. A duração
TCP completa, a duração do segmento V4 e o intervalo entre pacotes com payload
são medidas diferentes. Em r2 o envio do payload continuou concentrado em
milissegundos; este cenário não demonstrou envio sustentado apenas por usar
arquivo de 256 KiB ou limite de taxa no cliente.

Não houve experimento que isolasse a causa da variação dos scores. Duas sessões
pequenas, HTTP sintético e segmentos correlacionados não estimam desempenho em
produção. Mantém-se a ressalva histórica/V4 das flags documentada no diagnóstico
das 60 features. Não ajustar o limiar em função destes resultados locais.

## 6. Integridade, testes e reprodução

Os hashes dos modelos conferem com o registro operacional, antes e depois da
inferência. Fontes em Downloads, cópias preservadas, arquivos protegidos e saídas
foram reconferidos. Os resultados anteriores foram mantidos; modelos, manifestos,
limiares, rede e VMs não foram alterados. Não houve acesso ao MongoDB.

Persistem os avisos dos JSONs auxiliares de metadados com hashes históricos
divergentes: não foram corrigidos ou usados para predizer. Também ocorreram
os avisos já conhecidos de localização do Python e consulta de núcleos físicos
via WMIC; houve fallback para núcleos lógicos e a inferência terminou com exit 0.

Passaram os mesmos 39 testes selecionados de inclusão de sessões, diagnóstico,
adaptador, auditoria e validação HTTP. Nenhuma mudança no código de inferência
ou validação foi necessária para processar esta sessão.

Evidências em `data/lab/lab04_medium/r2/`: `capture_validation.json`, `input/`,
`client_logs/`, `extracted/` e `inference/`. O novo consolidado tem sete sessões:
`reports/lab/lab_capture_summary_through_lab04_r2.json`.

Para reproduzir a consolidação na raiz, usando um arquivo novo:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --include-run lab04_medium_r2=data/lab/lab04_medium/r2/inference --output reports/lab/lab_capture_summary_through_lab04_r2_recheck.json
.\.venv\Scripts\python.exe -B -m unittest tests.test_lab_summary_runs tests.test_lab_feature_diagnostics tests.test_lab_v4_adapter tests.test_lab_flow_audit tests.test_benign_capture_validation -q
```

## 7. Próxima coleta: LAB05/r2

Manter o servidor comum no Kali servindo `/lab-http`. Conferir por HEAD o arquivo
`/benign-v1/large_2m.bin` antes da captura: HTTP 200, Content-Length 2097152.
Criar novo job `lab05_slow_r2` com hn2/KALI, IPv4, TCP, host 172.31.50.161,
porta 8000, snaplen 65535, Count 50000. Não reiniciar os jobs anteriores.

Após iniciar o job, no Windows-LAB:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab05_slow -Repetition 2 -CaptureStarted
```

São seis downloads de 2 MiB, limite planejado de 128K no cliente e pausas de
três segundos. Os tempos reais serão verificados posteriormente em logs/PCAP.
Não usar ainda o servidor especial do LAB06. Ao concluir, esperar cinco segundos,
parar/baixar a captura e separar ZIP, manifesto e JSONL novos para envio.
