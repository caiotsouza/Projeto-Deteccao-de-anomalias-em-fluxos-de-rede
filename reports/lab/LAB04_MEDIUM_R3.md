# LAB04 médio / repetição 3 — validação e comparação das três sessões

Estado: captura validada, extração V4 e inferência exploratória concluídas.
Sessão em 26/10/2026 UTC (25/10/2026 em Brasília). Modelos, limiares e
resultados anteriores preservados. Há uma ressalva de disponibilidade dos
originais em Downloads na conferência final; as cópias preservadas conferem.

## 1. Evidências e rastreabilidade

O manifesto recebido identifica `lab04_medium`, repetição 3, completed, com
12 pedidos bem-sucedidos, limite planejado 512K no cliente e pausas de três
segundos. Os anexos foram tratados como dados, não como instruções. O validador
criou uma pasta nova `data/lab/lab04_medium/r3/`, copiou os três originais e
conferiu seus hashes antes/depois da importação. Não sobrescreveu r1 ou r2.

| Evidência | SHA-256 registrado na importação |
| --- | --- |
| 0621e505-fef3-4dd8-9dee-62238de1b542.zip | 5c2dc47147bcb4257818703788850e86c8d6105c983b4d67406dea7f9c0a1e83 |
| run_manifest.json do cliente | 80ac691e561c0f514649494e0d2e4d5905d23785b7acacfde698be8a6c7acde2 |
| requests.jsonl do cliente | 57ff4c1f16cafea586619ab00f3ab2a9e5971983c1481e7a42d6053561ecc2a2 |
| PCAP extraído | aef48101307e594ede75e0a5b3253faae13c7f14900c3b1f505188cdb7898a71 |
| CSV V4 | d036935c637118923bee5732b949c898e576a1a8f84ec08a25be9e899d6da45c |

Na primeira reconferência final, o ZIP já não estava no caminho original de
Downloads. Na verificação seguinte, também os dois logs originais estavam
indisponíveis. A causa dessa indisponibilidade não foi determinada. Nenhum
comando deste processamento removeu esses arquivos. Não se afirma que os
originais continuem disponíveis ou tenham sido reconferidos nesse momento.

As três cópias preservadas em `input/` e `client_logs/` foram reconferidas e
coincidem com os hashes registrados pelo importador. O processamento usou
essas cópias. O PCAP, CSV, arquivos protegidos e saídas de inferência também
conferem; a ausência posterior dos caminhos originais não invalida por si só
a cópia já preservada e verificada.

## 2. Validação independente da captura

O validador conferiu plano/logs, ZIP/CRC, configuração de captura e endpoints.
Remontou os streams TCP para verificar pedidos HTTP/1.0, respostas, corpos,
handshakes e encerramentos bidirecionais nas 12 conexões.

| Verificação | Resultado |
| --- | --- |
| Endpoints | 172.31.50.161 → 172.31.60.10:8000 |
| Downloads / respostas HTTP 200 | 12 / 12 |
| Corpo por resposta | 262.144 bytes (256 KiB) |
| Corpos totais | 3.145.728 bytes (3 MiB) |
| Conexões / pacotes | 12 / 2.482 |
| Registros truncados / TCP RST | 0 / 0 |
| Bytes duplicados de payload na remontagem | 0 |
| Primeiro ao último pacote | 33,574312 s |
| Intervalo entre inícios | mínimo 3,027668 s; mediana 3,046277 s; máximo 3,080982 s |

Os corpos coincidem com o hash sintético esperado
`c8c95472f06e76d11771f52fe3fdefcbc535340dfe3cd8dcfad010546eee633c`.
Não houve um intervalo longo como o observado no LAB05/r3. Contador de drops
não fornecido: a reconstrução completa sustenta a completude HTTP, não ausência
de toda perda ou cobertura do tráfego fora dos filtros.

## 3. Extração V4 e decisões congeladas

Reutilizou-se a imagem existente do commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`. O acesso ao Docker na sandbox foi
negado; a execução autorizada fora dela concluiu em container sem rede e PCAP
somente leitura. Não houve instalação ou build.

Foram exportados 24 registros de dados (25 linhas contando o cabeçalho),
12 com payload e 12 sem payload. Somam os 2.482 pacotes e 3.149.448 bytes de
payload TCP, incluindo pedidos/cabeçalhos HTTP, não apenas os corpos.
As 60 features passaram em tipos, ordem e finitude, schema
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Não houve clipping, imputação, remoção/união de segmentos ou uso de Label.
A equivalência semântica com o extrator histórico permanece não estabelecida.

Ponto `validation_fpr_operational`, regra score >= limiar. IF utiliza
0,615824439899627; LOF utiliza 91,08685969933371.

| Grupo | Segmentos por sessão | IF r1 / r2 / r3 | LOF r1 / r2 / r3 |
| --- | ---: | --- | --- |
| Com payload | 12 | 0 / 0 / 0 | 12 / 12 / 12 |
| Sem payload | 12 | 0 / 0 / 0 | 12 / 12 / 12 |
| Total | 24 | 0 / 0 / 0 | 24 / 24 / 24 |

Na decisão nativa, IF sinalizou os 12 segmentos com payload e LOF os 24 em r3,
também repetindo as primeiras sessões. Não substituir o resultado operacional
pelo nativo. A ausência de alerta IF não comprova capacidade de detectar
ataques futuros; alerta LOF não comprova ataque.

| Mediana do score | r1 | r2 | r3 |
| --- | ---: | ---: | ---: |
| IF com payload | 0,576574 | 0,571512 | 0,576871 |
| IF sem payload | 0,361636 | 0,361836 | 0,363503 |
| LOF com payload | 104,494309 | 121,772153 | 132,569464 |
| LOF sem payload | 2.099,628203 | 2.303,420162 | 2.568,995702 |

O maior score LOF sem payload foi 6843,405745274419 em r3; isso é diferença
descritiva de score, não probabilidade ou medida de severidade validada.
Todos os scores LOF ficaram acima do limiar, enquanto o maior score IF,
0,577287571782268, ficou abaixo do seu limiar operacional. Não se atribuiu
causalmente essa variação a uma única feature nem se recalibraram os modelos.

## 4. Tempos e limites da comparação

| Medida, mediana | r1 | r2 | r3 |
| --- | ---: | ---: | ---: |
| Pacotes por sessão (total) | 2.474 | 2.459 | 2.482 |
| Conexão TCP completa | 26,547 ms | 38,539 ms | 25,239 ms |
| Intervalo do payload do servidor | 1,9085 ms | 2,255 ms | 2,025 ms |
| Segmento V4 com payload | 3,2725 ms | 4,819 ms | 3,319 ms |
| Segmento V4 sem payload | 22,972 ms | 30,9775 ms | 22,071 ms |

A igualdade das contagens não implica tráfego, scores ou features idênticos.
LAB04 continua um cenário curto no ponto capturado, não envio sustentado
demonstrado pelo limite do cliente. As três sessões somam 36 downloads e
72 segmentos, pequenos e correlacionados, no mesmo ambiente. Não foram
calculados precisão, recall, F1, acurácia ou FPR de produção. Não agregar os
cenários heterogêneos numa métrica única de qualidade.

## 5. Testes, arquivos e reprodução

Passaram 39 testes selecionados de consolidador, diagnóstico, adaptador,
auditoria e validação HTTP. Os modelos joblib correspondem ao registro
operacional e ficaram inalterados, assim como limiares e resultados anteriores.
Persistem os avisos históricos dos JSONs auxiliares de metadados divergentes,
que não são usados para inferência. O runtime avisou sobre o caminho do Python
e consulta WMIC de núcleos físicos, com fallback para núcleos lógicos e exit 0.

Não houve mudança de código para processar esta sessão, treino, calibração,
banco, rede, firewall ou VM. Evidências em `data/lab/lab04_medium/r3/`, com
`input/`, `client_logs/`, `extracted/`, `inference/` e `capture_validation.json`.
Novo snapshot `reports/lab/lab_capture_summary_through_lab04_r3.json`, com
12 sessões, 142 conexões e 284 segmentos incluindo LAB02. Anteriores preservados.

Reprodução na raiz, com nome de saída novo:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --include-run lab04_medium_r2=data/lab/lab04_medium/r2/inference --include-run lab05_slow_r2=data/lab/lab05_slow/r2/inference --include-run lab06_serverpaced_r2=data/lab/lab06_serverpaced/r2/inference --include-run lab06_serverpaced_r3=data/lab/lab06_serverpaced/r3/inference --include-run lab05_slow_r3=data/lab/lab05_slow/r3/inference --include-run lab04_medium_r3=data/lab/lab04_medium/r3/inference --output reports/lab/lab_capture_summary_through_lab04_r3_recheck.json
```

## 6. Última coleta da matriz: LAB03/r3

Manter o servidor HTTP comum servindo `/lab-http`. Antes da captura, conferir
HEAD de `/benign-v1/small_16k.bin`: HTTP 200 e Content-Length 16384. Criar job
novo `lab03_small_r3`, hn2, IPv4/TCP, host 172.31.50.161, porta 8000,
snaplen 65535, teto 50000. Somente após iniciar:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab03_small -Repetition 3 -CaptureStarted
```

São 30 downloads de 16 KiB, limite planejado 512K no cliente e pausas de dois
segundos. Após concluir, esperar cinco segundos, parar/baixar captura e enviar
ZIP, `run_manifest.json` e `requests.jsonl` da nova sessão. Não reiniciar os
jobs anteriores. LAB03/r3 ainda não foi coletado por este processamento.
