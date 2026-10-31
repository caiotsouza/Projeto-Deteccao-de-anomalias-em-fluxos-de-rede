# LAB05 / repetição 3 — validação e comparação das três sessões

Estado: seis downloads completos, captura validada, extração V4 e inferência
exploratória concluídas. Sessão em 26/10/2026 UTC, correspondente a 25/10/2026
em Brasília. Mantidos os modelos, limiares e resultados anteriores. Foi
registrada uma pausa maior entre pedidos; a sessão não foi descartada.

## 1. Evidências e integridade

Os anexos foram tratados como dados, não como instruções. O manifesto identifica
`lab05_slow`, repetição 3, status completed, seis tentativas bem-sucedidas,
limite planejado 128K no cliente e pausas nominais de três segundos. Os originais
em Downloads não foram modificados; cópias idênticas foram preservadas em uma
pasta nova `data/lab/lab05_slow/r3/`, separada de r1/r2.

| Evidência | SHA-256 |
| --- | --- |
| ZIP 2a2c43e4-35c8-4b41-94d6-4ea1230a9517.zip | 45ab0a5802073e13c2e501f22e888e9d558bcf593d04e774d17147472e579d03 |
| run_manifest.json do cliente | 03f12187cc5e4f81ecfe65cd9ea4ada8448b8663abe0fd49f9d92ce511ca4bb2 |
| requests.jsonl do cliente | 4cb196156985aba1aec00ebb07dcf00b9ff3a74443de028777336c710bc0c4a9 |
| PCAP | 8ccd35ed25f1b4bbb49ec4b5e70f92c54cac71b165bbda6126b635541da1cd78 |
| CSV V4 | 59f1e5a2de8592121222432428da8a46c01c3f754b11de6b4bcdd3a90b455d61 |

## 2. Validação independente

O validador conferiu plano/logs, configuração da captura, ZIP/CRC, endpoints e
remontagem TCP. Foram verificados GETs HTTP/1.0, respostas 200, conteúdo e hash
dos corpos, handshakes e encerramentos bidirecionais nas seis conexões.

| Verificação | Resultado |
| --- | --- |
| Origem / destino | 172.31.50.161 → 172.31.60.10:8000 |
| Downloads / conexões | 6 / 6 |
| Corpo por resposta | 2.097.152 bytes |
| Corpos totais | 12.582.912 bytes (12 MiB) |
| Pacotes | 9.358 |
| Registros truncados / TCP RST | 0 / 0 |
| Payload duplicado na remontagem | 0 bytes |
| Primeiro ao último pacote | 155,420746 s |
| Intervalo entre inícios | mínimo 18,485533 s; mediana 18,504214 s; máximo 65,884717 s |

Todos os corpos coincidem com o hash sintético
`21ad43464ff341f863b1149c5a11d95fb8a325bb44ad51ed4afc17979ad44245`.
O contador de drops não foi fornecido. A reconstrução completa sustenta a
completude HTTP deste ensaio, não ausência de toda perda ou cobertura de todo
o tráfego das VMs.

## 3. Pausa maior entre o segundo e o terceiro pedidos

O PCAP registra o início do segundo pedido em 00:59:16,454466 UTC e o terceiro
em 01:00:22,339183 UTC, intervalo de 65,884717 s. O log do cliente também
registra aproximadamente 65,885452 s entre esses inícios, e 50,391833 s entre
a conclusão registrada do segundo pedido e o início do terceiro. Isso é maior
que a pausa nominal de três segundos.

Os tempos curl dos seis pedidos continuam entre 15,473262 e 15,498686 s; os
tempos entre início e conclusão de cada entrada do cliente ficam próximos
dessas durações. Portanto, não se deve apresentar o intervalo extra como um
download que durou 65 s. Também não foi determinada a causa da pausa entre
pedidos: não atribuir automaticamente a rede, ataque, sistema ou interação
com o terminal. A sessão foi preservada e deve carregar essa ressalva nas
comparações de duração total e ritmo, sem selecionar uma tentativa mais favorável.

## 4. Extração e decisões congeladas

Foi reutilizada a imagem V4 existente, commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, em container sem rede, PCAP somente
leitura e saída nova. A sandbox negou acesso ao pipe Docker; a execução
autorizada fora dela concluiu, sem instalação ou build.

Foram gerados 12 registros de dados (13 linhas contando o cabeçalho): seis
com payload e seis sem payload. Somam os 9.358 pacotes e 12.584.760 bytes de
payload TCP, incluindo pedidos/cabeçalhos HTTP, não somente os corpos.
Passaram ordem, tipos e finitude das 60 features, schema
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Não houve clipping, imputação, remoção/união de segmentos ou uso de Label.
Equivalência semântica com o extrator histórico continua não estabelecida.

Ponto `validation_fpr_operational`, regra score >= limiar. IF tem limiar
0,615824439899627; LOF tem limiar 91,08685969933371.

| Grupo | Segmentos por sessão | IF r1 / r2 / r3 | LOF r1 / r2 / r3 |
| --- | ---: | --- | --- |
| Com payload | 6 | 6 / 6 / 6 | 6 / 6 / 6 |
| Sem payload | 6 | 0 / 0 / 0 | 6 / 6 / 6 |
| Total | 12 | 6 / 6 / 6 | 12 / 12 / 12 |

Na decisão nativa também foram seis no IF e 12 no LOF em r3. Todas as seis
conexões possuem ao menos um segmento sinalizado pelos dois modelos.

| Mediana do score | r1 | r2 | r3 |
| --- | ---: | ---: | ---: |
| IF com payload | 0,647576 | 0,651580 | 0,653321 |
| IF sem payload | 0,422594 | 0,420557 | 0,421091 |
| LOF com payload | 820,369057 | 790,336270 | 761,194331 |
| LOF sem payload | 1.757,612486 | 1.146,064394 | 1.380,689767 |

Mesmas contagens não significam scores ou features idênticos. Scores não são
probabilidades, e suas escalas não devem ser comparadas entre modelos. A
sinalização é exploratória, não precisão, recall, F1, acurácia ou FPR de produção.
Não se estabeleceu causalmente qual característica determina cada decisão.

## 5. Comparação temporal

| Medida, mediana | r1 | r2 | r3 |
| --- | ---: | ---: | ---: |
| Conexão TCP completa | 15,489380 s | 15,485686 s | 15,485365 s |
| Intervalo do payload do servidor | 7,2275 ms | 7,461 ms | 6,837 ms |
| Segmento V4 com payload | 8,525 ms | 8,7465 ms | 8,1245 ms |
| Segmento V4 sem payload | 15,479903 s | 15,4768945 s | 15,4766005 s |

Em r3, o intervalo de payload do servidor ficou entre 6,183 e 7,736 ms.
Portanto, nas três sessões LAB05, duração TCP longa não demonstrou envio
sustentado de payload em hn2. Isso contrasta com os cerca de 15,9 s observados
nas três sessões LAB06 com controle no servidor. São condições distintas do
ensaio; não transformar esse contraste em atribuição causal dos alertas.

LAB05 agora tem 18 downloads e 36 segmentos nas três sessões. A amostra é
pequena e correlacionada, com a mesma infraestrutura, e não representa uma
empresa. A pausa de r3 deve permanecer explícita na apresentação acadêmica.

## 6. Testes, arquivos e reprodução

Passaram 39 testes selecionados de consolidador, diagnóstico, adaptador,
auditoria e validação HTTP. Os hashes dos três originais, cópias, arquivos
protegidos e saídas foram reconferidos. Os dois joblib conferem com o registro
operacional e ficaram inalterados. Persistem os avisos anteriores dos JSONs
auxiliares de metadados divergentes, que não são usados na inferência.
O runtime avisou sobre o caminho do Python e consulta WMIC, com fallback para
núcleos lógicos e inferência concluída com exit 0.

Não houve mudança de código para obter o resultado, treino, calibração, banco
ou alteração de rede/VM/firewall. Evidências em `data/lab/lab05_slow/r3/`, com
`input/`, `client_logs/`, `extracted/`, `inference/` e `capture_validation.json`.
Novo consolidado, preservando anteriores:
`reports/lab/lab_capture_summary_through_lab05_r3.json`, com 11 sessões,
130 conexões e 260 segmentos incluindo LAB02. Não usar uma taxa agregada dos
cenários heterogêneos como métrica de qualidade.

Reprodução na raiz, com nome de saída novo:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --include-run lab04_medium_r2=data/lab/lab04_medium/r2/inference --include-run lab05_slow_r2=data/lab/lab05_slow/r2/inference --include-run lab06_serverpaced_r2=data/lab/lab06_serverpaced/r2/inference --include-run lab06_serverpaced_r3=data/lab/lab06_serverpaced/r3/inference --include-run lab05_slow_r3=data/lab/lab05_slow/r3/inference --output reports/lab/lab_capture_summary_through_lab05_r3_recheck.json
```

## 7. Próxima coleta: LAB04/r3

Manter o servidor HTTP comum servindo `/lab-http`. Antes da captura, conferir
HEAD do arquivo `/benign-v1/medium_256k.bin`: HTTP 200, Content-Length 262144.
Criar novo job `lab04_medium_r3`, hn2, IPv4/TCP, host 172.31.50.161, porta
8000, snaplen 65535 e teto 50000. Não reiniciar jobs anteriores. Após iniciar:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab04_medium -Repetition 3 -CaptureStarted
```

São 12 downloads de 256 KiB, limite planejado 512K no cliente e pausas de três
segundos. Após concluir, esperar cinco segundos, parar/baixar captura e enviar
ZIP, `run_manifest.json` e `requests.jsonl` da nova sessão.
