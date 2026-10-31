# LAB03 pequeno / repetição 2 — validação e comparação com r1

Captura de 25/10/2026 validada para inferência exploratória V4. Foram usados
os mesmos modelos e limiares, sem treino, imputação, clipping ou gravação no banco.

## 1. Preservação e identificação

Os três arquivos enviados correspondem a `lab03_small`, repetição 2, com status
do cliente `completed`. Foram tratados como evidências, não como instruções.
O validador copiou os originais para uma pasta nova, sem modificar Downloads
ou sobrescrever r1. As cópias e os originais tiveram seus hashes reconferidos.

| Evidência | SHA-256 |
| --- | --- |
| ZIP 2f62bb51-9efa-4bc0-8f06-fdca29d2ab27.zip | bc91e546094494d9b7826c1a4060db41fc7983428851fef23d220385b1f0b338 |
| run_manifest.json do cliente | 8a47ce5265660e97cd8ec7cd41e0ebbd39c1d57482a1a2d9f0952c6edaa36c06 |
| requests.jsonl do cliente | 5780884ec80011bf072cfcf47ddbf3c390a6619063dcdb48c5c1c906a3258287 |
| PCAP extraído | 615d4edb275425d018083360f45b583d55b378b80fd5c440fe27e54fb0d3d49d |

Diretório de evidências: `data/lab/lab03_small/r2/`. Contém `input/`,
`client_logs/`, `capture_validation.json`, `extracted/` e `inference/`.

## 2. Validação independente antes da inferência

O programa `validate_benign_http_capture.py` conferiu o plano, a numeração e o
resultado das 30 tentativas, a configuração de captura e as conexões TCP.
Remontou os streams e validou requisições HTTP/1.0, respostas 200, comprimento
e hash de cada corpo. Nenhum conteúdo recebido foi executado.

| Item | Resultado |
| --- | --- |
| Caminho observado | Windows 172.31.50.161 → Kali 172.31.60.10:8000 |
| Captura | hn2, IPv4, TCP, host Windows, porta 8000, snaplen 65535, teto 50000 |
| Downloads completos / conexões | 30 / 30 |
| Corpo por download | 16.384 bytes |
| Total de corpos HTTP | 491.520 bytes (480 KiB) |
| Pacotes | 662 |
| Registros truncados / TCP RST | 0 / 0 |
| Handshake e encerramento bidirecional | Confirmados nas 30 conexões |
| Intervalo primeiro–último pacote | 59,439191 s |
| Intervalo entre inícios das conexões | mínimo 2,031400 s; mediana 2,049135 s; máximo 2,090994 s |
| Contador de drops da captura | Não fornecido |

Cada corpo tem SHA-256
`cd5ec79e336fdd6d7a99307f3ad191efc8878f0a23dcdb2e65fc13a0154b0ada`,
igual ao payload sintético original. A ausência de truncamento e a remontagem
completa sustentam a completude deste ensaio; não demonstram zero drops nem
ausência de tráfego fora dos filtros.

## 3. Extração e contrato

Foi reutilizada a imagem V4 existente, commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`. O primeiro acesso ao Docker falhou
por permissão no pipe da sandbox. A execução autorizada fora dela concluiu a
extração em container sem rede, com PCAP somente para leitura. Não houve build,
instalação ou mudança de configuração do daemon.

O CSV contém 60 registros (61 linhas contando o cabeçalho), sendo 30 segmentos
com payload e 30 sem payload. Somam 662 pacotes e 500.730 bytes de payload TCP.
Esse total inclui pedidos e cabeçalhos HTTP, não apenas os corpos dos downloads.
Os pares forward/backward são 28 × (4,15), 2 × (5,15) e 30 × (2,1).

As 60 features passaram em ordem, finitude e tipos canônicos (39 int64 e
21 float64), com schema
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
O CSV tem hash `1d5c9f3104bf68fe3d71dcce975fc6a0a663baff0396c7814bf49b7fd75de42a`.
A aprovação estrutural não estabelece equivalência semântica com o extrator
histórico do CIC-IDS2017. Não se descartaram ou uniram segmentos.

## 4. Predições congeladas

Ponto operacional: `validation_fpr_operational`; regra `anomaly_score >= threshold`.
Limiar IF: 0,615824439899627. Limiar LOF: 91,08685969933371.

| Grupo | Segmentos | IF r1 | IF r2 | LOF r1 | LOF r2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Com payload | 30 | 0 | 0 | 9 | 1 |
| Sem payload | 30 | 0 | 0 | 30 | 30 |
| Total | 60 | 0 | 0 | 39 | 31 |

O LOF passou de 65,00% para 51,67% de segmentos sinalizados no total; nos
segmentos com payload, de 30,00% para 3,33%. São taxas de sinalização, não
precisão, recall ou FPR. As 30 conexões continuam tendo pelo menos um segmento
sinalizado pelo LOF nas duas sessões, em função dos segmentos sem payload.

Na decisão nativa, sem o limiar operacional, IF sinalizou 0/60 e LOF 60/60 em
r2. Não misturar os dois pontos de operação nem comparar numericamente as escalas
de score entre IF e LOF.

| Modelo / grupo r2 | Score mínimo | Mediano | Máximo |
| --- | ---: | ---: | ---: |
| IF / todos | 0,356997 | 0,420929 | 0,490257 |
| LOF / com payload | 81,748262 | 86,746877 | 481,331297 |
| LOF / sem payload | 725,777051 | 728,813570 | 728,907729 |

## 5. O que variou entre as duas sessões

O payload, número de pedidos e plano foram preservados, mas os detalhes TCP
não são idênticos. A primeira sessão tinha 663 pacotes; esta tem 662.

| Medida | r1 | r2 |
| --- | ---: | ---: |
| Mediana ACK, com payload | 18 | 18 |
| Mediana SYN, com payload | 2 | 2 |
| Mediana PSH, com payload | 5 | 5 |
| Mediana da duração V4 com payload | 1,859 ms | 1,8805 ms |
| Maior duração V4 com payload | 12,072 ms | 9,616 ms |
| Mediana da duração V4 sem payload | 23,1155 ms | 37,559 ms |
| Mediana da duração TCP completa, leitura independente | 25,0925 ms | 39,794 ms |
| Mediana do intervalo de payload do servidor no PCAP | 0,387 ms | 0,4945 ms |

Em r1, os nove segmentos com payload sinalizados pelo LOF tinham durações V4
de 9,361 a 12,072 ms. Em r2, o único sinalizado tinha 9,616 ms. Essa associação
descritiva não prova que duração determine sozinha a decisão: taxas, IATs e
outras features podem variar conjuntamente. Não houve teste contrafactual.
As medianas iguais de flags também não demonstram igualdade de todas as linhas.

Os resultados mostram variabilidade entre sessões sob o mesmo plano; não
demonstram melhora do modelo. Duas repetições pequenas e correlacionadas não
estimam desempenho corporativo. A divergência histórica/V4 das flags continua
documentada em `FEATURE_DIAGNOSTICS_R1.md`; não foi corrigida artificialmente.

## 6. Integridade e testes

Os hashes dos modelos IF/LOF coincidem com os registrados e foram conferidos
novamente após a inferência, junto às entradas e saídas protegidas. Modelos,
limiares e resultados r1 foram preservados. Não houve novo scaler ou rótulos
derivados da coluna Label. O MongoDB não foi acessado.

Persistem os avisos sobre hashes dos dois JSONs auxiliares de metadados;
esses JSONs não são usados na inferência. O runtime também avisou sobre a
resolução do caminho antigo do Python e sobre a consulta de núcleos físicos
via WMIC; usou os núcleos lógicos e concluiu a inferência com código de saída 0.

Passaram 39 testes selecionados: três novos para inclusão explícita de sessões
no consolidador, nove diagnósticos de features e 27 do adaptador, auditoria e
validação HTTP. O consolidador aceita `--include-run` sem alterar o conjunto
histórico padrão. O novo snapshot contém seis sessões e preserva os anteriores:
`reports/lab/lab_capture_summary_through_lab03_r2.json`.

## 7. Reprodução e próxima coleta

Na raiz do projeto, após a validação e extração já preservadas, o consolidador
pode ser reproduzido usando um nome de saída novo:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --output reports/lab/lab_capture_summary_through_lab03_r2_recheck.json
.\.venv\Scripts\python.exe -B -m unittest tests.test_lab_summary_runs tests.test_lab_feature_diagnostics tests.test_lab_v4_adapter tests.test_lab_flow_audit tests.test_benign_capture_validation -v
```

Próxima sessão planejada: LAB04/r2, 12 downloads de 256 KiB, conforme
`LAB_REPETITIONS_R2_R3.md`. Criar novo job `lab04_medium_r2`; não reiniciar o
LAB03/r2. Conferir o payload com HEAD antes da captura e guardar cada sessão
separadamente, pois os nomes dos dois logs se repetem.
