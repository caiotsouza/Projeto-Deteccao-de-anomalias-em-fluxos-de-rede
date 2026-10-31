# LAB04 medio / repeticao 1 — validacao e inferencia

Data: 25/10/2026. Estado: captura validada, extracao V4 e inferencia exploratoria
concluidas. Mesmos modelos e limiares de LAB02/LAB03; sem recalibracao.

## 1. Evidencias e validacao

Recebidos: `63a3484e-e5f1-468c-b64e-b27e6a54b4c5.zip`, `run_manifest (1).json`
e `requests (1).jsonl`. Foram preservados em `data/lab/lab04_medium/r1/`, com
nomes padronizados apenas nas copias dos logs. Os bytes foram conservados.

- ZIP SHA-256: `886ec974ca64009d95dd110f898d2f310f0ef777807fd84c665aa65776fe9cff`.
- PCAP SHA-256: `8fa12eb047dd655e95943732c6aac33f858e022441ee5556529b544e9563b049`.
- Corpo SHA-256: `c8c95472f06e76d11771f52fe3fdefcbc535340dfe3cd8dcfad010546eee633c`.

O validador existente conferiu ZIP/CRC, filtro de captura, plano do cliente,
numeracao dos logs, endpoints, handshake, encerramentos FIN/ACK e remontagem
dos streams TCP. Nenhum conteudo recebido foi executado como instrucao.

| Conferencia | Resultado |
| --- | --- |
| Requisicoes e respostas HTTP 200 | 12 |
| Corpo por resposta | 262.144 bytes (256 KiB) |
| Corpos HTTP totais | 3.145.728 bytes (3 MiB) |
| Conexoes TCP distintas | 12 |
| Pacotes | 2.474 |
| Registros truncados / pacotes RST | 0 / 0 |
| Payload TCP duplicado na remontagem | 0 bytes |
| Conteudo e hash dos 12 corpos | Coincidem com o payload sintetico |
| Handshakes e fechamentos bidirecionais | Confirmados nas 12 conexoes |

A captura filtrada durou 40,932764 segundos. Os intervalos inicio-a-inicio das
conexoes tiveram minimo 3,031032 s, mediana 3,047039 s e maximo 9,593188 s.
O plano previa pausa de tres segundos apos a transferencia, nao inicios exatos
a cada tres segundos. A causa da pausa maior nao foi determinada.

Nao foi fornecido contador de drops: nao se afirma zero perdas da captura.
A validacao sustenta a completude do conteudo HTTP deste ensaio, nao uma
avaliacao de todo o trafego das VMs ou da rede domestica.

## 2. Volume maior nao significa duracao maior demonstrada

O cliente registrou tempos curl entre 0,025237 e 0,040856 segundos, com mediana
0,027104 s. Portanto, esta rodada **nao demonstrou downloads longos**, apesar
do limite planejado de 512K e do corpo maior. Nao foi isolada a causa desses
tempos; nao se assume que o limite tenha imposto o ritmo esperado a cada pacote.

Nos segmentos V4 com payload, `flow_duration` variou de 2.906 a 11.879 us
(mediana 3.272,5 us). Nos segmentos sem payload, de 13.502 a 37.385 us
(mediana 22.972 us). Tempos do curl, duracao do segmento e duracao da sessao
sao medidas diferentes e nao devem substituir umas as outras.

O proximo ensaio, LAB05, busca alongar os downloads, mas isso precisara ser
confirmado novamente em logs e PCAP, nao apenas pelo nome do cenario ou flags.

## 3. Extracao V4

Foi usada a mesma imagem/revisao V4
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, com PCAP somente leitura e container
sem rede. Acesso ao Docker fora da sandbox foi autorizado. Nenhuma imagem foi
reconstruida e nenhuma dependencia foi instalada.

Foram exportados 24 registros de dados (o terminal conta 25 com cabecalho):
12 com payload e 12 sem payload. A soma dos pacotes exportados e 2.474, igual
a captura. Payload TCP total: 3.149.448 bytes, incluindo requisicoes e
cabecalhos HTTP, por isso maior que os corpos registrados pelo curl.

Os segmentos com payload tem de 193 a 205 pacotes; os sem payload, de 5 a 10.
Nao presumir que um segmento final sempre tenha tres pacotes, como no LAB03.

As 60 features passaram em finitude, tipos e ordem. Fingerprint:
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Nenhuma linha foi removida, unida ou corrigida. Isso nao homologa equivalencia
semantica com a extracao historica do CIC-IDS2017.

## 4. Resultado nos limiares operacionais congelados

| Grupo | Quantidade | IF sinalizados | LOF sinalizados |
| --- | ---: | ---: | ---: |
| Com payload | 12 | 0 | 12 |
| Sem payload | 12 | 0 | 12 |
| Total | 24 | 0 | 24 |

| Modelo | Limiar operacional | Score minimo | Score mediano | Score maximo |
| --- | ---: | ---: | ---: | ---: |
| IF | 0,615824439899627 | 0,35982574512147014 | 0,46271298054528553 | 0,5777044340140828 |
| LOF | 91,08685969933371 | 92,9372385590881 | 799,7305617971296 | 3454,5224393953313 |

Regra: `anomaly_score >= threshold`; score nao e probabilidade. A escala de
IF nao e comparavel diretamente a de LOF. Em cada um dos 12 grupos TCP, LOF
sinalizou ao menos um segmento; IF nao sinalizou nenhum no ponto operacional.

**Decisao nativa e operacional nao sao a mesma coisa.** O IF nativo sinalizou
os 12 segmentos com payload. No ponto operacional registrado, os mesmos scores
ficaram abaixo do limiar e nao geraram sinalizacao. LOF nativo sinalizou 24.
Nenhuma dessas contagens foi usada para trocar o ponto de operacao escolhido.

## 5. Comparacao descritiva das rodadas

| Sessao | Corpo por resposta | Conexoes | Segmentos V4 | IF operacional | LOF operacional | LOF com payload |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| LAB02 | 187 bytes | 10 | 20 | 0/20 | 20/20 | 10/10 |
| LAB03/r1 | 16 KiB | 30 | 60 | 0/60 | 39/60 | 9/30 |
| LAB04/r1 | 256 KiB | 12 | 24 | 0/24 | 24/24 | 12/12 |

A variacao nao e monotona nem prova melhoria/piora de desempenho. Nao se
isolou o efeito de volume, ritmo, tamanho dos segmentos ou diferencas de
extracao. Ausencia de alerta do IF nao demonstra deteccao de ataques futuros.
Nao descartar segmentos sem payload para reduzir a taxa do LOF.

Foram calculadas apenas taxas de sinalizacao. Nao foram calculadas precisao,
recall, acuracia, F1 ou FPR de laboratorio; as atividades planejadas nao geraram
verdade de referencia independente por segmento. Ambiente e extracao diferem
do CIC-IDS2017, e os segmentos de uma conexao nao sao observacoes independentes.

## 6. Integridade e arquivos

O validador conferiu hashes das fontes antes/depois da importacao. As copias
preservadas tambem foram comparadas aos hashes registrados nessa recepcao.
Os .joblib coincidem com o registro e ficaram inalterados, assim como
manifestos, limiares e implementacao. Os hashes das saidas e as 24 decisoes
por modelo foram conferidos. Persistem os avisos anteriores dos JSONs
auxiliares de metadados: hashes historicos divergentes, causa nao estabelecida,
e arquivos nao usados para predizer. Nenhuma divergencia foi ocultada ou corrigida.

Os mesmos 33 testes da rodada anterior foram repetidos e aprovados. Nao houve
alteracao no codigo de validacao/inferencia para obter estes resultados.
Nao houve gravacao em banco nem mudanca de firewall, VM ou adaptadores.

Evidencias: `data/lab/lab04_medium/r1/capture_validation.json`, `input/`,
`client_logs/`, `extracted/` e `inference/`.

## 7. Proximo passo — LAB05/r1

No Windows-LAB, antes de iniciar a nova captura:

```powershell
curl.exe --noproxy "*" --max-time 10 --fail --head http://172.31.60.10:8000/benign-v1/large_2m.bin
```

Esperado: HTTP 200, Content-Length 2097152. No OPNsense crie um job **novo**,
com mesmos filtros (hn2, IPv4/TCP, host 172.31.50.161, porta 8000), snaplen
65535, Count 50000 e descricao `lab05_slow_r1`. Inicie-o antes do comando:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab05_slow -Repetition 1 -CaptureStarted
```

Sao seis downloads sequenciais de 2 MiB, teto planejado de 128 KiB/s e pausa
de tres segundos entre eles. Estimativa de cerca de dois minutos, nao garantia
de duracao dos segmentos. Espere seis respostas HTTP 200 de 2097152 bytes.

Depois aguarde cinco segundos, pare o job, baixe outro ZIP e preserve os logs
da nova pasta da sessao. Guarde tudo como LAB05_r1, sem sobrescrever rodadas
anteriores. Nao ajuste regras ou limiares para modificar a sinalizacao.
