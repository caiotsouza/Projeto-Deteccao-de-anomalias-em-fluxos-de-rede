# LAB05 / repeticao 1 — transferencia limitada no cliente

Data: 25/10/2026. Estado: captura validada, extracao V4 e inferencia exploratoria
concluidas. Os modelos e limiares anteriores foram preservados.

## 1. Validacao das evidencias

Recebidos: `a21d9530-64fc-4145-a022-ac55d3d8c1f5.zip`, `requests.jsonl` e
`run_manifest.json`. Copias dos bytes recebidos foram preservadas em
`data/lab/lab05_slow/r1/input/` e `client_logs/`, sem sobrescrever outras rodadas.

- ZIP SHA-256: `726b1a021f4ef98f79d1e2bb5d3be945f677c57752f7dd01b98bc91ba52e5a6c`.
- PCAP SHA-256: `45c0fc51781d6bd92b20ffbe976e416cd724400dc67f43dbf18e443e9c4f69d3`.
- Corpo SHA-256: `21ad43464ff341f863b1149c5a11d95fb8a325bb44ad51ed4afc17979ad44245`.

| Conferencia | Resultado |
| --- | --- |
| Downloads e respostas HTTP 200 | 6 |
| Corpo por resposta | 2.097.152 bytes (2 MiB) |
| Corpos HTTP totais | 12.582.912 bytes (12 MiB) |
| Conexoes TCP distintas | 6 |
| Pacotes observados | 9.245 |
| Registros truncados / pacotes RST | 0 / 0 |
| Payload duplicado na remontagem | 0 bytes |
| Conteudo/hash dos seis corpos | Identico ao sintetico esperado |
| Handshakes e encerramentos FIN/ACK | Confirmados nas duas direcoes |

O filtro e o plano correspondem ao cenario: hn2, IPv4/TCP, host Windows,
porta 8000, snaplen 65535, limite 50000, descricao `lab05_slow_r1`.
Foi conferida a integridade do ZIP, dos logs, dos streams e das copias. Nao se
executou conteudo recebido como instrucao. O contador de drops nao foi fornecido;
nao se afirma ausencia de todo tipo de perda ou captura de todo trafego das VMs.

A captura durou 108,680067 s. Os intervalos inicio-a-inicio das conexoes foram
de 18,477601 a 19,156853 s, com mediana 18,498218 s.

## 2. Achado principal: tempos diferentes medem coisas diferentes

Os downloads do cliente duraram aproximadamente 15,5 s, mas isso nao significa
que os dados passaram uniformemente pela interface capturada durante 15,5 s.

| Medida | Minimo | Mediana | Maximo |
| --- | ---: | ---: | ---: |
| Tempo curl por requisicao | 15,470714 s | 15,489723 s | 15,498626 s |
| Conexao TCP completa no PCAP | 15,470343 s | 15,489380 s | 15,498362 s |
| Entre primeiro/ultimo pacote com payload do servidor | 0,006416 s | 0,0072275 s | 0,008443 s |
| Duracao do segmento V4 com payload | 0,007652 s | 0,008525 s | 0,009854 s |
| Duracao do segmento V4 sem payload | 15,461488 s | 15,479903 s | 15,490689 s |

Portanto, no ponto hn2 o conteudo foi observado em rajada de milissegundos.
A maior parte da duracao ficou no segmento posterior sem payload. O teste
atingiu uma transferencia longa na perspectiva do cliente e uma conexao longa,
mas **nao demonstrou envio sustentado de payload no ponto de captura**.

O limite configurado no cliente e a medicao do envio em rede nao devem ser
tratados como equivalentes. Buffering e controle de leitura sao possibilidades
a investigar, nao uma causa isolada provada. Nenhum ajuste no firewall ou nas
interfaces foi feito para explicar esse efeito. As diferencas de segmentacao
do extrator tambem precisam permanecer explicitas na interpretacao.

## 3. Extracao e contrato

Foi reutilizada a V4 do commit `98a5ebad0df579cc8b43eedd3421b3ae87699901`,
em container sem rede, entrada somente leitura e saida nova. Acesso ao Docker
fora da sandbox foi autorizado; nao houve instalacao nem reconstrucao da imagem.

Foram exportados 12 registros de dados (13 no terminal contando cabecalho):
seis com payload e seis sem payload. Eles contabilizam os 9.245 pacotes.
Payload TCP total: 12.584.760 bytes, incluindo pedidos/cabecalhos HTTP, enquanto
os corpos totalizam 12.582.912 bytes.

Os segmentos com payload possuem 1.505 a 1.538 pacotes; os sem payload, de
7 a 29. As 60 features passaram em finitude, tipos e ordem, com fingerprint
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Nenhum segmento foi excluido ou unido; nao houve preenchimento ou correcao
de flags, janelas, tempos ou taxas. Equivalencia semantica com o CIC-IDS2017
permanece nao estabelecida.

## 4. Resultado nos limiares operacionais congelados

| Grupo | Quantidade | IF sinalizados | LOF sinalizados |
| --- | ---: | ---: | ---: |
| Com payload | 6 | 6 | 6 |
| Sem payload | 6 | 0 | 6 |
| Total | 12 | 6 | 12 |

| Modelo | Limiar | Score minimo | Score mediano | Score maximo |
| --- | ---: | ---: | ---: | ---: |
| IF | 0,615824439899627 | 0,4206080475848895 | 0,5346327563953346 | 0,6530848176418931 |
| LOF | 91,08685969933371 | 592,0002604399908 | 874,2828787213203 | 2653,8793964139486 |

O IF sinalizou todos os segmentos com payload; seus scores variaram de
0,6453772572459657 a 0,6530848176418931, acima do limiar existente. Os segmentos
sem payload permaneceram abaixo. Isso nao demonstra qual feature causou cada
decisao, nem autoriza chamar esse resultado de deteccao de ataques lentos.

No LOF, os seis segmentos com payload e os seis sem payload foram sinalizados.
As decisoes nativas tambem totalizaram 6 no IF e 12 no LOF nesta rodada.
Em cada um dos seis grupos TCP houve pelo menos um segmento sinalizado por
ambos os modelos. Os grupos nao foram transformados em novos rotulos reais.

Nao foram calculados precisao, recall, F1, acuracia ou FPR de laboratorio.
As taxas 50% (IF) e 100% (LOF) sao apenas taxas de sinalizacao nesta amostra
planejada como benigna, sem rotulagem independente por segmento. Sinalizacao
nao comprova ataque; ausencia de sinalizacao nao comprova seguranca.

## 5. Consolidacao das quatro rodadas

| Sessao | Corpo por resposta | Conexoes | Segmentos | IF operacional | LOF operacional |
| --- | --- | ---: | ---: | ---: | ---: |
| LAB02 | 187 bytes | 10 | 20 | 0/20 | 20/20 |
| LAB03/r1 | 16 KiB | 30 | 60 | 0/60 | 39/60 |
| LAB04/r1 | 256 KiB | 12 | 24 | 0/24 | 24/24 |
| LAB05/r1 | 2 MiB | 6 | 12 | 6/12 | 12/12 |

Sao 58 conexoes e 116 segmentos ao incluir LAB02. Apenas as tres sessoes da
matriz LAB03-LAB05 somam 48 conexoes e 96 segmentos. Esses totais sao pequenos,
correlacionados, restritos a HTTP/1.0 entre os mesmos endpoints e nao equivalem
a uma semana representativa de rede corporativa.

Nao calcular uma taxa agregada dessas sessoes heterogeneas como metrica de
qualidade. Nao se isolou causalmente tamanho, duracao, quantidade de pacotes
ou diferencas de extracao. A tendencia do IF acompanha mudancas nos dados, mas
nao prova desempenho superior, inferior ou generalizacao para producao.

Foi criado `summarize_lab_captures.py`, que conferiu a mesma identidade dos
modelos/pontos/limiares nas quatro rodadas, validou hashes das saidas e remontou
os streams para obter corpos e duracoes. Ele nao carrega modelos. Resultado:
`reports/lab/lab_capture_summary.json`. Repetir exige nome de saida novo:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --output reports/lab/lab_capture_summary_repeat.json
```

## 6. Integridade e verificacao

Modelos, limiares, manifestos e codigo de inferencia permaneceram inalterados.
Foram conferidos os hashes dos arquivos protegidos, implementacao, copias das
fontes contra o recibo de importacao e saidas. As 12 decisoes por modelo
correspondem a regra `anomaly_score >= threshold`; score nao e probabilidade.

Persistem os avisos dos JSONs auxiliares com hashes historicos divergentes,
cuja causa nao foi estabelecida. Eles nao sao usados na inferencia. Os dois
.joblib coincidem com o registro; nenhuma divergencia foi corrigida ou ocultada.

Os 33 testes existentes de validacao, adaptador, auditoria, helpers e
alinhamento/divisao foram repetidos e passaram. A consolidacao tambem foi
executada sobre as quatro capturas reais, verificando os hashes e estruturas.
Nenhum banco, dashboard, VM ou regra de rede foi modificado.

Evidencias completas em `data/lab/lab05_slow/r1/`: `capture_validation.json`,
`input/`, `client_logs/`, `extracted/` e `inference/`.

## 7. Proxima decisao experimental

A primeira rodada dos tres tamanhos foi concluida. Uma continuacao util e
planejar um LAB06 com envio dos blocos pausado no **servidor Kali**, mantendo
HTTP/1.0, porta 8000, topologia e modelos. O objetivo seria observar payload
distribuido no tempo, nao apenas encerramento TCP tardio. Esse cenario ainda
nao foi implementado nem executado e exige organizar a troca do servidor.

Tambem cabem repeticoes r2/r3 e comparacao das distribuicoes das features com
o treinamento, sempre preservando resultados e separando hipoteses de causas
demonstradas. Nao ajustar o limiar para fazer os alertas desaparecerem. Nao
iniciar ataques antes de definir escopo, evidencias e rotulagem adequados.
