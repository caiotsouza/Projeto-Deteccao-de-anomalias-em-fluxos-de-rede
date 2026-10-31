# LAB06 com envio pausado no servidor / repeticao 1 — resultados

Data: 25/10/2026. Estado: validacao, extracao V4 e inferencia exploratoria
concluidas. O objetivo temporal foi demonstrado no ponto de captura hn2.

## 1. Evidencias preservadas

Foram recebidos o ZIP `74e5299f-a775-455c-b68c-5849663641e6.zip`, dois logs do
cliente Windows e dois logs do servidor Kali. Todos foram copiados para uma
sessao nova em `data/lab/lab06_serverpaced/r1/`, sem substituir resultados.

- ZIP SHA-256: `384674a3bf0192533041267f3572a8df1c4cc0f0edef21a098d0d7ccd1dbc321`.
- PCAP SHA-256: `913e4a48116099bb8ea254cd6290966a46d051a02b69d09989346d26981c6503`.
- Servidor SHA-256: `1f1f3deaad867c97361bb9af70000d6758026ecf5f74c1eb05846b7cff50123a`.
- Corpo SHA-256: `21ad43464ff341f863b1149c5a11d95fb8a325bb44ad51ed4afc17979ad44245`.

O servidor executado coincide com a versao preparada na ISO. Seu manifesto
esta stopped e registra seis GETs tentados e seis concluidos. Os registros
contem um HEAD e seis GETs; o PCAP contem somente as seis conexoes do ensaio.

## 2. Validacao cruzada

| Conferencia | Resultado |
| --- | --- |
| Respostas completas HTTP 200 | 6 |
| Corpo por resposta / total | 2 MiB / 12 MiB |
| Conexoes TCP | 6 |
| Pacotes capturados | 10.116 |
| Registros truncados / pacotes RST | 0 / 0 |
| Payload duplicado na remontagem | 0 bytes |
| Handshakes e encerramentos FIN/ACK | Confirmados nas duas direcoes |
| Caminho, conteudo e SHA-256 dos corpos | Conferidos nas seis respostas |
| Marcador LAB06 | Presente nos logs do cliente e nas respostas do PCAP |
| Blocos registrados no Kali | 128 por GET, com 127 pausas |
| Limite de leitura no cliente | Nenhum, conforme o plano |

Foram conferidos o CRC do ZIP, nomes seguros, plano, filtro, sequencia das
requisicoes, endpoints, traces temporais e hashes antes/depois da importacao.
Nenhum arquivo recebido foi executado ou tratado como instrucao.

A captura durou 110,745589 s. Os intervalos inicio-a-inicio das conexoes
variaram entre 18,934508 e 19,023527 s, mediana 18,958804 s.
Nao foi fornecido contador de drops; nao se afirma ausencia absoluta de
perdas ou observacao de trafego fora do filtro.

## 3. Objetivo temporal confirmado

O criterio definido antes da coleta exigia pelo menos 12 s entre primeiro e
ultimo pacote com payload do servidor, por conexao. As seis conexoes passaram.
Os logs monotonicamente temporizados do servidor tambem confirmam as pausas.

| Medida | Minimo | Mediana | Maximo |
| --- | ---: | ---: | ---: |
| Tempo curl | 15,899071 s | 15,9002025 s | 15,906291 s |
| Conexao TCP completa | 15,898618 s | 15,899808 s | 15,905860 s |
| Intervalo entre primeiro/ultimo pacote com payload do servidor | 15,895647 s | 15,8968775 s | 15,903066 s |

Como conferencia descritiva adicional, os payloads TCP do servidor foram
agrupados em janelas de um segundo, ancoradas no primeiro pacote com payload
de cada conexao. Em todas houve 16 janelas ocupadas (indices 0 a 15), com
131.072 a 131.342 bytes por janela. O valor maior inclui cabecalhos HTTP;
o total por resposta foi 2.097.422 bytes de payload TCP do servidor.
Isso sustenta distribuicao dos dados ao longo do intervalo, nao apenas dois
pacotes distantes ou uma rajada inicial seguida de espera.

Os 128 blocos de aplicacao nao equivalem a 128 pacotes TCP: um bloco pode ser
segmentado em varios pacotes. Nao confundir eventos do programa com contagem
de fluxos, pacotes ou amostras independentes.

## 4. Extracao V4 e comparacao com LAB05

Foi reutilizado o commit `98a5ebad0df579cc8b43eedd3421b3ae87699901`, sem rede
no container, com PCAP somente leitura e saida separada. O acesso ao Docker
fora da sandbox foi autorizado. Nao houve reconstrucao da imagem ou instalacao.

Foram exportados 12 registros de dados (13 no terminal contando cabecalho):
seis com payload e seis sem. Os registros contabilizam os 10.116 pacotes.
Payload TCP total: 12.585.144 bytes, incluindo pedidos e cabecalhos HTTP.

O contrato estrutural das 60 features permaneceu:
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Nao se uniram segmentos, preencheram valores ou corrigiram flags/janelas.
A equivalencia semantica com o extrator original do CIC-IDS2017 segue nao
estabelecida; o LAB06 nao resolve retroativamente essa limitacao.

Medianas dos segmentos com payload, nos valores realmente entregues ao modelo:

| Feature | LAB05, limite no cliente | LAB06, pausas no servidor |
| --- | ---: | ---: |
| flow_duration | 8.525 us | 15.899.257,5 us |
| flow_bytes_s | 246.333.337,23 | 131.925,91 |
| flow_packets_s | 179.595,39 | 105,69 |
| flow_iat_mean | 5,576459 us | 9.467,149915 us |
| total_fwd_packets | 79,5 | 140,5 |
| total_backward_packets | 1.440 | 1.540 |

Nos segmentos sem payload, a duracao mediana passou de 15,479903 s no LAB05
para 0,0002285 s no LAB06. Portanto, a duracao longa ficou agora no segmento
com dados, em vez de no segmento posterior sem dados.

Varias features e a implementacao do servidor mudaram; estes resultados nao
isolam causalmente uma unica feature ou o efeito da duracao sobre o score.

## 5. Predicoes nos mesmos limiares operacionais

| Grupo | Quantidade | IF sinalizados | LOF sinalizados |
| --- | ---: | ---: | ---: |
| Com payload | 6 | 6 | 6 |
| Sem payload | 6 | 0 | 6 |
| Total | 12 | 6 | 12 |

| Modelo / grupo | Limiar | Score minimo | Score mediano | Score maximo |
| --- | ---: | ---: | ---: | ---: |
| IF, com payload | 0,615824439899627 | 0,6240240840789611 | 0,6241558741921124 | 0,6241558741921124 |
| IF, sem payload | mesmo | 0,3573057671135349 | 0,35840477134866433 | 0,35973251085938385 |
| LOF, com payload | 91,08685969933371 | 804,2931275965296 | 805,961250333971 | 812,3977730611273 |
| LOF, sem payload | mesmo | 111,25954369395565 | 158,72335784719087 | 195,87586974852962 |

Decisoes nativas: seis sinalizados no IF e 12 no LOF. Nenhum ponto operacional
foi trocado usando estes dados. Score nao e probabilidade e escalas dos modelos
nao devem ser comparadas diretamente.

LAB05 e LAB06 tiveram as mesmas contagens de alertas, mas nao os mesmos scores
ou features. No IF com dados, a mediana caiu de 0,647576 para 0,624156, ainda
acima do limiar. No LOF sem dados, caiu de 1.757,612486 para 158,723358,
tambem acima do respectivo limiar. Isso nao demonstra melhoria de qualidade.

Os alertas ocorreram na atividade planejada como benigna; nao sao evidencia
de ataque. Nao foram calculadas precisao, recall, F1, acuracia ou FPR de
laboratorio. Sao amostras pequenas, sem rotulagem independente por segmento,
com segmentos correlacionados e ambiente/extrator diferentes do treinamento.

## 6. Consolidacao preservando as rodadas anteriores

| Sessao | Conexoes | Segmentos | IF operacional | LOF operacional |
| --- | ---: | ---: | ---: | ---: |
| LAB02 | 10 | 20 | 0/20 | 20/20 |
| LAB03/r1 | 30 | 60 | 0/60 | 39/60 |
| LAB04/r1 | 12 | 24 | 0/24 | 24/24 |
| LAB05/r1 | 6 | 12 | 6/12 | 12/12 |
| LAB06/r1 | 6 | 12 | 6/12 | 12/12 |

O consolidado atualizado esta em
`reports/lab/lab_capture_summary_through_lab06.json`; o JSON anterior de quatro
rodadas foi preservado. A ferramenta de consolidacao conferiu os mesmos hashes
de modelo/pontos/limiares e os hashes das saidas, sem carregar estimadores.

Sao 64 conexoes e 128 segmentos ao incluir LAB02. Nao transformar esses totais
em uma avaliacao representativa de producao ou agregar taxas heterogeneas como
metrica de qualidade. O protocolo continua restrito a HTTP/1.0 e a dois hosts.

## 7. Integridade e verificacoes

As cinco fontes foram preservadas e conferidas contra o recibo de importacao.
Foram verificados arquivos protegidos, codigo da inferencia e hashes das saidas,
alem de 12 IDs unicos/decisoes coerentes por modelo. Os .joblib coincidem com
o registro; modelos, limiares e manifestos ficaram inalterados. Nao houve fit,
novo scaler, mudanca de regra ou gravacao em banco/dashboard.

Persistem os avisos dos JSONs auxiliares com hashes historicos divergentes,
causa nao estabelecida e arquivos nao usados na predicao. Nenhuma divergencia
foi corrigida ou ocultada.

Nesta rodada passaram 37 testes selecionados: as 33 verificacoes de captura,
adaptador, auditoria, helpers e alinhamento, mais quatro testes especificos
do LAB06 (trace e pacing versus rajada/marcador no PCAP). Nao foi necessario
repetir o teste de socket loopback nesta etapa de processamento de evidencias.

Evidencias em `data/lab/lab06_serverpaced/r1/`: `capture_validation.json`,
`input/`, `client_logs/`, `server_logs/`, `extracted/` e `inference/`.

## 8. Proximo passo recomendado

O piloto de coleta/validacao foi concluido. Antes de ampliar servicos ou
iniciar ataques, recomenda-se repetir cenarios relevantes (r2/r3), preservar
os limiares e analisar distribuicoes das 60 features contra o treinamento,
especialmente dos segmentos com dados que o IF e o LOF sinalizam.

Repeticao exige job novo e pastas novas; o servidor LAB06 precisa reiniciar
com outra pasta de logs por causa do limite de seis GETs. Essa continuacao
nao foi executada automaticamente. Calibracao futura exige uma amostra benigna
representativa e separada da avaliacao, nao escolher valores para eliminar
os alertas destes seis downloads.
