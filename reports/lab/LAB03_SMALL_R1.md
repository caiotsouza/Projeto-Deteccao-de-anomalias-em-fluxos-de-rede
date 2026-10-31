# LAB03 pequeno / repeticao 1 — validacao e inferencia

Data da captura: 25/10/2026. Estado: captura validada para o experimento
exploratorio V4; extracao e predicao concluidas. Nenhum modelo ou limiar alterado.

## 1. Evidencias recebidas e preservadas

- ZIP: `4d08662e-9f98-4c52-9c92-bec76eda4683.zip`.
- Manifesto do cliente: `run_manifest.json`.
- Tentativas do cliente: `requests.jsonl`.
- ZIP SHA-256: `6bd3818e2afd0b8ddc5cee7f5c29c5430c12bcc9ff8587319181dcd16de5edcb`.
- PCAP SHA-256: `c415144bb6791be1af904e0551938e74961cab8a230dadea7518c441d7997187`.

Os originais em Downloads nao foram modificados. Copias identicas foram
preservadas em `data/lab/lab03_small/r1/input/` e `client_logs/`. Foram conferidos
os hashes e a igualdade byte a byte das copias do ZIP e dos logs.

O ZIP contem somente o JSON de configuracao e um PCAP. Foram verificados nomes
seguros, limites de tamanho e CRC antes da extracao. Nenhum conteudo recebido
foi tratado como instrucao ou executado.

## 2. Validacao antes de carregar os modelos

Foi criado `validate_benign_http_capture.py` para tornar a conferencia
reproduzivel. A ferramenta exige pasta de sessao nova e nao sobrescreve
evidencias. Foram adicionados cinco testes com capturas sinteticas, incluindo
bytes incorretos, logs ausentes, caminho inseguro no ZIP e remontagem TCP.

| Conferencia | Resultado |
| --- | --- |
| Cenario e repeticao | lab03_small / 1 |
| Cliente / servidor | 172.31.50.161 -> 172.31.60.10:8000 |
| Interface e filtro | hn2, IPv4, TCP, host Windows, porta 8000 |
| Requisicoes no log | 30, numeradas de 1 a 30 |
| Respostas HTTP | 30 respostas 200 |
| Corpos por resposta | 16.384 bytes |
| Soma dos corpos HTTP | 491.520 bytes (480 KiB) |
| Conexoes TCP distintas | 30 |
| Pacotes capturados | 663 |
| Registros de pacote truncados | 0 |
| Pacotes TCP RST | 0 |
| Handshake e FIN/ACK nas duas direcoes | Confirmados nas 30 conexoes |
| Bytes duplicados na remontagem do payload TCP | 0 |
| Contador de drops da captura | Nao fornecido |

O leitor independente remontou os streams pela sequencia TCP, com deteccao de
lacunas e sobreposicoes conflitantes. Confirmou o caminho GET e o protocolo
HTTP/1.0, Content-Length, conteudo completo e SHA-256 de cada resposta.

Todos os corpos coincidem com o arquivo sintetico gerado pelo helper:

`cd5ec79e336fdd6d7a99307f3ad191efc8878f0a23dcdb2e65fc13a0154b0ada`

Os inicios das conexoes foram alinhados a janela de cada tentativa do cliente,
com tolerancia explicita de 250 ms para a conferencia temporal. Isso nao
substitui uma avaliacao independente de sincronizacao de relogios.

Nao atingir o teto de 50.000 pacotes, ter conteudo e encerramentos completos e
nao haver truncamentos sustenta a completude para este cenario HTTP. **Nao
afirmamos zero drops de captura**, pois o respectivo contador nao foi enviado.
Tambem nao se afirma ausencia de outros trafegos fora do filtro observado.

## 3. Horarios e variacao do ritmo

- Primeiro pacote: `2026-10-25T21:22:18.472187+00:00`.
- Ultimo pacote: `2026-10-25T21:23:30.130842+00:00`.
- Intervalo entre esses pacotes: 71,658655 segundos.
- Intervalo inicio-a-inicio entre conexoes: minimo 2,030735 s, mediana
  2,046651 s e maximo 10,069528 s.

A pausa planejada era de dois segundos apos cada transferencia, nao um
metronomo de inicios. Houve uma pausa maior entre as primeiras conexoes. Nao
foi determinada sua causa; nao se atribuiu automaticamente a ataque, rede ou
modelo. A sessao nao foi descartada para selecionar um resultado favoravel.
O tempo de transferencia do curl nao substitui a duracao do fluxo TCP.

## 4. Extracao com a V4 congelada

Foi usada a imagem existente do commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, em container sem rede, PCAP somente
leitura e saida separada. O Docker precisou de execucao autorizada fora da
sandbox devido a restricao de acesso ao pipe; nao foi necessario reconstruir a
imagem nem alterar o daemon.

Resultado bruto:

- 60 registros de dados; o terminal mostra 61 ao contar tambem o cabecalho.
- 30 segmentos com payload, 30 segmentos sem payload.
- Os 60 registros contabilizam os 663 pacotes.
- O payload TCP somado e 500.730 bytes: inclui corpos, cabecalhos HTTP e pedidos.
  Por isso difere dos 491.520 bytes de corpos registrados pelo curl.
- Pares forward/backward: 27 segmentos 4/15, 3 segmentos 5/15 e 30 segmentos 2/1.

Todas as 60 features passaram em ordem, tipos e finitude. Fingerprint canonico:

`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`

Essa verificacao estrutural nao homologa os calculos da V4 como identicos aos
do extrator historico do CIC-IDS2017. Nenhuma flag/janela foi corrigida, e
nenhum segmento foi excluido ou unido.

## 5. Predicoes nos limiares operacionais anteriores

| Grupo | Quantidade | IF sinalizados | LOF sinalizados |
| --- | ---: | ---: | ---: |
| Com payload | 30 | 0 | 9 |
| Sem payload | 30 | 0 | 30 |
| Total | 60 | 0 | 39 |

Taxas de sinalizacao: IF 0%; LOF 65% no total, 30% com payload e 100% sem
payload. Nos 30 grupos de endpoints, o LOF sinalizou ao menos um segmento em
todos; o IF nao sinalizou nenhum. Grupo nao e nova verdade de referencia.

| Modelo | Limiar | Score minimo | Score mediano | Score maximo |
| --- | ---: | ---: | ---: | ---: |
| IF | 0,615824439899627 | 0,35638580480337134 | 0,42047722868243054 | 0,49025671415112404 |
| LOF | 91,08685969933371 | 81,74833865930734 | 524,086657486684 | 843,5084466993392 |

A regra continua `anomaly_score >= threshold`. As escalas nao devem ser
comparadas entre modelos. Na decisao nativa, IF sinalizou 0 e LOF 60; esse
resultado nao foi usado para reajustar os limiares escolhidos anteriormente.

Comparacao descritiva com LAB02:

| Sessao | Conexoes | Segmentos | IF sinalizados | LOF sinalizados | LOF com payload |
| --- | ---: | ---: | ---: | ---: | ---: |
| LAB02, resposta de 187 bytes | 10 | 20 | 0 | 20 | 10/10 |
| LAB03/r1, arquivo de 16 KiB | 30 | 60 | 0 | 39 | 9/30 |

A reducao na taxa do LOF e uma observacao, nao prova de melhoria de qualidade.
Ela sugere investigar as caracteristicas dos segmentos, mas nao isola efeito
do tamanho do arquivo: ambiente, tempos e padroes TCP tambem podem variar.
Nao eliminar os segmentos sem payload para apresentar uma taxa menor.

Nao foram calculados precisao, recall, F1, acuracia ou FPR de laboratorio.
A atividade foi planejada como benigna, mas nao gerou rotulos independentes
por segmento. Alertas nao comprovam ataques, e ausencia de alerta nao comprova
capacidade de detectar um ataque futuro.

## 6. Integridade, testes e arquivos

O IF e o LOF coincidem com seus hashes registrados, antes e depois da execucao.
Limiares, modelos e manifestos ficaram inalterados. Nenhum novo scaler foi
ajustado, nenhum banco foi atualizado e nenhuma alteracao foi feita nas VMs.

Persiste o aviso anterior: os JSONs auxiliares de metadados divergem dos hashes
historicos, com causa ainda nao estabelecida. Nao sao usados na inferencia;
os .joblib continuam conferidos obrigatoriamente. A divergencia e registrada,
nao corrigida nem ocultada.

Foram aprovados 33 testes desta rodada: 5 da validacao da captura, 12 do
adaptador, 10 da auditoria, 2 dos helpers HTTP e 4 de alinhamento/divisao.
Depois foram conferidos os hashes dos arquivos protegidos, implementacao,
saidas e copias dos originais, alem dos totais extraidos.

Evidencias em `data/lab/lab03_small/r1/`:

- `capture_validation.json`: conferencia dos logs e PCAP;
- `input/`: ZIP e arquivos extraidos, preservados;
- `client_logs/`: logs originais copiados;
- `extracted/`: CSV e manifesto V4;
- `inference/`: entradas, predicoes IF/LOF e manifesto da execucao.

## 7. Proximo passo: LAB04/r1

A primeira rodada pequena foi validada. Podemos passar a 12 downloads de
256 KiB, com pausas de tres segundos, sem alterar regras, modelos ou limiares.

Antes da captura, no Windows-LAB:

```powershell
curl.exe --noproxy "*" --max-time 10 --fail --head http://172.31.60.10:8000/benign-v1/medium_256k.bin
```

Esperado: HTTP 200 e Content-Length 262144. Crie um job novo no OPNsense com
os mesmos filtros, snaplen 65535, Count 50000 e descricao `lab04_medium_r1`.
Inicie-o antes do comando abaixo; nao reinicie o job LAB03, pois seus resultados
podem ser substituidos no OPNsense.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab04_medium -Repetition 1 -CaptureStarted
```

Espere as 12 respostas de 262144 bytes, aguarde cinco segundos, pare o job e
preserve outro ZIP com os logs da nova sessao. Nao misture os arquivos de
mesmo nome com LAB03; organize-os numa pasta LAB04_r1. LAB05 fica para depois.
