# LAB02: primeira extracao de features do PCAP HTTP

Data da execucao: 25/10/2026. Estado: extracao concluida; compatibilidade
estrutural demonstrada nesta amostra; compatibilidade semantica ainda pendente.
Nenhum modelo foi treinado, recalibrado ou utilizado para predicao nesta etapa.

Atualizacao: a comparacao historica posterior esta documentada em
`reports/lab/LAB02_HISTORICAL_COMPARISON.md` e
`reports/lab/lab02_historical_comparison.json`. Ela nao homologou nenhum dos
dois perfis para equivalencia exata com o CIC-IDS2017.

## Entrada e ambiente

- Captura: `lab02_windows_kali_http_tcp`, interface `hn2` (KALI).
- PCAP: `data/lab/lab02_http/input/47788496-de5d-46de-b0cd-64f201001a38_hn2.pcap`.
- SHA-256: `8052d6aa3b9021787b18ca162d520e88cb093893bb1ac20ab7cf90e35dd66c7d`.
- Dez conexoes entre Windows `172.31.50.161:60029-60038` e Kali
  `172.31.60.10:8000`. Cem pacotes TCP, sem registros truncados.
- Fonte: https://github.com/ahlashkari/CICFlowMeter
- Commit fixado: `98a5ebad0df579cc8b43eedd3421b3ae87699901` (CICFlowMeter Java V4).
- Java e bibliotecas nativas instalados somente na imagem Docker.
- Execucao offline: sem rede, sem portas publicadas, usuario nao privilegiado,
  capacidades removidas, sistema de arquivos somente leitura, PCAP montado
  somente leitura e diretorio de saida separado. Limite de 1 CPU e 1 GiB de RAM.
- Fuso do extrator: UTC. O timestamp textual do CSV nao inclui o fuso;
  conservar esse metadado antes de construir `observed_at`.
- Os SHA-256 dos dois modelos `expanded_100k` foram conferidos contra o registro
  operacional apos a extracao e continuam iguais.

## Reproducao

Na raiz do projeto, com Docker Desktop em modo Linux:

```powershell
docker build --tag tcc-cicflowmeter:98a5ebad infra/flow_extractor

.\extract_lab_flows.ps1 `
  -PcapPath .\data\lab\lab02_http\input\47788496-de5d-46de-b0cd-64f201001a38_hn2.pcap `
  -OutputDirectory .\data\lab\lab02_http\extracted_repeat
```

A pasta de saida deve estar vazia. O extrator oficial remove CSVs com o mesmo
nome; o wrapper bloqueia a reutilizacao de uma pasta com resultados existentes.
O Dockerfile fixa o commit do extrator e os digests das imagens-base. As
dependencias de sistema ainda sao obtidas dos repositorios; o manifesto de cada
execucao guarda o ID exato da imagem utilizada. Conservar essa imagem para
reproduzir o mesmo ambiente binario.

## Resultado bruto observado

- CSV: `data/lab/lab02_http/extracted/47788496-de5d-46de-b0cd-64f201001a38_hn2.pcap_Flow.csv`.
- SHA-256: `3c3d4b8f021157c940c71040b9218d3df7ab6b262ae95033dbfbd1d69c770513`.
- 20 linhas de dados, 84 colunas. A mensagem de terminal `21 flows` conta tambem
  o cabecalho e nao corresponde a 21 registros de dados.
- Dez registros com 3 pacotes forward e 4 backward; outros dez com 2 forward
  e 1 backward. A soma permanece em 100 pacotes.
- Dez segmentos finais nao possuem payload. Nao foram descartados nem unidos.
- Total de payload TCP contabilizado: 4.230 bytes (423 por conexao).
- A coluna `Label` contem `NeedManualLabel`, marcador do extrator. Nao e rotulo
  observado nem classe verdadeira e foi excluida da verificacao das features.

O log do extrator informa `Total=100,Valid=100,Discarded=0`.
O manifesto `extraction_run.json` registra imagem, commit e hashes antes/depois
do PCAP. O PCAP nao mudou durante a execucao.

## Mapeamento estrutural avaliado

Aplicou-se apenas em memoria `normalize_columns`, seguido dos aliases abaixo.
O CSV bruto nao foi reescrito e nenhum registro foi enviado a inferencia.

| Nome normalizado V4 | Nome do modelo |
| --- | --- |
| dst_port | destination_port |
| total_fwd_packet | total_fwd_packets |
| total_bwd_packets | total_backward_packets |
| total_length_of_fwd_packet | total_length_of_fwd_packets |
| total_length_of_bwd_packet | total_length_of_bwd_packets |
| packet_length_min | min_packet_length |
| packet_length_max | max_packet_length |
| fwd_init_win_bytes | init_win_bytes_forward |
| bwd_init_win_bytes | init_win_bytes_backward |
| fwd_act_data_pkts | act_data_pkt_fwd |
| fwd_seg_size_min | min_seg_size_forward |

Com os 11 aliases, todas as 60 features estao presentes e nao ha colisoes de
nomes. Utilizou-se `align_features_to_manifest()` para conferir as familias
numericas existentes: 39 colunas `int64` e 21 colunas `float64`.
Os 20 registros passam em finitude e integralidade dos campos inteiros.

O fingerprint resultante e exatamente o esquema final dos splits/modelos:

`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`

Essa igualdade valida nomes, ordem e tipos; nao comprova a equivalencia dos
calculos com a ferramenta que gerou o CIC-IDS2017.

## Diferencas semanticas observadas

1. **Segmentacao TCP:** cada conexao completa de dez pacotes foi exportada em
   dois segmentos de sete e tres. Na primeira conexao, a duracao completa do
   PCAP e 1.685 microssegundos; o segmento principal do CSV tem 1.335 e o final
   157. O intervalo entre os segmentos nao integra nenhuma dessas duracoes.
   O codigo de `FlowGenerator.java` emite um fluxo ao processar FIN backward.
   A compatibilidade com a versao usada no CIC-IDS2017 ainda nao foi demonstrada.

2. **Janela backward:** nos dez SYN/ACK do servidor, o campo TCP Window Size
   bruto e 64.240. No primeiro segmento de cada conexao, o CSV exporta 126 como
   `Bwd Init Win Bytes`. A leitura independente do PCAP confirma que 126 aparece
   em pacotes posteriores. O metodo `BasicFlow.addPacket()` sobrescreve
   `Init_Win_bytes_backward` nos pacotes backward. Renomear a coluna nao resolve
   a diferenca de significado. Trata-se da janela bruta, sem multiplicacao pelo
   fator de escala TCP.

3. **Media de tamanho:** no primeiro segmento, o CSV apresenta 423 bytes de
   payload e sete pacotes, mas `Packet Length Mean=52.875` equivale a 423/8.
   `Average Packet Size=60.428571...` equivale a 423/7. O codigo inclui o primeiro
   pacote duas vezes em `flowLengthStats`. Isso tambem afeta estatisticas que
   usam esse acumulador. Nao corrigir automaticamente: o treinamento pode
   incorporar particularidades historicas de extracao.

Uma sondagem exploratoria das primeiras 10.000 linhas do Monday e do Tuesday
originais apresentou tanto casos compativeis com a media pelo total de pacotes
quanto pelo total mais um. Essa sondagem nao identifica a versao historica nem
comprova equivalencia geral; faltam PCAPs de referencia correspondentes ou
documentacao verificavel do extrator original.

Fontes para auditoria do commit utilizado:

- https://github.com/ahlashkari/CICFlowMeter/blob/98a5ebad0df579cc8b43eedd3421b3ae87699901/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java
- https://github.com/ahlashkari/CICFlowMeter/blob/98a5ebad0df579cc8b43eedd3421b3ae87699901/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java
- https://github.com/ahlashkari/CICFlowMeter/blob/98a5ebad0df579cc8b43eedd3421b3ae87699901/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java
- https://github.com/ahlashkari/CICFlowMeter/blob/98a5ebad0df579cc8b43eedd3421b3ae87699901/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java

## Decisao desta etapa

Extracao e estrutura aprovadas como experimento local; equivalencia semantica
pendente. Nao executar inferencia de forma automatica com este CSV ainda.
Nao somar segmentos, preencher valores, remover linhas de encerramento nem
corrigir a janela backward sem uma decisao metodologica explicita.

Proxima atividade: investigar a versao historica da extracao CIC-IDS2017 e
comparar implementacoes com esta captura de referencia; documentar um perfil
de extrator antes de criar o adaptador sem rotulos e realizar inferencia
exploratoria no laboratorio. Os modelos e seus limiares permanecem congelados.
