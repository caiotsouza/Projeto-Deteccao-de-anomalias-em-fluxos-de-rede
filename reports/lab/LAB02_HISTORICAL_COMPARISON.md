# LAB02 — comparacao historica dos extratores

Data: 25/10/2026. Etapa concluida: comparacao reproduzivel, sem inferencia.

Atualizacao posterior: o uso exploratorio da V4 foi autorizado e a primeira
inferencia foi executada, sem homologar equivalencia semantica nem alterar
modelos/limiares. Consulte `reports/lab/LAB02_V4_INFERENCE.md`. Este documento
conserva o estado da etapa de comparacao historica.

## 1. Resultado e decisao

**Nenhum dos dois perfis testados demonstrou equivalencia exata com o extrator
que gerou os CSVs originais do CIC-IDS2017.** Ambos atendem ao contrato estrutural
das 60 features, mas exibem diferencas de calculo ou construcao dos fluxos.

Nao houve treinamento, recalibracao, predicao com os modelos do projeto nem
gravacao em MongoDB/Grafana. O PCAP e os CSVs brutos foram preservados.

Isso nao invalida os resultados anteriores obtidos com os CSVs do CIC-IDS2017.
A limitacao identificada diz respeito a transferir os modelos para dados novos
produzidos por outra revisao do extrator.

## 2. O que foi executado e por que

1. Inspecao do historico publico do repositorio oficial CICFlowMeter. A revisao
   inicial encontrada no historico consultado e de 12/02/2018; nao foi
   identificado um commit verificavel como o gerador exato dos CSVs de 2017.
   Essa ausencia no historico consultado nao prova que o codigo nao exista em
   outro local.
2. Compilacao de uma segunda imagem Docker usando a revisao
   `99dc82768a0ebbf2be63a506b185113f52ab1edf`, anterior a correcao das flags de
   outubro de 2019. O nome interno `legacy_pre2019` significa aqui **anterior a
   essa correcao**, nao uma revisao publicada antes do ano de 2019.
3. Execucao sobre o mesmo PCAP de 100 pacotes, sem acesso a rede, sem publicar
   portas, com a entrada somente leitura e saida separada.
4. Implementacao de `src/lab_flow_audit.py` e `audit_lab_extractors.py`, que
   verificam hashes, procedencia, colisoes de nomes, finitude, tipos e ordem das
   features. O leitor PCAP independente suporta apenas Ethernet/IPv4/TCP sem
   fragmentacao e timestamps em microssegundos; rejeita formatos fora desse
   escopo em vez de produzir totais parciais. Nao e um novo extrator de features.
5. Leitura das sete flags selecionadas em todas as 2.830.743 linhas dos oito CSVs
   originais locais. Todas possuem somente valores 0 ou 1. Nao foi amostragem.
6. Comparacao das saidas sem preencher valores, unir segmentos, remover linhas
   ou converter contagens de flags para booleanos.
7. Execucao de 19 testes: 10 novos da auditoria, 4 de alinhamento/divisao e 5 de
   inferencia existente. Todos passaram. Os testes de inferencia usam fixtures
   sinteticas, nao as predicoes da captura. Uma primeira execucao falhou por
   permissao na pasta temporaria da sandbox; a repeticao autorizada fora dela
   passou sem alterar os testes existentes.

## 3. Comparacao observada

| Verificacao | Captura independente | V4 `98a5ebad` | Historico `99dc8276` |
| --- | --- | --- | --- |
| Conexoes TCP completas na amostra | 10, com 10 pacotes cada | 20 registros exportados | 20 registros exportados |
| Soma dos pacotes contabilizados | 100 | 100 | 90 |
| Soma do payload TCP | 4.230 bytes | 4.230 bytes | 4.230 bytes |
| Segmento principal, ate o primeiro FIN | 3 forward / 4 backward | 3 / 4 | 2 / 5 |
| Segmentos finais exportados | Tres pacotes restantes por conexao | 2 / 1 | 1 / 1 |
| SYN Flag Count do segmento principal | Dois pacotes com SYN | 2 | 1 |
| ACK Flag Count do segmento principal | Seis pacotes com ACK | 6 | 0 |
| Janela inicial backward, campo TCP bruto | 64.240 | 126 | 126 |
| Contrato estrutural das 60 features | Nao se aplica | Passou | Passou |
| Equivalencia semantica com CIC-IDS2017 | Nao determinada | Nao estabelecida | Nao estabelecida |

Os valores por segmento se repetem nas dez conexoes desta captura. Os 20
registros exportados nao sao 20 requisicoes HTTP nem 20 ataques: correspondem a
segmentos de dez conexoes conhecidas. Cada requisicao recebeu HTTP 200.

O perfil historico conserva todo o payload, mas nao contabiliza dez pacotes nos
registros exportados. O codigo encerra o fluxo ao encontrar FIN; os ACK finais
que ficam isolados sao omitidos na exportacao de fluxos correntes com apenas um
pacote. O log `Valid=100,Discarded=0` refere-se a leitura dos pacotes e nao garante
que todos estejam representados na soma dos registros exportados.

Tambem se observam `init_win_bytes_forward=-1` e `min_seg_size_forward=0` nos
segmentos principais historicos. A auditoria nao substitui esses valores nem os
declara corretos. O uso de comparacao de referencias de arrays no primeiro
pacote em `BasicFlow` e uma possivel causa; a observacao numerica foi confirmada,
mas nao foi aplicada nem validada uma correcao do Java nesta etapa.

Nos dois perfis, a media de comprimento e 52,875 para o segmento principal,
enquanto Average Packet Size e aproximadamente 60,428571. Nao se tentou
"corrigir" esses calculos, pois uma alteracao tambem mudaria a distribuicao
vista pelos modelos.

## 4. Evidencia historica sobre as flags

A pesquisa primaria dos autores de *Troubleshooting an Intrusion Detection
Dataset: the CICIDS2017 Case Study* documenta que as contagens originais de
flags eram incrementadas apenas no primeiro pacote e descreve o encerramento
no primeiro FIN. Isso explica por que utilizar uma revisao mais recente nao
equivale automaticamente a reproduzir o treinamento:

https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html

No historico oficial, o commit abaixo reativa `checkFlags(packet)` em
`BasicFlow.addPacket()` em 15/10/2019. A diferenca foi inspecionada localmente:

https://github.com/ahlashkari/CICFlowMeter/commit/ed1d6bcbdefe161be51ac278f76be995f7121482

Codigo das duas revisoes examinadas:

- https://github.com/ahlashkari/CICFlowMeter/tree/98a5ebad0df579cc8b43eedd3421b3ae87699901
- https://github.com/ahlashkari/CICFlowMeter/tree/99dc82768a0ebbf2be63a506b185113f52ab1edf

**Nao basta limitar contagens modernas a 0/1.** Por exemplo, o primeiro pacote
da conexao e SYN sem ACK. No segmento principal historico, ACK Flag Count e 0;
converter a contagem moderna 6 para 1 nao reproduziria esse comportamento.

## 5. Arquivos, integridade e reproducao

- Auditoria estruturada: `reports/lab/lab02_historical_comparison.json`.
- Relatorio inicial V4: `reports/lab/lab02_extractor_compatibility.md`.
- Resultados brutos: `data/lab/lab02_http/extracted/` e `extracted_pre2019/`.
- Cada pasta possui `extraction_run.json` com commit, ID da imagem e hashes.
- O auditor confirmou hashes inalterados dos modelos IF/LOF expandidos, registro
  operacional, manifesto de selecao, manifesto dos splits, PCAP e saidas dos
  extratores. Os hashes dos modelos coincidem com o registro operacional.
- Nenhuma classe verdadeira foi inferida de `Label`; os marcadores do extrator
  sao ignorados. As features nao incluem IP, timestamp ou rotulo.
- O agrupamento independente por endpoints nao separa reutilizacoes da mesma
  5-tupla e nao aplica timeouts. Essa limitacao nao interfere nas dez conexoes
  distintas desta captura curta, mas impede generalizar o agrupamento como um
  motor de reconstrucao TCP.

Na raiz do projeto, com a imagem V4 ja existente:

```powershell
docker build --build-arg CICFLOWMETER_COMMIT=99dc82768a0ebbf2be63a506b185113f52ab1edf --tag tcc-cicflowmeter:99dc8276 infra/flow_extractor

.\extract_lab_flows.ps1 -ExtractorProfile legacy_pre2019 -PcapPath .\data\lab\lab02_http\input\47788496-de5d-46de-b0cd-64f201001a38_hn2.pcap -OutputDirectory .\data\lab\lab02_http\extracted_pre2019_repeat

.\.venv\Scripts\python.exe -B audit_lab_extractors.py --pcap data/lab/lab02_http/input/47788496-de5d-46de-b0cd-64f201001a38_hn2.pcap --v4-dir data/lab/lab02_http/extracted --legacy-dir data/lab/lab02_http/extracted_pre2019_repeat --report reports/lab/lab02_historical_comparison_repeat.json --scan-original-flags

.\.venv\Scripts\python.exe -B -m unittest tests.test_lab_flow_audit tests.test_data_split tests.test_inference_service -v
```

Use pastas de saida vazias e nomes novos para os relatorios. O auditor bloqueia
sobrescrita. O resultado esperado inclui 100 pacotes na captura, 100 na soma V4,
90 na soma historica e status `comparison_completed_not_approved_for_inference`.
Esse status significa que a comparacao terminou, nao que houve falha na execucao.

## 6. Proxima decisao metodologica

Nao promover o perfil historico como extrator definitivo apenas pelas flags.
Nao alterar os modelos ou os limiares para compensar diferencas de extracao.

O caminho mais rigoroso e obter um pequeno recorte PCAP original do CIC-IDS2017
com fluxos correspondentes aos CSVs originais, preservar contexto de captura e
comparar as 60 features e a segmentacao antes de homologar um perfil. Recortar
PCAPs tambem pode alterar fluxos; as bordas precisam ser controladas.

Como alternativa, pode-se autorizar uma inferencia **explicitamente
exploratoria** com a V4, mantendo os modelos congelados e registrando a revisao
do extrator e as incompatibilidades em cada resultado. Isso demonstra o caminho
tecnico PCAP -> features -> score, mas nao valida eficacia em producao. Um alerta
nessa amostra nao prova ataque, e a taxa de sinalizacao nao e precisao nem FPR.

Essa escolha deve preceder o adaptador de inferencia. Nenhuma dessas alternativas
exige iniciar ataques, mudar regras do firewall ou expor as VMs a rede domestica.
