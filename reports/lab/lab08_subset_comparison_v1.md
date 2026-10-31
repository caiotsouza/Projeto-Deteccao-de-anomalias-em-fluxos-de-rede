# Comparativo exploratório — tráfego benigno e recorte LAB08

## Resultado consolidado

Contagens no ponto operacional `validation_fpr_operational`. Denominador: registros
exportados pelo V4, não pacotes, ataques independentes ou tentativas totais.

| Cenário | Sessões | Registros | IF sinalizados | LOF sinalizados |
| --- | ---: | ---: | ---: | ---: |
| LAB03 — HTTP pequeno | 3 | 180 | 0/180 | 103/180 |
| LAB04 — HTTP médio | 3 | 72 | 0/72 | 72/72 |
| LAB05 — limite no cliente | 3 | 36 | 18/36 | 36/36 |
| LAB06 — controle no servidor | 3 | 36 | 18/36 | 36/36 |
| LAB08 — reconhecimento, recorte exportado | 1 | 4 | 0/4 | 1/4 |

As quatro linhas benignas reúnem três repetições cada; LAB08 contém uma única
sessão e somente os quatro registros exportados. Não são amostras balanceadas.
Não somar cenários heterogêneos para anunciar um índice geral de desempenho.

## Os quatro registros do reconhecimento

| Linha CSV | Porta origem Kali | Porta destino Windows | Score IF | IF sinaliza | Score LOF | LOF sinaliza |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 37416 | 135 | 0.395035 | 0 | 35.981627 | 0 |
| 2 | 37422 | 135 | 0.395035 | 0 | 35.981628 | 0 |
| 3 | 56628 | 139 | 0.366700 | 0 | 222.223433 | 1 |
| 4 | 45000 | 445 | 0.395035 | 0 | 35.981588 | 0 |

Limiares congelados: IF 0,615824439899627; LOF 91,08685969933371.
A decisão é score >= limiar. Scores não são probabilidades e suas escalas
não devem ser comparadas diretamente entre os modelos. O LOF nativo sinalizou
4/4, mas no limiar operacional sinalizou 1/4; o comparativo usa apenas o operacional.

## Cobertura e limites da conclusão

- LAB08: 42 pacotes, 30 grupos de endpoints; CSV representa 16 pacotes (38,10%)
  em quatro grupos (13,33%). Os 26 grupos de um SYN não foram exportados.
- Nenhuma predição foi produzida para os grupos não exportados. A auditoria
  original de extração parcial permanece intacta; a nova autorização está no
  manifesto de inferência e em cada registro de entrada/saída.
- Os quatro registros não têm payload. LAB03–LAB06 incluem registros com
  payload e segmentos finais sem payload; a segmentação afeta a comparação.
- A divergência semântica entre o V4 e as features históricas, especialmente
  as flags, continua não resolvida. Não houve clipping, imputação ou ajuste
  dos modelos para melhorar o resultado.
- Atividade de reconhecimento conhecida no nível da sessão não equivale a
  rotulagem independente de cada segmento. Não se calculam precisão, recall,
  F1, FPR, acurácia ou taxa de detecção da sondagem inteira.
- Os modelos analisam registros individuais; este ensaio não valida um
  detector temporal que correlacione todas as portas da varredura.
- Um único cenário de reconhecimento não representa força bruta, malware,
  exploração ou negação de serviço. A proteção do firewall e os alertas de
  aprendizado de máquina são resultados distintos.

## Discussão para o artigo

Nos cenários HTTP sintéticos, o Isolation Forest apresentou menor sinalização
que o LOF, incluindo ausência de alertas nos cenários de arquivos pequenos e
médios. Entretanto, no recorte exportado da sessão de reconhecimento, o
Isolation Forest não sinalizou nenhum dos quatro registros, enquanto o LOF
sinalizou um. Esse contraste evidencia que menor sinalização no tráfego benigno
não demonstra, isoladamente, maior capacidade de identificar atividades de
reconhecimento. A cobertura parcial da extração, a amostra reduzida e as
diferenças de representação das features impedem estabelecer superioridade
geral entre os modelos ou estimar a detecção da varredura completa. Os
resultados devem ser apresentados como avaliação exploratória de transferência
dos modelos treinados no CIC-IDS2017 para capturas controladas do laboratório.

## Rastreabilidade

O JSON homônimo contém hashes dos manifestos e da auditoria, identidade dos
modelos, ponto operacional, contagens por grupo de payload e decisões individuais.
Os hashes das saídas foram conferidos antes da consolidação. Nenhuma predição
benigna foi refeita ou alterada. Não houve treino, calibração ou escrita em banco.
As divergências já conhecidas dos JSONs auxiliares de metadados permanecem
registradas no manifesto; esses JSONs não são usados para inferência. Os hashes
dos modelos joblib foram verificados. Avisos de localização do Python e WMIC
não impediram a execução; o manifesto registra as versões do ambiente.

Para reproduzir em saída nova: `python compare_lab08_subset.py --output-prefix
reports/lab/lab08_subset_comparison_recheck` (comando em uma única linha).
