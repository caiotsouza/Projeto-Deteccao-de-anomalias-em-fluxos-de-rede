# Diagnóstico descritivo das 60 features — primeiras sessões

## Objetivo e referência

Comparar as capturas locais com a distribuição efetivamente utilizada pelo
modelo, sem alterar os dados para obter menos alertas. Foram examinadas cinco
sessões (LAB02 e LAB03–LAB06/r1), 128 segmentos V4, separados entre segmentos
com payload e sem payload. As referências são os 100.000 registros benignos
de `experiments/scale_100k/data/splits/X_train.parquet`, com as 60 colunas na
ordem do manifesto de treinamento.

O programa `analyze_lab_features.py` verifica os hashes dos dois modelos e das
saídas de inferência, a identidade das decisões armazenadas e os limiares.
Carrega o scaler já ajustado do pipeline LOF e usa somente `transform`.
A matriz transformada foi comparada à referência interna `_fit_X` do LOF:
diferença absoluta máxima **0,0**, tolerância de comparação 1e-12. O acesso a
esse atributo privado é apenas diagnóstico e pode exigir revisão ao mudar a
versão do scikit-learn. Não executar `fit` ou `fit_transform` nas capturas.

## Cálculos produzidos

Para cada feature são registrados mínimo, máximo, média, desvio-padrão
populacional, quartis, p01/p99, cardinalidade e quantidade de valores negativos
do treino. Para cada grupo local: mínimo, mediana, máximo, moda, frequência da
moda no treino, posição empírica da mediana e contagens fora dos intervalos
mínimo–máximo e p01–p99 históricos. Os dois limites da posição empírica tratam
empates; não são um intervalo de confiança. Estar fora de p01–p99 não é uma
regra adicional de alerta nem um teste estatístico de drift.

Também são consultados os 20 vizinhos reais do LOF, na geometria euclidiana
após o scaler congelado. Para cada registro e feature, calcula-se a média do
quadrado da diferença para esses vizinhos. A soma por dimensão é conferida
contra as distâncias fornecidas pelo estimador. A participação agrupada divide
a soma de cada dimensão pela soma de todas elas; registros mais distantes
pesam mais. A mediana da participação individual também fica disponível.

O [StandardScaler](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html)
usa a média e o desvio aprendidos no treino. Já o
[LOF](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html)
calcula desvio de densidade local em relação aos vizinhos. Logo, a decomposição
da distância não decompõe o score LOF e não mede importância no Isolation Forest.

## Resultado central

ACK, SYN, PSH e FIN variam de 0 a 1 na referência histórica. As capturas V4
apresentam contagens maiores. A diferença observada é compatível com a
divergência de representação já investigada entre extratores, não prova de
ataque. Nem mesmo o mesmo nome de coluna garante equivalência semântica.

| Sessão | Segmentos com payload | Mediana ACK | ACK: participação geométrica agrupada |
| --- | ---: | ---: | ---: |
| LAB02 | 10 | 6 | 48,46% |
| LAB03/r1 | 30 | 18 | 82,04% |
| LAB04/r1 | 12 | 198 | 99,26% |
| LAB05/r1 | 6 | 1.518,5 | 99,88% |
| LAB06/r1 | 6 | 1.679,5 | 99,31% |

O máximo ACK no treino é 1 e o desvio-padrão é aproximadamente 0,4626.
Valores elevados em V4 ficam, portanto, muito afastados nessa dimensão após
a padronização congelada. No LAB06, 99,31% refere-se exclusivamente à distância
quadrática agrupada dos segmentos com payload para os vizinhos consultados.
Não significa “99,31% do score”, explicação causal ou taxa de detecção.

Outras diferenças também permanecem no relatório completo. Por exemplo,
`min_seg_size_forward` contém cinco valores negativos na referência histórica,
com mínimo -83.885.313; essa característica altera a escala aprendida e é uma
limitação dos dados históricos. Nenhum valor foi corrigido ou removido. Nem todo
valor negativo em outras colunas é necessariamente inválido: há sentinelas.

## Evidências e reprodução

- `feature_diagnostics_r1/diagnostics.json`: 60 features × dez grupos, vizinhos,
  participações por registro e hashes dos arquivos protegidos.
- `feature_diagnostics_r1/SUMMARY.md`: tabela resumida dos dez grupos.
- `feature_diagnostics_r1/flags_and_lof_geometry.png`: figura comparativa.
- `src/lab_feature_diagnostics.py`: funções de cálculo, sem ajuste de modelos.
- `tests/test_lab_feature_diagnostics.py`: nove testes novos.

Na raiz do projeto, para uma nova execução preservando a primeira:

```powershell
.\.venv\Scripts\python.exe -B analyze_lab_features.py --output-dir reports/lab/feature_diagnostics_r1_recheck
.\.venv\Scripts\python.exe -B -m unittest tests.test_lab_feature_diagnostics tests.test_lab_v4_adapter tests.test_lab_flow_audit tests.test_benign_capture_validation -v
```

A pasta de saída deve ser nova. Nesta etapa passaram **36 testes**, incluindo
empates, valores não finitos, ordem das colunas, índices inválidos, reconstrução
de distâncias, distância zero e ponderação dos registros. O gráfico foi
inspecionado visualmente; aumentou-se a margem superior para não sobrepor os
rótulos ao título.

Os hashes dos modelos joblib coincidem com o registro operacional. Persistem
avisos anteriores: os dois JSONs auxiliares de metadados divergem dos hashes
registrados; esses JSONs não são usados na inferência e não foram alterados.
A identidade do scaler foi conferida no próprio pipeline carregado.

## Conclusões permitidas e limites

Há evidência descritiva de divergência entre a representação do treino e a V4.
Não se demonstrou que flags sejam a única causa dos alertas, nem que uma troca
isolada dessas features tornaria o sistema válido. Não houve clipping para
0/1, seleção de linhas, novo treino, calibração ou uso dos conjuntos de
validação/teste. As predições existentes foram lidas, não recalculadas.

O treino tem tráfego heterogêneo; a amostra local é pequena, correlacionada e
restrita a HTTP sintético. Percentuais de segmentos sinalizados continuam sendo
taxas de sinalização exploratórias, não precisão, recall ou FPR estimado em
produção. As repetições r2/r3 servem para verificar estabilidade deste ensaio,
não para conferir representatividade corporativa.

Nenhum banco, rede ou VM foi alterado. Próxima coleta:
`reports/lab/LAB_REPETITIONS_R2_R3.md`.
