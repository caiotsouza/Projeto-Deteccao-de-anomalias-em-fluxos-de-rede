# Marco 10 — inventário final de artefatos

Status: **concluído**.

Este relatório cataloga os modelos, métricas, tabelas e gráficos já produzidos. Nenhum modelo foi carregado, retreinado ou modificado; nenhuma previsão, métrica ou calibração foi refeita.

## Integridade

- Artefatos de origem: 47
- Tamanho total indexado: 47923777 bytes
- Figuras catalogadas: 17
- Modelos registrados: 4
- Digest agregado: `1ca51d7a053efc3acc5f30590346255260c8cba0b90f502fe5b888ac3a027de0`

## Modelos registrados

| Experimento | Modelo | Treino | Modelo serializado |
|---|---|---:|---|
| Baseline 20k | Isolation Forest | 20000 | [isolation_forest.joblib](../../models/isolation_forest.joblib) |
| Baseline 20k | Local Outlier Factor | 20000 | [lof.joblib](../../models/lof.joblib) |
| Expandido 100k | Isolation Forest | 100000 | [isolation_forest.joblib](../../experiments/scale_100k/models/isolation_forest.joblib) |
| Expandido 100k | Local Outlier Factor | 100000 | [lof.joblib](../../experiments/scale_100k/models/lof.joblib) |

## Métricas no teste

| Experimento | Modelo | Ponto | Precision | Recall | F1 | FPR |
|---|---|---|---:|---:|---:|---:|
| Baseline 20k | Isolation Forest | Nativo | 0.8900 | 0.4062 | 0.5578 | 0.0502 |
| Baseline 20k | Isolation Forest | Calibrado F1 | 0.6740 | 0.9368 | 0.7840 | 0.4531 |
| Baseline 20k | Local Outlier Factor | Nativo | 0.7847 | 0.7275 | 0.7550 | 0.1996 |
| Baseline 20k | Local Outlier Factor | Calibrado F1 | 0.7756 | 0.7418 | 0.7583 | 0.2146 |
| Expandido 100k | Isolation Forest | Nativo | 0.8974 | 0.4106 | 0.5634 | 0.0470 |
| Expandido 100k | Isolation Forest | Calibrado F1 | 0.6798 | 0.9378 | 0.7882 | 0.4417 |
| Expandido 100k | Local Outlier Factor | Nativo | 0.7808 | 0.9168 | 0.8434 | 0.2573 |
| Expandido 100k | Local Outlier Factor | Calibrado F1 | 0.7941 | 0.9018 | 0.8446 | 0.2338 |

## Leitura do resultado

O maior F1 observado entre os candidatos já congelados foi `0.8446`: Expandido 100k, Local Outlier Factor, ponto `validation_f1_calibrated`. Isso é uma descrição do teste, não uma aprovação automática para produção.

Os conjuntos de validação e teste têm prevalência controlada de 50% de ataques. Antes de implantação, o limiar deve ser validado com a prevalência e o orçamento de alertas da rede real.

## Arquivos deste fechamento

- `artifact_inventory.json`: caminho, tamanho, SHA-256 e metadados.
- `model_registry.json`: configuração, limiares, métricas e tempos.
- `metrics_summary.csv`: tabela longa com 16 combinações.
- `figure_catalog.csv`: finalidade, dimensões e hash das figuras.
- `marco_10_manifest.json`: prova de imutabilidade e hashes das saídas.
