# Comparacao descritiva das 60 features

Referencia: 100,000 registros; 60 features; referencia LOF confirmada.

Participacao geometrica abaixo NAO e importancia causal ou fracao do score.

| Sessao | Grupo | Segmentos | Mediana ACK | Maximo ACK no treino | ACK: parcela geometrica |
| --- | --- | ---: | ---: | ---: | ---: |
| lab02_http | with_payload | 10 | 6 | 1 | 48.46% |
| lab02_http | zero_payload | 10 | 3 | 1 | 82.79% |
| lab03_small_r1 | with_payload | 30 | 18 | 1 | 82.04% |
| lab03_small_r1 | zero_payload | 30 | 3 | 1 | 82.85% |
| lab04_medium_r1 | with_payload | 12 | 198 | 1 | 99.26% |
| lab04_medium_r1 | zero_payload | 12 | 7 | 1 | 97.91% |
| lab05_slow_r1 | with_payload | 6 | 1518.5 | 1 | 99.88% |
| lab05_slow_r1 | zero_payload | 6 | 19.5 | 1 | 99.35% |
| lab06_serverpaced_r1 | with_payload | 6 | 1679.5 | 1 | 99.31% |
| lab06_serverpaced_r1 | zero_payload | 6 | 3.5 | 1 | 88.66% |

Os 60 campos por grupo estao em diagnostics.json. Nenhum limiar/modelo foi alterado.
