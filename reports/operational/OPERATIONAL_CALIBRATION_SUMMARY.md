# Calibração operacional do limiar

## Decisão

O candidato recomendado é **Isolation Forest** no ponto `validation_fpr_operational`, com limiar `0.6158244399` e FPR-alvo de `1.00%`.

A recomendação maximiza o recall de validação entre os modelos que respeitam o mesmo teto de falsos positivos. Ela não usa o teste para escolher o limiar nem para escolher o modelo.

## Resultado no ponto de 1%

| Modelo | Limiar | FPR teste | Precision teste | Recall teste | F1 teste |
|---|---:|---:|---:|---:|---:|
| Isolation Forest | 0.6158244399 | 1.02% | 96.48% | 28.06% | 43.47% |
| Local Outlier Factor | 91.0868596993 | 1.00% | 76.72% | 3.28% | 6.29% |

## Limitações operacionais

- Um FPR de 1% ainda representa cerca de 10.000 fluxos falso-positivos por milhão de fluxos benignos antes da agregação.
- E-mails por fluxo não são recomendados; os eventos devem ser agregados e deduplicados primeiro.
- O tráfego de validação do CICIDS não substitui tráfego temporalmente separado da rede-alvo.
- A precision medida no teste balanceado 50/50 não representa a precision de produção.

Este é um candidato de laboratório, não uma aprovação de produção. O próximo ajuste deve usar uma janela temporal de tráfego benigno da rede-alvo e um orçamento real de alertas por hora/dia.
