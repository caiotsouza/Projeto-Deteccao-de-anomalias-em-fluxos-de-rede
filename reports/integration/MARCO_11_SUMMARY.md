# Marco 11 — preparação para integração e Grafana

Status: **contratos preparados; serviços externos ainda não iniciados**.

A inferência agora pode receber objetos estruturados em memória, sem depender de CSV. O MongoDB, a API FastAPI e o Grafana ainda não são iniciados por este marco.

## Configuração de referência

- Experimento: `expanded_100k`
- Modelo: `isolation_forest`
- Ponto operacional: `validation_fpr_operational`
- Features obrigatórias: 60
- `anomaly_score` é um escore, não uma probabilidade.

## Fluxo planejado

```text
pfSense/Squid -> extrator das 60 features -> serviço de inferência
-> documento de monitoramento -> MongoDB -> FastAPI -> Grafana
```

O extrator das 60 estatísticas de fluxo ainda deverá ser implementado. Logs brutos de pfSense ou Squid não podem ser enviados diretamente ao modelo treinado no CIC-IDS2017.

## Primeira página do Grafana

A especificação contém 11 painéis: volume de fluxos, anomalias, taxa de anomalias, P95 do escore, séries temporais, protocolos, principais origens, portas de destino, anomalias recentes e estado do modelo.

Falsos positivos e famílias de ataque não aparecem como métricas ao vivo porque não existe rótulo verdadeiro imediato e o modelo não faz classificação supervisionada de ataques.

## Arquivos

- `inference_request.schema.json`: entrada esperada pela futura API.
- `inference_response.schema.json`: resposta estável da inferência.
- `mongodb_prediction.schema.json`: documento e índices recomendados.
- `grafana_dashboard_spec.json`: painéis, filtros e endpoints futuros.
- `marco_11_manifest.json`: integridade das fontes e das saídas.
