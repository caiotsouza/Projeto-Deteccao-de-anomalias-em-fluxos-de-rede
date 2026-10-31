# Marco 12 — Persistência, API e dashboard Grafana

## Estado do marco

Implementação concluída e validada localmente com repositório em memória e
requisições HTTP reais à FastAPI. A execução dos containers MongoDB e Grafana
permanece pendente porque Docker/MongoDB/Grafana não estão instalados no ambiente
em que este pacote foi produzido.

Isso significa que o código, os contratos e a integração interna estão prontos,
mas não se afirma que os containers foram iniciados ou que a página foi renderizada
visualmente nesta máquina.

## Arquitetura implementada

```text
previsões congeladas (Parquet)
        |
        v
replay_to_mongodb.py -- reaplica somente o limiar operacional
        |
        v
MongoDB / repositório em memória -- BSON Date, validador e índices
        |
        v
FastAPI -- cinco endpoints de dashboard + healthchecks
        |
        v
Grafana 12.2.5 + Infinity 4.0.0 -- 11 painéis provisionados
```

O Grafana nunca consulta os Parquets nem o MongoDB diretamente. Ele consulta a
FastAPI; a API fixa internamente a identidade completa do modelo para impedir a
mistura silenciosa de versões, pontos operacionais ou limiares.

## Identidade operacional congelada

- experimento: `expanded_100k`;
- modelo: `isolation_forest`;
- SHA-256: `d6f7754e14bbc7adb453eb298559efeebdccad98f59143283dc74a78211b4f40`;
- ponto operacional: `validation_fpr_operational`;
- limiar: `0.615824439899627`;
- regra positiva: `anomaly_score >= threshold`.

O `anomaly_score` é um escore de ordenação: **não é probabilidade**. A regra usa
comparação inclusiva (`>=`) com o limiar operacional selecionado apenas na validação.

## Validação integrada com 5.000 registros

Primeira ingestão:

- tentados: 5.000;
- inseridos: 5.000;
- duplicados: 0;
- conflitos: 0.

Repetição idêntica:

- inseridos: 0;
- reconhecidos como duplicados: 5.000;
- conflitos: 0.

Resultado observado pela API:

- fluxos: 5.000;
- normais previstos: 4.292;
- anomalias previstas: 708;
- taxa sinalizada no replay: 0,141600;
- P95 do anomaly score: 0,642758;
- buckets temporais: 17;
- todos os sete checks HTTP: status 200;
- todas as reconciliações numéricas e metodológicas: aprovadas.

Esses números descrevem apenas decisões do modelo nos primeiros
5.000 registros do teste balanceado. Eles não são novas
métricas supervisionadas e não estimam a prevalência natural de ataques.

## Garantias do replay

1. Carrega previsões já congeladas; o modelo `.joblib` não é desserializado.
2. Não lê as colunas `Label` nem `binary_label` do Parquet de proveniência.
3. Recalcula `record_hash` nas 60 features e compara com previsão/proveniência.
4. Usa `event_id` determinístico, início fixo e namespace fixo.
5. Normaliza timestamps para milissegundos, precisão do BSON Date.
6. Faz upsert idempotente e rejeita o mesmo `event_id` com conteúdo divergente.
7. Preserva somente referência criptográfica curta do arquivo-fonte; o nome do
   cenário não é persistido nem exibido.
8. Não fabrica IP nem protocolo; `destination_port` vem da feature real.
9. Verifica os hashes das fontes antes e depois do replay.
10. Verifica a proteção do relatório antes de qualquer escrita no repositório.

## Persistência MongoDB

O inicializador aplica:

- timestamps exclusivamente como BSON Date;
- validação estrita dos objetos `model`, `classification` e `context`;
- índice único de `event_id`;
- índice temporal;
- índices para anomalias recentes, IP de origem e porta de destino;
- recusa explícita de índice TTL não autorizado.

O modo em memória reproduz a semântica idempotente para testes. A ausência de uma
execução MongoDB real está registrada no manifesto, e não é ocultada por um status
genérico de sucesso.

## API entregue

- `GET /api/v1/dashboard/overview`;
- `GET /api/v1/dashboard/timeseries`;
- `GET /api/v1/dashboard/breakdowns`;
- `GET /api/v1/anomalies/recent`;
- `GET /api/v1/model/status`;
- `GET /health/live` e `GET /health/ready`.

As janelas seguem `[start, end)`, datas sem fuso são rejeitadas, o máximo é 31
dias e nenhuma métrica agregada é publicada quando a leitura ultrapassa o limite
seguro de 100 mil documentos. Janelas vazias retornam HTTP 200 com zeros/listas
vazias e `p95 = null`, nunca `NaN`.

## Dashboard provisionado

O contrato Grafana foi aprovado com 11 painéis,
IDs únicos, datasource `tcc-fastapi`, UTC e atualização de 30 segundos. Os painéis
mostram volume, anomalias previstas, taxa sinalizada, P95, duas séries temporais,
dimensões, portas, eventos recentes e identidade do modelo.

Os painéis de protocolo e IP deixam explícito que a dimensão está indisponível.
Eles recebem lista vazia da API, evitando que `unknown` seja interpretado como um
protocolo ou endereço real.

## Como executar quando Docker estiver disponível

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item infra/.env.example infra/.env
# substitua a senha em infra/.env
docker compose --env-file infra/.env -f infra/compose.yaml config
docker compose --env-file infra/.env -f infra/compose.yaml up -d --build
python replay_to_mongodb.py --limit 5000 --overwrite-report
```

Depois, use `http://127.0.0.1:8000/docs` e `http://127.0.0.1:3000`.

## Limitações que continuam deliberadamente abertas

- o teste é balanceado 50/50;
- os timestamps são simulados;
- não há IP ou protocolo no split processado;
- o ponto operacional ainda não foi calibrado com tráfego benigno temporal e
  orçamento real de alertas;
- a composição MongoDB sem autenticação é somente para demonstração local em
  `127.0.0.1`;
- é necessária validação externa do Compose, do plugin Infinity, do datasource e
  da renderização dos painéis em uma máquina com Docker.
