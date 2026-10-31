# Infraestrutura do Marco 12

Este diretório provisiona três serviços locais:

```text
MongoDB : 127.0.0.1:27017
FastAPI : http://127.0.0.1:8000
Grafana : http://127.0.0.1:3000
```

O Grafana consulta a FastAPI pelo datasource Infinity. A API consulta somente
documentos que coincidam com modelo, SHA-256, ponto operacional, limiar e regra
positiva ativos.

A imagem da API usa `requirements.lock.txt`, com todas as versões Python
congeladas conforme o ambiente validado no Marco 12. O `requirements.txt`
continua sendo a especificação flexível para desenvolvimento.

## Pré-requisitos

1. Docker Desktop com Docker Compose.
2. Python 3.12 e o ambiente virtual do projeto para executar o replay no host.
3. Acesso à internet na primeira inicialização para baixar as imagens e o
   plugin Infinity.
4. Portas 27017, 3000 e 8000 livres.

Prepare as dependências Python no PowerShell, a partir da raiz do projeto:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -c "import pandas, pyarrow, pymongo; print('Dependências disponíveis')"
```

## Inicialização

No PowerShell, a partir da raiz do projeto:

```powershell
Copy-Item infra/.env.example infra/.env
# Edite infra/.env e substitua a senha de exemplo.
docker compose --env-file infra/.env -f infra/compose.yaml config
docker compose --env-file infra/.env -f infra/compose.yaml up -d --build
docker compose --env-file infra/.env -f infra/compose.yaml ps
```

O serviço one-shot `mongo-init` cria/aplica automaticamente o schema e os cinco
índices antes que a API seja iniciada. Para repetir essa verificação manualmente:

```powershell
$env:TCC_MONGODB_URI = "mongodb://127.0.0.1:27017"
python initialize_mongodb.py
```

Carregue 5.000 previsões congeladas:

```powershell
python replay_to_mongodb.py --limit 5000 --network-context-dir .\data\reference\generated_labelled_flows --overwrite-report
```

Executar novamente o mesmo comando não cria duplicatas. A data e o namespace
padrão são congelados (`2026-01-01T00:00:00Z` e
`cicids2017-test-expanded-100k-v1`), portanto o mesmo comando continua
idempotente também em dias diferentes. Para criar outra sessão experimental,
informe ambos explicitamente:

```powershell
python replay_to_mongodb.py `
  --limit 5000 `
  --network-context-dir .\data\reference\generated_labelled_flows `
  --start-time "2026-09-06T00:00:00Z" `
  --namespace "demonstracao-tcc-v1" `
  --overwrite-report
```

Depois, abra:

- documentação da API: http://127.0.0.1:8000/docs
- dashboard: http://127.0.0.1:3000

O intervalo inicial do dashboard cobre de `2026-01-01T00:00:00Z` a
`2026-01-02T04:00:00Z`, suficiente para os 100 mil registros espaçados em um
segundo. Ajuste o seletor de tempo apenas se usar outro `--start-time`.

## Encerramento recuperável

```powershell
docker compose --env-file infra/.env -f infra/compose.yaml down
```

O comando preserva os volumes. Não acrescente `--volumes` a menos que a
remoção permanente dos dados tenha sido deliberadamente autorizada.

## Limites metodológicos

- o replay não lê `Label` nem `binary_label`;
- o tempo é uma sequência simulada;
- o teste do CICIDS está balanceado 50/50;
- IPs e protocolo não existem nos dados processados. Eles só são adicionados
  quando o replay recebe CSVs `GeneratedLabelledFlows` e valida cada linha
  contra as features de `X_test`; valores não são fabricados;
- somente `destination_port` e estatísticas de fluxo realmente disponíveis são
  levadas ao contexto;
- o modo continua experimental e não está aprovado para produção.

## Limite de segurança da composição local

MongoDB, FastAPI e Grafana são publicados exclusivamente em `127.0.0.1`.
O MongoDB desta composição não usa autenticação para simplificar a banca local;
por isso, não exponha essa composição em rede compartilhada ou produção. O
Grafana exige senha definida em `infra/.env`, e a API roda no container com
usuário não privilegiado.
