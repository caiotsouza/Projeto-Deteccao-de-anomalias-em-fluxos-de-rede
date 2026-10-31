# Detecção de anomalias em tráfego de rede

Projeto de TCC para estudar a detecção não supervisionada de anomalias no
tráfego de redes corporativas. A fonte de referência é o CIC-IDS2017. No
laboratório isolado, o OPNsense realiza capturas PCAP, posteriormente
processadas pelo CICFlowMeter V4 para a análise exploratória dos fluxos.

As frentes avaliadas permanecem separadas:

```text
CIC-IDS2017 -> pré-processamento e seleção de 60 features -> treino e avaliação IF/LOF

Laboratório -> captura PCAP no OPNsense -> CICFlowMeter V4
            -> auditoria de features e cobertura -> inferência exploratória IF/LOF

Previsões históricas congeladas -> replay com horários simulados
                               -> MongoDB -> FastAPI -> Grafana
```

A análise das capturas locais é offline e não representa integração contínua
do laboratório ao dashboard. O atendimento ao contrato estrutural das 60
features não garante equivalência semântica com os dados históricos; as
limitações de cobertura e de representação são descritas nos relatórios do
laboratório. Esta arquitetura não depende de um servidor proxy.

Este estado do projeto implementa os **Marcos 1 a 12** e um experimento
adicional de escala **20k versus 100k**: estrutura, ambiente
Python, carga, inspeção, pré-processamento, seleção auditável de features,
divisão reproduzível de treino/validação/teste e o primeiro modelo Isolation
Forest, incluindo sua avaliação pós-predição com os rótulos, além do segundo
modelo Local Outlier Factor (LOF). As previsões congeladas dos dois modelos já
foram avaliadas e comparadas nos mesmos registros, sem retreino e sem usar o
teste para selecionar limiares. O experimento adicional repete o fluxo em uma
pasta isolada, com cinco vezes mais registros em cada split, e preserva o
baseline original para uma comparação auditável. O Marco 11 acrescenta uma
camada de inferência para objetos estruturados. O Marco 12 implementa a
persistência do replay no MongoDB, as consultas FastAPI e o provisionamento do
Grafana, sem representar monitoramento contínuo em produção. As capturas e
avaliações exploratórias do laboratório complementam esses marcos.

## Materiais do artigo e reprodução

O repositório público do TCC está em
[Projeto Detecção de anomalias em fluxos de rede](https://github.com/caiotsouza/Projeto-Deteccao-de-anomalias-em-fluxos-de-rede).
O [guia de materiais complementares](docs/reproducibilidade/README.md) relaciona
os quadros e figuras do artigo aos respectivos dados, relatórios e manifestos.
O [artigo revisado](docs/artigo/artigo_tcc_revisao_orientador_20261031.docx)
está na cópia pública, em `docs/artigo/`.

A publicação inclui código, resultados derivados, modelos congelados e capturas
controladas do laboratório. Os CSVs originais do CIC-IDS2017 devem ser obtidos
na fonte oficial; nomes e hashes estão no manifesto de dados originais.
Credenciais, áudio e parecer privado, ambientes virtuais e imagens de desktop
não integram a distribuição. Os originais locais não foram alterados pelo
processo de preparação da cópia pública.

Para conferir a integridade da cópia publicada, execute
`python tools/verify_publication.py` na raiz do checkout. Arquivos `.joblib`
devem ser carregados somente quando sua origem for confiável; conferir o hash
verifica a identidade do arquivo, não torna seguro um objeto de origem desconhecida.

## Estrutura

```text
tcc-network-anomaly/
|-- data/
|   |-- raw/                  # CSVs originais do CIC-IDS2017
|   `-- processed/            # splits e previsões sem rótulos em Parquet
|-- models/                   # modelo joblib e metadados de treinamento
|-- notebooks/                # exploração opcional, sem lógica definitiva
|-- reports/
|   |-- figures/              # gráficos científicos gerados por marco
|   |-- metrics/              # relatórios e métricas em JSON
|   |-- final/                # inventário auditável gerado no Marco 10
|   `-- integration/          # contratos MongoDB/FastAPI/Grafana do Marco 11
|-- src/
|   |-- __init__.py
|   |-- config.py             # caminhos e constantes
|   |-- inspect_data.py       # diagnóstico de qualidade
|   |-- load_data.py          # descoberta, leitura e concatenação
|   |-- preprocessing.py      # políticas de limpeza do Marco 3
|   |-- feature_selection.py  # análise, seleção e manifesto do Marco 4
|   |-- data_split.py         # amostragem e divisão sem vazamento do Marco 5
|   |-- isolation_forest.py   # treino e inferência sem rótulos do Marco 6
|   |-- local_outlier_factor.py # StandardScaler + LOF novelty do Marco 8
|   |-- evaluation.py         # associação, métricas e figuras do Marco 7
|   |-- model_comparison.py   # avaliação pareada IF x LOF do Marco 9
|   |-- scale_experiment.py   # comparação auditável 20k x 100k
|   |-- artifact_inventory.py # registro e integridade do Marco 10
|   |-- inference_service.py  # inferência estruturada independente de CSV
|   |-- dashboard_reporting.py # documento e agregações para dashboards
|   |-- integration_contracts.py # schemas e desenho inicial do Grafana
|   `-- utils.py              # logging, normalização e JSON
|-- tests/
|   |-- test_data_split.py
|   |-- test_evaluation.py
|   |-- test_feature_selection.py
|   |-- test_isolation_forest.py
|   |-- test_lof.py
|   |-- test_model_comparison.py
|   |-- test_scale_experiment.py
|   |-- test_artifact_inventory.py
|   |-- test_inference_service.py
|   |-- test_integration_contracts.py
|   |-- test_marcos_1_2.py
|   `-- test_preprocessing.py
|-- experiments/
|   `-- scale_100k/           # splits, modelos, métricas e figuras isolados
|-- main.py                   # inspeção sem alterar registros
|-- preprocess.py             # limpeza e persistência dos dados derivados
|-- select_features.py        # seleção reproduzível das features
|-- create_splits.py          # criação de treino, validação e teste
|-- train_isolation_forest.py # treinamento do primeiro modelo
|-- evaluate_isolation_forest.py # avaliação posterior com os rótulos
|-- train_lof.py              # treinamento e inferência do LOF
|-- evaluate_models.py        # avaliação do LOF e comparação dos modelos
|-- run_scale_100k.py         # execução completa do experimento de escala
|-- finalize_artifacts.py     # inventário final sem retreinamento
|-- prepare_integration.py    # gera contratos e especificação dos painéis
|-- predict_json.py           # inferência em objeto/lote JSON
|-- requirements.txt
`-- README.md
```

Cada módulo foi adicionado apenas em seu respectivo marco. Isso evita arquivos
vazios e mantém o histórico do projeto alinhado à metodologia incremental do
TCC.

## Dataset

Use os arquivos CSV de *MachineLearningCSV* do CIC-IDS2017. Copie um ou vários
arquivos diretamente para:

```text
data/raw/
```

Os CSVs são ignorados pelo Git para evitar versionar dados grandes. Os dados
originais nunca são alterados pelo código dos Marcos 1 a 8.

## Preparação do ambiente no Windows PowerShell

Execute os comandos a partir da raiz `tcc-network-anomaly`:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Se a política do PowerShell bloquear a ativação, execute apenas na sessão atual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Erro `ModuleNotFoundError`

Se a execução informar que `pandas`, `pyarrow` ou outro módulo não existe,
confirme primeiro qual Python está ativo:

```powershell
python -c "import sys; print(sys.executable)"
python -m pip show pandas pyarrow scikit-learn
```

O primeiro comando deve apontar para:

```text
tcc-network-anomaly\.venv\Scripts\python.exe
```

Se apontar para uma instalação global, como `C:\Python314\python.exe`, crie ou
ative a `.venv` e instale as dependências nela. Use sempre
`python -m pip install ...`; dessa forma, o `pip` pertence ao mesmo Python que
executará os scripts.

## Inspeção — Marco 2

Inspecionar todos os CSVs de `data/raw/`:

```powershell
python main.py
```

Validar primeiro com no máximo 10.000 linhas por arquivo:

```powershell
python main.py --nrows-per-file 10000
```

Ler somente um CSV pelo nome:

```powershell
python main.py --pattern "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
```

Ler CSVs também dentro de subpastas:

```powershell
python main.py --recursive
```

Ver todos os parâmetros:

```powershell
python main.py --help
```

O limite `--nrows-per-file` seleciona as primeiras N linhas de cada arquivo e é
destinado apenas a testes da carga. O console e o JSON registram explicitamente
esse limite. Essa opção ainda não realiza amostragem estratificada e não deverá
ser usada, sozinha, na futura avaliação dos modelos.

## Resultado esperado

A execução lista os arquivos selecionados e apresenta:

- número de registros e colunas;
- tipo inferido de cada coluna;
- uso estimado de memória do DataFrame;
- total e distribuição dos valores ausentes;
- total e distribuição dos valores infinitos nas colunas numéricas;
- quantidade de registros duplicados;
- distribuição da coluna `label`;
- features de texto que parecem numéricas e merecem conversão no Marco 3.

O relatório completo é salvo em:

```text
reports/metrics/dataset_inspection.json
```

Os nomes das colunas são normalizados em memória para `snake_case`, sem espaços
nas extremidades e sem acentos. Por exemplo, `" Flow Duration "` se torna
`flow_duration` e `" Label "` se torna `label`. Colisões de nomes após a
normalização interrompem a execução em vez de sobrescrever dados silenciosamente.

Nenhum registro é excluído. `NaN`, `inf`, `-inf`, duplicatas e possíveis erros
de tipo são apenas reportados para orientar o Marco 3.

## Pré-processamento — Marco 3

O Marco 3 cria uma cópia tratada do dataset. Os CSVs de `data/raw/` continuam
imutáveis. Para processar somente o arquivo Monday completo:

```powershell
python preprocess.py `
  --pattern "Monday-WorkingHours.pcap_ISCX.csv" `
  --output-prefix monday
```

Para validar o fluxo com apenas 10.000 linhas, sem usar a amostra no modelo:

```powershell
python preprocess.py `
  --pattern "Monday-WorkingHours.pcap_ISCX.csv" `
  --nrows-per-file 10000 `
  --output-prefix monday_sample
```

O comando completo gera:

```text
data/processed/monday_features.parquet
data/processed/monday_labels.parquet
reports/metrics/monday_preprocessing.json
```

Features e rótulos são salvos separadamente. A coluna `label` não aparece em
`monday_features.parquet`; ela permanece disponível apenas para a futura
divisão dos dados e avaliação posterior às previsões.

### Políticas de limpeza

1. **Conversão numérica:** uma feature textual é convertida com
   `pandas.to_numeric`. Falhas isoladas são contabilizadas e viram `NaN`. Uma
   coluna inteiramente não numérica interrompe a execução para exigir uma
   decisão metodológica explícita.
2. **Infinitos:** `inf` e `-inf` viram `NaN`, com contagem por coluna e sinal.
3. **Linhas inválidas:** linhas que ainda contêm `NaN` em alguma feature ou não
   possuem rótulo são removidas e contabilizadas. Não se aplica mediana neste
   marco, pois ajustar uma imputação antes da divisão treino/teste causaria
   vazamento de informação.
4. **Duplicatas exatas:** são removidas antes da futura divisão para impedir que
   uma mesma observação apareça simultaneamente em treino e teste.
5. **Features constantes, quase constantes ou idênticas:** são reportadas, mas
   mantidas. A decisão sobre sua remoção pertence ao Marco 4. Isso evita excluir
   uma flag que seja constante no tráfego normal, mas mude durante um ataque.
6. **Tipos eficientes:** inteiros são reduzidos para o menor tipo que comporte
   todos os valores e `float64` é convertido para `float32`. Use
   `--keep-float64` para desativar a conversão de floats.
7. **Persistência:** Parquet com compressão Snappy preserva tipos, ocupa menos
   espaço e é mais rápido para recarregar do que CSV.

Por segurança, artefatos existentes não são substituídos automaticamente. Para
regenerar conscientemente os mesmos arquivos:

```powershell
python preprocess.py `
  --pattern "Monday-WorkingHours.pcap_ISCX.csv" `
  --output-prefix monday `
  --overwrite
```

As opções `--drop-constant-columns` e `--drop-duplicate-columns` existem para
experimentos, mas não devem ser usadas antes da decisão documentada do Marco 4.

### Resultado obtido com Monday

- 529.918 registros e 78 features na entrada;
- 810 infinitos substituídos por `NaN`;
- 437 linhas inválidas removidas;
- 26.831 duplicatas exatas removidas depois da limpeza;
- 502.650 registros e 78 features na saída;
- 10 features constantes, 6 pares idênticos não constantes e 2 features quase
  constantes reportados, sem remoção de colunas;
- 502.650 rótulos `BENIGN` na saída;
- nenhum `NaN` ou infinito remanescente em `X`;
- memória das features reduzida de aproximadamente 302,958 MB para 120,320 MB
  pelo ajuste seguro dos tipos numéricos.

## Seleção de features — Marco 4

O Marco 4 recebe somente `monday_features.parquet`. O arquivo de rótulos não é
lido e nenhum registro de ataque participa das decisões.

Execute:

```powershell
python select_features.py `
  --features-path "data\processed\monday_features.parquet" `
  --output-prefix monday
```

O comando gera:

```text
data/processed/monday_selected_features.parquet
data/processed/monday_feature_manifest.json
reports/metrics/monday_feature_selection.json
```

### Critérios adotados

1. **Features constantes:** 10 colunas com um único valor no treino normal são
   excluídas. Sem variação, o Isolation Forest não consegue criar divisões que
   aprendam seu comportamento.
2. **Redundâncias comprovadas:** uma feature só é excluída quando a relação com
   a feature mantida é confirmada numericamente com `numpy.allclose`, usando
   `rtol=1e-5` e `atol=1e-6`.
3. **Variância:** `packet_length_variance` é excluída porque corresponde ao
   quadrado de `packet_length_std`, dentro da tolerância numérica.
4. **Quase constantes:** são reportadas e mantidas. Flags TCP raras podem ser
   relevantes na detecção de ataques.
5. **Correlação:** pares com `|Pearson| >= 0,995` são registrados, mas não
   removidos automaticamente. Correlação no tráfego normal não prova que as
   features continuarão equivalentes durante um ataque.
6. **Semântica:** `syn_flag_count` e `fwd_psh_flags` permanecem, apesar de terem
   valores iguais no Monday, pois representam flags TCP diferentes.
7. **Esquema:** o manifesto registra nome, ordem, tipo e SHA-256 das features.
   Os dados dos próximos marcos deverão ser selecionados pelo manifesto, nunca
   por posição numérica ou por uma nova análise independente.

A descrição das features usada como referência está no
[repositório do CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt).

### Features excluídas

Constantes no treino normal:

```text
bwd_psh_flags
fwd_urg_flags
bwd_urg_flags
cwe_flag_count
fwd_avg_bytes_bulk
fwd_avg_packets_bulk
fwd_avg_bulk_rate
bwd_avg_bytes_bulk
bwd_avg_packets_bulk
bwd_avg_bulk_rate
```

Redundantes, com a feature equivalente preservada:

```text
fwd_header_length_1       -> fwd_header_length
subflow_fwd_packets       -> total_fwd_packets
subflow_fwd_bytes         -> total_length_of_fwd_packets
subflow_bwd_packets       -> total_backward_packets
subflow_bwd_bytes         -> total_length_of_bwd_packets
avg_fwd_segment_size      -> fwd_packet_length_mean
avg_bwd_segment_size      -> bwd_packet_length_mean
packet_length_variance    -> packet_length_std
```

### Resultado obtido

- 502.650 registros preservados;
- 78 features analisadas;
- 10 constantes excluídas;
- 8 redundâncias comprovadas excluídas;
- 2 features quase constantes mantidas: `rst_flag_count` e `ece_flag_count`;
- 27 pares altamente correlacionados reportados antes da seleção;
- 8 pares altamente correlacionados mantidos depois da seleção;
- 60 features finais;
- memória do DataFrame recarregado reduzida de 116,486 MB para 96,352 MB;
- nenhum rótulo ou registro de ataque usado;
- fingerprint do esquema:
  `f4bc0bbe1ffd2ef1b9aeb86923eccd4344d8bf38ec76eba4d5cf161258c7c33a`.

Para conjuntos maiores, a correlação pode usar uma amostra explícita e
reproduzível:

```powershell
python select_features.py --correlation-sample-size 100000
```

O relatório registrará o tamanho da amostra e o `random_state`. No resultado
oficial do Monday, todos os 502.650 registros foram usados.

Artefatos existentes não são sobrescritos por padrão. Para regenerar:

```powershell
python select_features.py --output-prefix monday --overwrite
```

## Divisão dos dados — Marco 5

O Marco 5 usa somente tráfego normal do Monday no treino. Validação e teste
recebem tráfego `BENIGN` e ataques dos outros sete CSVs.

Perfil controlado inicial:

| Conjunto | BENIGN | Ataques | Total |
|---|---:|---:|---:|
| Treino | 20.000 | 0 | 20.000 |
| Validação | 5.000 | 5.000 | 10.000 |
| Teste | 10.000 | 10.000 | 20.000 |

Esse volume foi escolhido para permitir a comparação futura com LOF, cuja
busca por vizinhos em 60 dimensões pode ficar muito cara com centenas de
milhares de registros. Todos os tamanhos são parâmetros e podem ser ampliados.

Execute:

```powershell
python create_splits.py
```

Para regenerar artefatos existentes:

```powershell
python create_splits.py --overwrite
```

### Processamento em duas passagens

1. A primeira passagem lê somente `Label`, em blocos de 100.000 linhas, para
   contar as classes e calcular cotas estratificadas.
2. A segunda passagem lê as features, aplica as regras de limpeza do Marco 3,
   seleciona as 60 colunas do manifesto e mantém apenas os candidatos
   necessários para a divisão.

Os 2.300.825 registros externos não ficam simultaneamente na memória. Foram
identificadas 1.294 células ausentes e 3.566 infinitos positivos; 2.430 linhas
inválidas foram removidas, restando 2.298.395 candidatos válidos antes da
amostragem.

### Estratificação dos ataques

As 14 categorias conhecidas são preservadas nos dois conjuntos de avaliação.
Cada categoria recebe pelo menos cinco observações em validação e cinco em
teste quando há disponibilidade. Isso protege classes raras:

```text
Heartbleed:                5 validação + 5 teste (11 originais)
Infiltration:              5 validação + 5 teste (36 originais)
Web Attack - Sql Injection: 5 validação + 5 teste (21 originais)
```

As demais vagas são distribuídas proporcionalmente ao número de ataques de
cada categoria. Os rótulos servem apenas para estratificação e avaliação; nunca
são incluídos em `X`.

### Prevalência controlada

Validação e teste são balanceados em 50% `BENIGN` e 50% ataque. Essa proporção
facilita o benchmark inicial, mas não representa necessariamente uma rede real.
A `precision` calculada posteriormente refletirá essa prevalência artificial.
Por isso, serão especialmente importantes `recall`, F1 e False Positive Rate.

### Tipos numéricos entre diferentes dias

Os tipos compactos do Monday descrevem armazenamento, não limites globais. Por
exemplo, `down_up_ratio` cabe em `int8` no Monday, mas ultrapassa 127 em outro
dia. No Marco 5:

- features inteiras são promovidas para `int64`;
- features decimais são promovidas para `float64`;
- nomes e ordem continuam sendo impostos pelo manifesto do Marco 4.

Isso resultou em 39 features `int64` e 21 `float64`, iguais nos três conjuntos.

### Prevenção de vazamento

Cada observação recebe um hash determinístico de 64 bits calculado somente a
partir das 60 features. O hash é usado para:

- amostragem reproduzível com `random_state=42`;
- remoção de observações idênticas após a seleção de features;
- impedimento de compartilhamento entre treino, validação e teste.

Resultado da auditoria:

```text
treino ∩ validação = 0
treino ∩ teste = 0
validação ∩ teste = 0
ataques no treino = 0
label presente em X = false
```

Fingerprint do esquema de modelagem:

```text
07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4
```

### Artefatos

```text
data/processed/splits/X_train.parquet
data/processed/splits/y_train.parquet
data/processed/splits/X_validation.parquet
data/processed/splits/y_validation.parquet
data/processed/splits/X_test.parquet
data/processed/splits/y_test.parquet
data/processed/splits/split_manifest.json
reports/metrics/data_split_report.json
```

Os arquivos `X_*` contêm somente as 60 features. Os arquivos `y_*` contêm:

- `label`: categoria original normalizada;
- `binary_label`: `0` para BENIGN e `1` para ataque;
- `source_file`: CSV de origem;
- `source_row`: linha de origem ou índice processado do Monday;
- `record_hash`: assinatura usada na auditoria de vazamento.

Para alterar os tamanhos:

```powershell
python create_splits.py `
  --train-benign-size 30000 `
  --validation-benign-size 10000 `
  --validation-attack-size 10000 `
  --test-benign-size 20000 `
  --test-attack-size 20000 `
  --overwrite
```

## Isolation Forest — Marco 6

O Marco 6 treina o primeiro detector de anomalias exclusivamente com
`X_train.parquet`. Esse conjunto foi criado no Marco 5 a partir de 20.000
fluxos `BENIGN` do Monday. O script não recebe caminhos `y_*`, não abre os
arquivos de rótulos e não calcula métricas supervisionadas.

Execute:

```powershell
python train_isolation_forest.py
```

Para regenerar conscientemente todos os artefatos do modelo:

```powershell
python train_isolation_forest.py --overwrite
```

### Validação das entradas

Antes do ajuste, os três conjuntos `X_*` passam pelas mesmas verificações:

1. devem conter exatamente as 60 features do manifesto;
2. nomes e ordem das colunas devem coincidir;
3. os tipos devem gerar o mesmo fingerprint SHA-256 do Marco 5;
4. todas as features devem ser numéricas;
5. não pode existir `NaN`, `inf` ou `-inf`.

O modelo, a ordem das features e o fingerprint são salvos juntos no arquivo
`joblib`. Uma aplicação futura deverá reaplicar essas verificações antes de
enviar novos fluxos para inferência.

### Hiperparâmetros do baseline

```text
n_estimators = 200
max_samples = 2048
contamination = "auto"
max_features = 1.0
bootstrap = false
random_state = 42
n_jobs = -1
```

- **200 árvores:** reduz a variação causada pelos cortes aleatórios sem tornar
  o primeiro experimento pesado.
- **2.048 amostras por árvore:** permite que cada árvore observe uma parcela
  mais detalhada dos 20.000 registros. É maior que o valor automático usual de
  256, mas ainda limita o custo de cada árvore.
- **`contamination="auto"`:** não força uma porcentagem de ataques no treino,
  pois o conjunto foi construído como normal. Nessa política, o offset aprendido
  foi `-0,5`; observações com `decision_function < 0` são marcadas como
  anomalias.
- **Todas as features disponíveis:** `max_features=1.0` deixa as 60 features
  disponíveis para cada árvore.
- **Sem reposição:** `bootstrap=false` evita repetir observações dentro da
  amostra de uma árvore.
- **Reprodução e paralelismo:** `random_state=42` permite repetir o experimento,
  enquanto `n_jobs=-1` usa os núcleos disponíveis.

Não foi aplicado `StandardScaler`. O Isolation Forest cria divisões aleatórias
entre os valores mínimo e máximo das features e não calcula distâncias
euclidianas; portanto, escalonar não é necessário para este baseline. Essa
decisão também evita introduzir um transformador sem benefício comprovado.

### Treinamento e inferência

Somente `X_train` participa de `model.fit`. Depois do ajuste, o mesmo modelo
gera previsões para treino, validação e teste. `X_validation` e `X_test` não
alteram árvores, limites ou offset.

Cada arquivo de previsão contém:

- `row_position`: posição original dentro do respectivo `X_*`;
- `record_hash`: chave hexadecimal para a associação segura com `y_*` no
  Marco 7;
- `sklearn_prediction`: `1` para normal e `-1` para anomalia;
- `predicted_anomaly`: convenção do projeto, `0` para normal e `1` para
  anomalia;
- `score_samples`: quanto menor, mais atípica é a observação;
- `decision_function`: valores negativos são classificados como anomalia;
- `anomaly_score`: o negativo de `score_samples`, logo valores maiores indicam
  maior anomalia.

A duplicação das convenções `-1/1` e `0/1` é intencional: ela torna a saída do
scikit-learn auditável e reduz o risco de inverter as classes na avaliação.

### Resultado sem consultar os rótulos

| Conjunto | Registros | Normal previsto | Anomalia prevista | Taxa prevista |
|---|---:|---:|---:|---:|
| Treino | 20.000 | 19.333 | 667 | 3,33% |
| Validação | 10.000 | 7.760 | 2.240 | 22,40% |
| Teste | 20.000 | 15.436 | 4.564 | 22,82% |

O ajuste das 200 árvores levou aproximadamente `0,376 s` no ambiente de
validação. O tempo depende do processador e deve ser interpretado apenas como
registro da execução atual.

Essas contagens não representam acurácia, `precision`, `recall` ou falsos
positivos. Elas dizem apenas quantos fluxos cruzaram o limiar interno do modelo.
Os arquivos `y_*` permaneceram reservados durante o treinamento e só foram
abertos depois que as previsões foram congeladas, no Marco 7.

### Artefatos

```text
models/isolation_forest.joblib
models/isolation_forest_metadata.json
data/processed/predictions/isolation_forest_train_predictions.parquet
data/processed/predictions/isolation_forest_validation_predictions.parquet
data/processed/predictions/isolation_forest_test_predictions.parquet
reports/metrics/isolation_forest_training.json
```

O JSON de metadados documenta configuração, bibliotecas, ordem das features,
fingerprint e SHA-256 do `joblib`. O relatório registra validações de entrada,
tempos, estatísticas dos escores e contagens previstas, além de declarar
explicitamente que os rótulos não foram carregados.

## Avaliação do Isolation Forest — Marco 7

O Marco 7 associa as previsões congeladas do Marco 6 aos rótulos do Marco 5.
O modelo `joblib` não é carregado, retreinado ou modificado nesta etapa.

Execute:

```powershell
python evaluate_isolation_forest.py
```

Como os resultados oficiais já existem, use `--overwrite` para reproduzi-los:

```powershell
python evaluate_isolation_forest.py --overwrite
```

### Ordem metodológica

1. O SHA-256 do modelo é comparado com o relatório do Marco 6.
2. Previsões e rótulos de validação são associados um-para-um por
   `record_hash`.
3. São conferidas a orientação do escore e as conversões `-1/1` e `0/1`.
4. O limiar que maximiza F1 é calculado somente com a validação.
5. O limiar é congelado em `anomaly_score >= 0,334933360955919`.
6. Somente depois dessa decisão o arquivo `y_test.parquet` é aberto.
7. O limiar congelado é aplicado uma única vez ao teste.

Essa ordem impede que o desempenho do teste influencie a escolha do ponto
operacional. A avaliação mantém dois resultados:

- **original:** usa diretamente `decision_function < 0`, equivalente a
  `anomaly_score > 0,5` neste modelo;
- **calibrado por F1:** usa o limiar escolhido na validação. Ele é um cenário
  experimental secundário e não substitui silenciosamente o baseline.

A regra `score >= threshold` segue a definição da
[`precision_recall_curve`](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.precision_recall_curve.html)
do scikit-learn. Como ataque é a classe positiva, `anomaly_score` é usado sem
inversão: valores maiores significam maior evidência de anomalia.

### Métricas de validação

| Ponto operacional | TN | FP | FN | TP | Precision | Recall/TPR | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Original | 4.803 | 197 | 2.957 | 2.043 | 0,9121 | 0,4086 | 0,5644 | 0,0394 |
| Calibrado por F1 | 2.722 | 2.278 | 294 | 4.706 | 0,6738 | 0,9412 | 0,7854 | 0,4556 |

### Métricas finais de teste

| Ponto operacional | TN | FP | FN | TP | Precision | Recall/TPR | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Original | 9.498 | 502 | 5.938 | 4.062 | 0,8900 | 0,4062 | 0,5578 | 0,0502 |
| Calibrado por F1 | 5.469 | 4.531 | 632 | 9.368 | 0,6740 | 0,9368 | 0,7840 | 0,4531 |

No teste, o limiar original é conservador: quando sinaliza uma anomalia,
possui alta `precision`, mas perde 59,38% dos ataques. O limiar calibrado reduz
os falsos negativos de 5.938 para 632 e alcança recall de 93,68%, porém marca
45,31% dos fluxos normais como anômalos.

Assim, o limiar calibrado melhora F1, mas ainda não é automaticamente adequado
para produção. Em uma rede corporativa, esse FPR poderia gerar alertas em
excesso. A escolha operacional futura deverá considerar uma meta explícita de
falsos positivos, custo de investigação e prevalência real dos ataques.

### Desempenho de ranking

| Conjunto | ROC-AUC | Average Precision |
|---|---:|---:|
| Validação | 0,8265 | 0,8092 |
| Teste | 0,8236 | 0,8095 |

ROC-AUC e Average Precision usam o escore contínuo e não dependem de um único
limiar. Foi utilizada
[`average_precision_score`](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html),
que resume a curva Precision–Recall ponderando a precisão pelo ganho de recall;
ela não é a integração trapezoidal, que poderia ser mais otimista. A ROC-AUC
segue a definição oficial de
[`roc_auc_score`](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.roc_auc_score.html).

### Detecção por categoria no teste

| Categoria de ataque | Registros | Original | Calibrado por F1 |
|---|---:|---:|---:|
| FTP-Patator | 146 | 0,00% | 98,63% |
| SSH-Patator | 110 | 0,00% | 91,82% |
| Web Attack - Brute Force | 32 | 0,00% | 84,38% |
| Web Attack - Sql Injection | 5 | 0,00% | 60,00% |
| PortScan | 2.836 | 0,14% | 99,12% |
| Bot | 40 | 2,50% | 32,50% |
| Web Attack - XSS | 16 | 6,25% | 93,75% |
| DDoS | 2.285 | 19,43% | 84,95% |
| DoS GoldenEye | 188 | 32,98% | 99,47% |
| DoS slowloris | 108 | 61,11% | 98,15% |
| DoS Slowhttptest | 103 | 78,64% | 100,00% |
| Infiltration | 5 | 80,00% | 100,00% |
| DoS Hulk | 4.121 | 82,36% | 94,81% |
| Heartbleed | 5 | 100,00% | 100,00% |

O resultado agregado não representa todas as famílias igualmente. O baseline
original reconhece bem alguns DoS, mas praticamente não reconhece PortScan,
Patator e ataques Web. Taxas calculadas com somente cinco observações, como
Heartbleed e Infiltration, têm grande incerteza e não devem ser generalizadas
isoladamente.

### Tempos registrados

- treinamento das 200 árvores: aproximadamente `0,376 s`;
- inferência da validação: aproximadamente `0,085 s`;
- inferência do teste: aproximadamente `0,155 s`.

Esses tempos foram importados do relatório congelado do Marco 6. Eles dependem
do hardware e das versões das bibliotecas.

### Artefatos do Marco 7

```text
data/processed/evaluation/isolation_forest_validation_evaluated.parquet
data/processed/evaluation/isolation_forest_test_evaluated.parquet
reports/metrics/isolation_forest_evaluation.json
reports/figures/isolation_forest_confusion_matrices.png
reports/figures/isolation_forest_roc_pr_curves.png
reports/figures/isolation_forest_score_distributions.png
```

Os Parquets avaliados preservam escores, rótulos, previsão original e previsão
calibrada. O JSON mantém as matrizes, métricas, resultados por ataque, hashes
de entrada, versões das bibliotecas e declaração de que o teste foi aberto
somente depois da seleção do limiar.

## Local Outlier Factor — Marco 8

O Marco 8 acrescenta um segundo detector não supervisionado: o **Local
Outlier Factor (LOF)**. Assim como no Marco 6, o treinamento lê somente
`X_train.parquet`, que contém 20.000 registros `BENIGN`, e não abre nenhum
arquivo `y_*`. As previsões de validação e teste são persistidas sem a verdade
de referência; os rótulos serão associados somente no Marco 9.

Execute a partir da raiz do projeto:

```powershell
python train_lof.py
```

O script protege os artefatos existentes por padrão. Para repetir
intencionalmente o treinamento e substituí-los:

```powershell
python train_lof.py --overwrite
```

### Por que a padronização foi aplicada

O LOF mede densidades locais a partir das distâncias entre observações. As 60
features possuem ordens de grandeza muito diferentes: algumas são flags
binárias, enquanto durações, contagens e taxas podem alcançar valores muito
altos. Sem padronização, features numericamente grandes dominariam a distância,
mesmo sem serem as mais relevantes para caracterizar a vizinhança.

Foi criado um único `Pipeline` com esta ordem:

```text
dados brutos -> StandardScaler -> LocalOutlierFactor
```

O [`StandardScaler`](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html)
aprendeu média e desvio-padrão **somente em `X_train`**. Validação e teste
receberam apenas `transform`, sem recalcular estatísticas. A auditoria encontrou
zero features com variância nula; após a transformação, a maior média absoluta
do treino foi `1,31e-16` e o maior desvio em relação ao desvio-padrão unitário
foi `2,22e-16`, diferenças compatíveis com precisão de ponto flutuante.

Scaler e LOF foram serializados juntos em `models/lof.joblib`. Isso garante que
uma inferência futura não consiga aplicar acidentalmente outra padronização.

### Configuração do LOF

| Parâmetro | Valor | Papel |
|---|---:|---|
| `n_neighbors` | 20 | quantidade de vizinhos usada para estimar a densidade local |
| `contamination` | `auto` | usa o limiar nativo do algoritmo |
| `novelty` | `True` | permite inferência em registros que não participaram do ajuste |
| `algorithm` | `auto` | deixa o scikit-learn selecionar a estratégia de busca |
| `leaf_size` | 30 | tamanho de folha para estruturas de vizinhança aplicáveis |
| `metric` | `minkowski`, `p=2` | distância euclidiana após a padronização |
| `n_jobs` | -1 | utiliza os núcleos disponíveis na busca de vizinhos |

O valor 20 foi mantido como baseline da implementação oficial do
[`LocalOutlierFactor`](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html).
Não existe `random_state`: para os parâmetros usados, `StandardScaler` e LOF
são determinísticos.

### Regra especial de `novelty=True`

Com `novelty=True`, a própria documentação do scikit-learn determina que
`predict`, `decision_function` e `score_samples` sejam chamados apenas em
dados **inéditos**, não no conjunto usado em `fit`. Por isso:

- o pipeline foi ajustado somente com `X_train`;
- hashes confirmaram sobreposição zero entre treino, validação e teste;
- validação e teste receberam `score_samples` normalmente;
- o treino foi descrito exclusivamente pelo atributo
  `negative_outlier_factor_`, próprio das observações usadas no ajuste;
- nenhum dos três métodos de novidade foi chamado sobre o treino.

Essa separação segue o exemplo oficial de
[`novelty detection com LOF`](https://scikit-learn.org/stable/auto_examples/neighbors/plot_lof_novelty_detection.html).
O diagnóstico do treino não deve ser comparado diretamente às previsões de
novidade: apesar de ambos expressarem densidade local, são calculados em
contextos diferentes.

### Convenções de escores e classes

- `score_samples`: *opposite LOF*; valores menores representam observações mais
  anormais;
- `decision_function`: `score_samples - offset_`; valores negativos são
  anomalias;
- `anomaly_score`: negativo de `score_samples`; valores maiores representam
  maior evidência de anomalia;
- `sklearn_prediction`: `1` para normal e `-1` para anomalia;
- `predicted_anomaly`: conversão explícita para `0` normal e `1` anomalia.

O limiar aprendido foi `offset_ = -1,5`. A previsão binária foi derivada do
mesmo resultado de `score_samples`, evitando repetir a dispendiosa busca de
vizinhos em cada conjunto.

### Resultado sem consultar rótulos

| Conjunto | Registros | Normais pelo LOF | Anomalias pelo LOF | Taxa sinalizada |
|---|---:|---:|---:|---:|
| Treino — diagnóstico interno | 20.000 | 16.871 | 3.129 | 15,65% |
| Validação — dados inéditos | 10.000 | 5.392 | 4.608 | 46,08% |
| Teste — dados inéditos | 20.000 | 10.729 | 9.271 | 46,36% |

Esses números são **quantidades sinalizadas pelo modelo**, não acurácia,
precision, recall ou F1. Como nenhum `y_*` foi carregado, ainda não é possível
afirmar quantos sinais são ataques verdadeiros ou falsos positivos. Essa
avaliação, incluindo a comparação justa com o Isolation Forest nos mesmos
splits, pertence ao Marco 9.

### Tempos registrados

- ajuste do pipeline nas 20.000 observações normais: aproximadamente `2,782 s`;
- inferência da validação: aproximadamente `0,469 s`;
- inferência do teste: aproximadamente `0,511 s`;
- ajuste mais as duas inferências: aproximadamente `3,761 s`.

Esses tempos dependem do hardware, do sistema operacional e das versões das
bibliotecas. A comparação formal de custo com o Isolation Forest será feita no
Marco 9 junto às métricas preditivas.

### Artefatos do Marco 8

```text
models/lof.joblib
models/lof_metadata.json
data/processed/predictions/lof_train_diagnostics.parquet
data/processed/predictions/lof_validation_predictions.parquet
data/processed/predictions/lof_test_predictions.parquet
reports/metrics/lof_training.json
```

O SHA-256 do pipeline congelado é
`1e4a8b96759bcf1844e8884d2d09c2361065d646096b0e6959fd90cd9d8ce382`.
Metadados e relatório registram a ordem das 60 features, o fingerprint do
esquema, os parâmetros, as estatísticas do scaler, a semântica dos escores,
os hashes de entrada, as versões das bibliotecas e a declaração
`labels_loaded: false`.

## Comparação Isolation Forest versus LOF — Marco 9

O Marco 9 associa os rótulos às previsões congeladas dos dois algoritmos e faz
uma comparação pareada. Nenhum `.joblib` é carregado, nenhum modelo é
retreinado e nenhum escore é recalculado. Os SHA-256 dos modelos são
revalidados antes da avaliação.

Execute a partir da raiz do projeto:

```powershell
python evaluate_models.py
```

Os artefatos do Marco 9 são protegidos contra substituição. Para repetir
intencionalmente a avaliação:

```powershell
python evaluate_models.py --overwrite
```

### Ordem de abertura dos dados

A execução respeita esta sequência:

1. valida os relatórios de treinamento e os SHA-256 dos dois modelos;
2. abre `y_validation` e as previsões de validação;
3. associa cada modelo aos mesmos 10.000 rótulos por `record_hash`;
4. escolhe separadamente o melhor limiar de F1 de cada modelo na validação;
5. congela os dois limiares;
6. somente então abre `y_test` e as previsões de teste;
7. avalia os dois modelos nos mesmos 20.000 registros;
8. verifica que o limiar do Isolation Forest reproduz exatamente o Marco 7.

O teste nunca participa da seleção de hiperparâmetros ou limiares. Cada junção
é um-para-um, sem hashes ausentes, duplicados ou fora de ordem.

### Pontos operacionais comparados

Cada modelo é apresentado em dois pontos operacionais:

- **nativo:** decisão original congelada antes da abertura dos rótulos;
- **calibrado por F1:** limiar secundário escolhido somente na validação.

Os limiares de `anomaly_score` foram:

| Modelo | Nativo | Calibrado na validação |
|---|---:|---:|
| Isolation Forest | 0,500000 | 0,334933 |
| LOF | 1,500000 | 1,444917 |

A seleção usa a convenção `anomaly_score >= threshold` da
[`precision_recall_curve`](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.precision_recall_curve.html).
Os escores numéricos brutos dos dois algoritmos não são comparados diretamente,
pois possuem escalas diferentes. A comparação usa métricas de ranking e
decisões em limiares declarados.

### Métricas de validação

| Modelo e ponto | Precision | Recall/TPR | F1 | FPR |
|---|---:|---:|---:|---:|
| Isolation Forest nativo | 0,9121 | 0,4086 | 0,5644 | 0,0394 |
| Isolation Forest calibrado | 0,6738 | 0,9412 | 0,7854 | 0,4556 |
| LOF nativo | 0,7841 | 0,7226 | 0,7521 | 0,1990 |
| LOF calibrado | 0,7760 | 0,7374 | 0,7562 | 0,2128 |

O limiar do Isolation Forest (`0,334933`) reproduziu exatamente o valor salvo
no Marco 7. Isso confirma que acrescentar o LOF não alterou retroativamente a
avaliação anterior.

### Métricas finais de teste — limiares nativos

| Modelo | TN | FP | FN | TP | Precision | Recall/TPR | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Isolation Forest | 9.498 | 502 | 5.938 | 4.062 | 0,8900 | 0,4062 | 0,5578 | 0,0502 |
| LOF | 8.004 | 1.996 | 2.725 | 7.275 | 0,7847 | 0,7275 | 0,7550 | 0,1996 |

No ponto nativo, o Isolation Forest é mais conservador: apresenta maior
precision e menor FPR, mas deixa de detectar 5.938 ataques. O LOF encontra
3.213 ataques adicionais e aumenta o F1 em 0,1972, ao custo de 1.494 falsos
positivos adicionais.

### Métricas finais de teste — limiares calibrados por F1

| Modelo | TN | FP | FN | TP | Precision | Recall/TPR | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Isolation Forest | 5.469 | 4.531 | 632 | 9.368 | 0,6740 | 0,9368 | 0,7840 | 0,4531 |
| LOF | 7.854 | 2.146 | 2.582 | 7.418 | 0,7756 | 0,7418 | 0,7583 | 0,2146 |

Após calibração, o Isolation Forest possui o maior recall e o maior F1. O LOF
calibrado mantém maior precision e reduz o FPR em 23,85 pontos percentuais em
relação ao Isolation Forest calibrado, mas perde 1.950 ataques adicionais.
Isso mostra por que a escolha operacional não deve considerar somente F1.

### Desempenho de ranking

| Conjunto | Métrica | Isolation Forest | LOF | Diferença LOF − IF |
|---|---|---:|---:|---:|
| Validação | ROC-AUC | 0,8265 | 0,7777 | -0,0488 |
| Validação | Average Precision | 0,8092 | 0,7162 | -0,0931 |
| Teste | ROC-AUC | 0,8236 | 0,7817 | -0,0419 |
| Teste | Average Precision | 0,8095 | 0,7266 | -0,0829 |

O Isolation Forest produz o melhor ordenamento global de ataques e normais nos
dois splits. ROC-AUC segue a definição de
[`roc_auc_score`](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.roc_auc_score.html).
Para a curva Precision–Recall foi utilizada
[`average_precision_score`](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html),
que pondera a precisão pelo ganho de recall e não usa interpolação trapezoidal.

### Comparação pareada

Como cada linha representa o mesmo fluxo nos dois modelos, também foi possível
medir a complementaridade dos erros:

| Ponto | Mesma decisão | Decisão diferente | Ambos corretos | Ambos errados | Só IF correto | Só LOF correto |
|---|---:|---:|---:|---:|---:|---:|
| Nativo | 14.545 | 5.455 | 11.692 | 2.853 | 1.868 | 3.587 |
| Calibrado | 12.769 | 7.231 | 11.439 | 1.330 | 3.398 | 3.833 |

Os modelos cometem erros diferentes em milhares de fluxos. Isso sugere que uma
estratégia de combinação pode ser estudada futuramente, mas nenhum ensemble é
criado neste marco para não ampliar o escopo nem ajustar uma solução após ver o
teste.

### Detecção por categoria no teste

| Categoria | Registros | IF nativo | LOF nativo | IF calibrado | LOF calibrado |
|---|---:|---:|---:|---:|---:|
| Bot | 40 | 2,50% | 10,00% | 32,50% | 10,00% |
| DDoS | 2.285 | 19,43% | 98,03% | 84,95% | 99,43% |
| DoS GoldenEye | 188 | 32,98% | 79,26% | 99,47% | 79,79% |
| DoS Hulk | 4.121 | 82,36% | 96,12% | 94,81% | 96,46% |
| DoS Slowhttptest | 103 | 78,64% | 45,63% | 100,00% | 45,63% |
| DoS slowloris | 108 | 61,11% | 34,26% | 98,15% | 70,37% |
| FTP-Patator | 146 | 0,00% | 1,37% | 98,63% | 1,37% |
| Heartbleed | 5 | 100,00% | 100,00% | 100,00% | 100,00% |
| Infiltration | 5 | 80,00% | 60,00% | 100,00% | 60,00% |
| PortScan | 2.836 | 0,14% | 28,46% | 99,12% | 30,36% |
| SSH-Patator | 110 | 0,00% | 8,18% | 91,82% | 9,09% |
| Web Attack - Brute Force | 32 | 0,00% | 18,75% | 84,38% | 18,75% |
| Web Attack - Sql Injection | 5 | 0,00% | 60,00% | 60,00% | 80,00% |
| Web Attack - XSS | 16 | 6,25% | 12,50% | 93,75% | 18,75% |

O LOF nativo se destaca em DDoS, DoS Hulk e DoS GoldenEye, enquanto o
Isolation Forest calibrado reconhece melhor PortScan, Patator e vários ataques
Web. Categorias com cinco ou poucas dezenas de registros possuem grande
incerteza e não devem determinar isoladamente a escolha do modelo.

### Comparação de tempo

| Etapa | Isolation Forest | LOF | Razão LOF/IF |
|---|---:|---:|---:|
| Treinamento | 0,376 s | 2,782 s | 7,39x |
| Inferência — validação | 0,085 s | 0,469 s | 5,54x |
| Inferência — teste | 0,155 s | 0,511 s | 3,30x |

O Isolation Forest foi mais rápido em todas as etapas medidas. Os tempos vêm
dos relatórios congelados dos Marcos 6 e 8 e dependem do hardware e das versões
das bibliotecas.

### Conclusão do Marco 9

Não há um vencedor absoluto:

- o **Isolation Forest** tem melhor ROC-AUC, Average Precision, velocidade e,
  no limiar calibrado, maior recall e F1;
- o **LOF nativo** oferece um compromisso intermediário, com recall e F1 muito
  maiores que o Isolation Forest nativo e FPR muito menor que o Isolation
  Forest calibrado;
- a escolha para operação real deve ser guiada por uma meta de falsos positivos
  e pelo custo de deixar um ataque passar;
- como validação e teste foram construídos com 50% de ataques, precision e
  accuracy não estimam diretamente o comportamento de uma rede corporativa,
  cuja prevalência real tende a ser diferente.

### Artefatos do Marco 9

```text
data/processed/evaluation/lof_validation_evaluated.parquet
data/processed/evaluation/lof_test_evaluated.parquet
data/processed/evaluation/model_comparison_validation.parquet
data/processed/evaluation/model_comparison_test.parquet
reports/metrics/lof_evaluation.json
reports/metrics/model_comparison.json
reports/metrics/model_comparison_summary.csv
reports/metrics/attack_category_comparison.csv
reports/figures/model_comparison_roc_pr_curves.png
reports/figures/model_comparison_confusion_matrices.png
reports/figures/model_comparison_test_metrics.png
reports/figures/model_comparison_attack_detection.png
```

Os Parquets `model_comparison_*` colocam as decisões e os acertos dos dois
modelos lado a lado para cada `record_hash`. Os CSVs são tabelas prontas para
análise ou inclusão no TCC. Os JSONs preservam metodologia, hashes, métricas,
tempos, categorias, versões e a ordem temporal de abertura dos rótulos.

## Experimento adicional — escala 20k versus 100k

O experimento adicional verifica o efeito de aumentar, de forma proporcional,
o número de registros usado em todo o fluxo. Ele não substitui o Marco 9: os
artefatos de 20k continuam sendo o baseline e a nova execução fica inteiramente
em `experiments/scale_100k/`.

Execute a partir da raiz do projeto:

```powershell
python run_scale_100k.py
```

Uma segunda execução é bloqueada para evitar substituição acidental. Quando a
repetição for deliberada, use:

```powershell
python run_scale_100k.py --overwrite
```

### Ações executadas

1. Os hashes SHA-256 dos dois modelos, do relatório de splits e do relatório
   comparativo do baseline foram calculados antes do experimento.
2. Foram criados novos splits com a mesma semente `42`, o mesmo esquema de 60
   features e cinco vezes mais registros em cada parcela.
3. O treino continuou usando exclusivamente tráfego `BENIGN` do Monday. Os
   dados de ataque foram usados somente em validação e teste.
4. Isolation Forest e LOF foram treinados novamente com os mesmos
   hiperparâmetros do baseline. As versões das bibliotecas também foram
   mantidas iguais às registradas no treinamento anterior.
5. Cada limiar calibrado foi escolhido exclusivamente na respectiva validação.
   O teste permaneceu fechado até o congelamento do limiar.
6. Os dois modelos foram avaliados nos mesmos hashes do experimento expandido.
   Em seguida, métricas, limiares e tempos foram comparados com o baseline.
7. Ao final, os hashes do baseline foram recalculados. Todos permaneceram
   idênticos, confirmando que a execução de 100k não alterou o experimento
   anterior.

### Tamanho dos conjuntos

| Split | Baseline 20k | Expandido 100k | Composição expandida |
|---|---:|---:|---|
| Treino | 20.000 | 100.000 | 100.000 `BENIGN` |
| Validação | 10.000 | 50.000 | 25.000 `BENIGN` + 25.000 ataques |
| Teste | 20.000 | 100.000 | 50.000 `BENIGN` + 50.000 ataques |

As 14 categorias de ataque aparecem nos dois conjuntos de avaliação e não há
sobreposição de `record_hash` entre treino, validação e teste. Classes muito
raras, como Heartbleed, Infiltration e Web Attack - SQL Injection, não possuem
registros de origem suficientes para crescer exatamente cinco vezes; a
amostragem preserva todas as classes e distribui o restante entre as categorias
com maior disponibilidade.

### Resultado no conjunto de teste

| Modelo | Limiar | Escala | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|
| Isolation Forest | Nativo | 20k | 89,00% | 40,62% | 55,78% | 5,02% |
| Isolation Forest | Nativo | 100k | 89,74% | 41,06% | 56,34% | 4,70% |
| Isolation Forest | Calibrado | 20k | 67,40% | 93,68% | 78,40% | 45,31% |
| Isolation Forest | Calibrado | 100k | 67,98% | 93,78% | 78,82% | 44,17% |
| LOF | Nativo | 20k | 78,47% | 72,75% | 75,50% | 19,96% |
| LOF | Nativo | 100k | 78,08% | 91,68% | 84,34% | 25,73% |
| LOF | Calibrado | 20k | 77,56% | 74,18% | 75,83% | 21,46% |
| LOF | Calibrado | 100k | 79,41% | 90,18% | 84,46% | 23,38% |

No Isolation Forest, a ampliação teve efeito pequeno: no ponto nativo, o F1
subiu 0,56 ponto percentual e o FPR caiu 0,32 ponto; no ponto calibrado, o F1
subiu 0,43 ponto e o FPR caiu 1,14 ponto. Isso indica comportamento estável,
mas não uma mudança estrutural na capacidade do modelo.

O LOF apresentou a maior mudança. No ponto nativo, o recall subiu de 72,75%
para 91,68% e o F1 de 75,50% para 84,34%. No ponto calibrado, o recall subiu de
74,18% para 90,18% e o F1 de 75,83% para 84,46%. O ganho veio acompanhado de
mais falsos positivos: +5,77 pontos no ponto nativo e +1,92 ponto no calibrado.

As métricas independentes de limiar confirmam a diferença:

| Modelo | Métrica de teste | 20k | 100k | Delta 100k - 20k |
|---|---|---:|---:|---:|
| Isolation Forest | ROC-AUC | 0,8236 | 0,8232 | -0,0004 |
| Isolation Forest | Average Precision | 0,8095 | 0,8142 | +0,0048 |
| LOF | ROC-AUC | 0,7817 | 0,8713 | +0,0896 |
| LOF | Average Precision | 0,7266 | 0,8044 | +0,0778 |

### Custo computacional observado

| Modelo | Etapa | 20k | 100k | Razão 100k/20k |
|---|---|---:|---:|---:|
| Isolation Forest | Treino | 0,376 s | 0,931 s | 2,48x |
| Isolation Forest | Inferência — validação | 0,085 s | 0,606 s | 7,17x |
| Isolation Forest | Inferência — teste | 0,155 s | 1,123 s | 7,26x |
| LOF | Treino | 2,782 s | 9,984 s | 3,59x |
| LOF | Inferência — validação | 0,469 s | 4,300 s | 9,18x |
| LOF | Inferência — teste | 0,511 s | 7,390 s | 14,48x |

Os tempos mostram o custo de escala esperado, principalmente na inferência do
LOF. Eles são medidas desta máquina e desta execução; não devem ser tratados
como benchmarks universais.

### Interpretação

Com 100k registros de treino, o **LOF calibrado** apresentou o maior F1 de
teste, `0,8446`, e o melhor compromisso global entre os dois modelos neste
experimento. Seu FPR de `23,38%`, porém, ainda é elevado para operação em uma
rede real e exigiria uma política de limiar orientada pelo orçamento de alertas.
O Isolation Forest calibrado alcançou o maior recall, `93,78%`, mas classificou
`44,17%` do tráfego benigno como anômalo. O Isolation Forest nativo manteve o
menor FPR, `4,70%`, ao custo de detectar apenas `41,06%` dos ataques.

Esta comparação altera simultaneamente o tamanho do treino e dos conjuntos de
avaliação. Portanto, a melhora observada não deve ser atribuída apenas aos
80.000 exemplos benignos adicionais: a estimativa das métricas também ficou
mais estável por usar validação e teste maiores. Um experimento controlado
posterior pode avaliar os modelos de 20k e 100k sobre o mesmo conjunto fixo
para isolar melhor o efeito do tamanho de treino.

### Artefatos do experimento

```text
experiments/scale_100k/experiment_manifest.json
experiments/scale_100k/data/splits/
experiments/scale_100k/data/predictions/
experiments/scale_100k/data/evaluation/
experiments/scale_100k/models/
experiments/scale_100k/metrics/scale_comparison.json
experiments/scale_100k/metrics/scale_comparison_summary.csv
experiments/scale_100k/metrics/scale_comparison_deltas.csv
experiments/scale_100k/figures/model_comparison/
experiments/scale_100k/figures/scale_comparison/
```

O experimento produziu 45 arquivos, aproximadamente 122,63 MiB. O manifesto
registra configuração, tempos de cada etapa, caminhos e a verificação dos
hashes do baseline. O JSON comparativo contém a metodologia e todos os deltas;
os dois CSVs oferecem formatos longo e diferencial para análise no TCC; e as
três figuras de escala comparam métricas de teste, ranking e custo.

## Consolidação final dos artefatos — Marco 10

O Marco 10 fecha a etapa experimental do projeto ao reunir, em índices
auditáveis, os modelos, metadados, relatórios, tabelas e figuras já produzidos.
Ele não copia os arquivos grandes para uma segunda pasta: registra seus caminhos
relativos, tamanhos e hashes SHA-256. Assim, um arquivo pode ser localizado e
ter sua integridade comprovada sem aumentar desnecessariamente o espaço usado.

Execute a partir da raiz do projeto:

```powershell
python finalize_artifacts.py
```

A execução normal é protegida contra substituição. Para regenerar
deliberadamente apenas os índices do Marco 10, sem tocar nos modelos de origem:

```powershell
python finalize_artifacts.py --overwrite
```

### Ações realizadas

1. Foram localizados os artefatos nas pastas do baseline 20k e do experimento
   expandido 100k.
2. Cada `.joblib`, JSON, CSV e PNG foi verificado como arquivo existente e não
   vazio. O SHA-256 foi calculado em blocos para evitar cópias grandes na
   memória.
3. Os hashes dos quatro modelos foram comparados com os valores registrados nos
   respectivos relatórios e metadados de treinamento.
4. Os fingerprints do esquema confirmaram 60 features idênticas. Os relatórios
   de split também confirmaram treino somente benigno e sobreposição zero de
   hashes entre treino, validação e teste.
5. Os contratos do Marco 9 foram conferidos: previsões congeladas antes dos
   rótulos, nenhum modelo recarregado na comparação e limiares calibrados sem
   utilizar o teste.
6. Configurações, limiares, métricas e tempos já calculados foram copiados para
   um registro central. Nenhuma previsão, métrica ou calibração foi refeita.
7. As métricas foram organizadas em uma tabela longa com os dois experimentos,
   dois modelos, dois splits e dois pontos operacionais: 16 combinações.
8. As figuras foram catalogadas com finalidade, largura, altura, tamanho e
   SHA-256. Nenhum gráfico decorativo ou duplicado foi criado.
9. Depois da montagem dos índices, o digest agregado das fontes foi calculado
   novamente. O valor permaneceu idêntico ao inicial.

### Resultado produzido

Foram inventariados 47 artefatos de origem, aproximadamente 45,70 MiB:

| Categoria | Quantidade |
|---|---:|
| Modelos `.joblib` | 4 |
| Metadados de modelos | 4 |
| Relatórios de métricas JSON | 16 |
| Tabelas de métricas CSV | 6 |
| Figuras científicas PNG | 17 |

O baseline contribui com 22 artefatos e o experimento 100k com 25. O digest
agregado desta consolidação é
`1ca51d7a053efc3acc5f30590346255260c8cba0b90f502fe5b888ac3a027de0`.
Esse valor resume os caminhos e hashes dos 47 arquivos; qualquer modificação
posterior em uma fonte produzirá outro digest.

O maior F1 de teste observado entre os candidatos já congelados permanece o do
LOF calibrado no experimento 100k: `0,8446`. Esse registro é descritivo e não
constitui aprovação automática para produção, pois o conjunto de avaliação tem
prevalência controlada de 50% de ataques.

### Arquivos do Marco 10

```text
reports/final/artifact_inventory.json
reports/final/model_registry.json
reports/final/metrics_summary.csv
reports/final/figure_catalog.csv
reports/final/MARCO_10_SUMMARY.md
reports/final/marco_10_manifest.json
```

- `artifact_inventory.json` contém uma entrada por artefato, incluindo caminho
  portátil, categoria, bytes, SHA-256 e metadados específicos do formato;
- `model_registry.json` reúne os quatro modelos, configurações, versões,
  esquemas, limiares congelados, métricas e tempos;
- `metrics_summary.csv` é a tabela final pronta para filtros, gráficos ou
  importação em ferramentas de análise;
- `figure_catalog.csv` explica o propósito de cada figura e registra suas
  dimensões e integridade;
- `MARCO_10_SUMMARY.md` oferece uma leitura humana concisa do fechamento;
- `marco_10_manifest.json` registra os hashes das cinco saídas anteriores e a
  prova de que as 47 fontes permaneceram inalteradas.

Ao executar corretamente, o terminal deve informar `Marco 10 concluído`,
`Fontes inalteradas: True` e `Validação: passed`.

## Inferência estruturada e preparação do Grafana — Marco 11

O Marco 11 remove a dependência conceitual de CSV durante a inferência. Depois
que um coletor transformar um fluxo em 60 estatísticas compatíveis com o
CIC-IDS2017, o modelo pode receber um dicionário Python ou um objeto JSON,
validá-lo, restaurar a ordem treinada das features e devolver uma resposta
estável para as próximas camadas.

O fluxo preparado é:

```text
PCAP capturado no OPNsense -> extrator de features de fluxo -> inferência estruturada
-> documento de monitoramento -> MongoDB -> FastAPI -> Grafana
```

O extrator de features ainda não fazia parte do Marco 11. Capturas PCAP e logs
brutos do firewall não podem ser enviados diretamente ao modelo: é necessário
produzir as 60 estatísticas e verificar sua compatibilidade. Os testes locais
posteriores utilizam CICFlowMeter V4, sem homologar equivalência semântica com
os CSVs históricos ou integração contínua de ponta a ponta.

### Modelo de referência

A configuração padrão da camada de integração é:

```text
experimento: expanded_100k
modelo: lof
ponto operacional: validation_f1_calibrated
limiar: 1.6046928359157646
```

Essa escolha corresponde ao maior F1 observado, `0,8446`, mas continua marcada
como experimental. Seu FPR de teste foi `23,38%`; o limiar precisará ser
validado novamente com a prevalência e o orçamento de alertas da rede real.

Isolation Forest, baseline 20k e limiar nativo também podem ser selecionados
explicitamente pelos parâmetros dos comandos, sem alterar a implementação.

### Como preparar os contratos

Execute:

```powershell
python prepare_integration.py
```

Como os contratos já foram gerados, uma repetição deliberada requer:

```powershell
python prepare_integration.py --overwrite
```

O script realiza estas ações:

1. abre o registro de modelos produzido no Marco 10;
2. localiza modelo e metadados somente por caminhos internos ao projeto;
3. recalcula o hash do `.joblib` antes de aceitar a referência;
4. recupera dos metadados os nomes e a ordem exata das 60 features;
5. confirma que o limiar calibrado não utilizou o conjunto de teste;
6. gera schemas para requisição, resposta e documento MongoDB;
7. gera a especificação dos painéis e endpoints futuros do Grafana;
8. recalcula os hashes das três fontes para confirmar que não foram alteradas.

O comando não carrega o modelo, não inicia banco, servidor HTTP ou Grafana e
não modifica o limiar.

### Contrato da requisição

A futura requisição de inferência terá quatro grupos:

| Campo | Finalidade | Entra no modelo? |
|---|---|---|
| `event_id` | Identificador estável para evitar duplicação | Não |
| `observed_at` | Data e hora do fluxo com fuso | Não |
| `source` | Origem do coletor, como OPNsense ou `lab_pcap_v4_exploratory` | Não |
| `features` | As 60 estatísticas numéricas e finitas | Sim |
| `context` | IPs, portas, protocolo, interface e dispositivo | Não |

`features` rejeita colunas ausentes, extras, booleanos, texto, `NaN`, `inf` e
`-inf`. A ordem recebida no JSON não importa: o serviço sempre reconstrói a
ordem registrada no bundle do modelo. `Label`, `binary_label` e saídas de
predição nunca são aceitas como features.

O arquivo `inference_request.schema.json` possui a lista completa dos 60 nomes.
O contexto é separado para permitir investigação no dashboard sem criar
vazamento de informação no modelo. Chaves iniciadas por `$` ou contendo `.` são
rejeitadas para evitar campos problemáticos no MongoDB.

### Execução de uma inferência JSON

Depois de criar um arquivo que obedeça ao schema, execute:

```powershell
python predict_json.py caminho\requisicao.json
```

Para salvar a resposta:

```powershell
python predict_json.py caminho\requisicao.json `
  --output caminho\predicao.json
```

O comando aceita um único objeto ou um array de até 1.000 objetos. O modelo é
carregado apenas uma vez por processo e a inferência do lote é vetorizada. Uma
saída existente é protegida; use `--overwrite` somente quando a substituição
for intencional.

Para selecionar outro ponto operacional:

```powershell
python predict_json.py caminho\requisicao.json `
  --experiment baseline_20k `
  --model isolation_forest `
  --operating-point native
```

### Resposta de inferência

A resposta contém:

- identidade, SHA-256 e limiar do modelo;
- classificação normal/anomalia em texto e em `0/1`;
- saída nativa `1/-1` do Scikit-learn;
- `score_samples`, `decision_function` e `anomaly_score`;
- distância entre o score e o limiar;
- data da observação, data do processamento, origem e contexto.

`anomaly_score` continua definido como `-score_samples`: valores maiores são
mais anômalos. Ele não é uma probabilidade e scores brutos de Isolation Forest
e LOF não devem ser colocados na mesma série. O agregador exige o mesmo hash de
modelo, experimento e ponto operacional em cada snapshot.

No teste de fumaça operacional executado com um registro processado e sem
consultar seu rótulo, o Isolation Forest 100k retornou:

```text
anomaly_score: 0.6289170447808043
threshold: 0.615824439899627
threshold_distance: 0.013092604881177361
prediction: anomaly
```

Esse resultado comprova o funcionamento técnico do contrato; não constitui uma
nova medição de desempenho nem uma nova calibração.

### Calibração operacional pós-Marco 11

O limiar calibrado por F1 foi útil para comparar os modelos em um conjunto
balanceado, mas produziu FPR elevado demais para monitoramento contínuo. Foi
criado um terceiro ponto, `validation_fpr_operational`, com FPR-alvo de 1%.

Execute a calibração com:

```powershell
python calibrate_operational_threshold.py
```

A seleção ocorre em duas etapas antes da leitura do teste:

1. para cada modelo, o menor limiar que mantém no máximo 1% dos registros
   benignos da validação como anomalias é congelado;
2. entre os modelos sujeitos ao mesmo limite, vence o de maior recall na
   validação. Precision e menor FPR são usados somente como desempate.

Os rótulos de ataque não determinam o valor numérico dos limiares. Eles são
usados na validação apenas para comparar o recall dos modelos. O conjunto de
teste permanece fechado até o congelamento dos dois limiares e da escolha do
modelo.

| Modelo | Limiar operacional | FPR teste | Precision teste | Recall teste | F1 teste |
|---|---:|---:|---:|---:|---:|
| Isolation Forest | 0,6158244399 | 1,024% | 96,48% | 28,06% | 43,47% |
| LOF | 91,0868596993 | 0,996% | 76,72% | 3,28% | 6,29% |

O **Isolation Forest** passa a ser o candidato operacional padrão porque, sob
o mesmo orçamento de falsos positivos, detecta aproximadamente 8,5 vezes mais
ataques que o LOF. Os resultados nativo e calibrado por F1 não foram removidos;
continuam disponíveis para comparação acadêmica.

Esse ajuste reduz os falsos positivos do Isolation Forest de 44,17% no ponto de
F1 para 1,024% no teste, mas também reduz o recall de 93,78% para 28,06%. Esse é
o custo explícito de tornar o volume de alertas menos agressivo. Mesmo 1% pode
representar cerca de 10.000 fluxos falsamente sinalizados por milhão de fluxos
benignos, portanto alertas por e-mail devem ser agregados e deduplicados.

Os artefatos ficam em:

```text
reports/operational/operational_calibration.json
reports/operational/threshold_sensitivity.csv
reports/operational/operational_threshold_tradeoff.png
reports/operational/model_registry_operational.json
reports/operational/OPERATIONAL_CALIBRATION_SUMMARY.md
reports/operational/operational_calibration_manifest.json
```

O registro operacional é derivado do registro final do Marco 10. A inferência
passa a preferi-lo automaticamente, mas mantém fallback para o registro original
quando esse novo arquivo não existe. O perfil ainda não é aprovado para
produção: o FPR-alvo deverá ser recalibrado com uma janela temporal benigna da
rede real e com um limite explícito de alertas que a operação consiga tratar.

### Documento preparado para MongoDB

`build_monitoring_document()` transforma a resposta em um documento com:

```text
event_id
observed_at
processed_at_utc
source
model.*
classification.*
context.*
```

O schema recomenda cinco índices:

1. `event_id` único para ingestão idempotente;
2. `observed_at` decrescente para filtros temporais;
3. `classification.is_anomaly + observed_at` para anomalias recentes;
4. `context.src_ip + observed_at` para investigação de origens;
5. `context.dst_port + observed_at` para análise de portas.

Nenhum índice TTL foi ativado automaticamente. Retenção e anonimização de IPs
devem ser definidas antes do uso com tráfego real.

### Primeira página planejada no Grafana

| Painel | Visualização | Informação fundamental |
|---|---|---|
| Fluxos analisados | Stat | Volume total no intervalo |
| Anomalias detectadas | Stat | Total marcado como anômalo |
| Taxa de anomalias | Gauge | Anomalias divididas pelos fluxos |
| P95 do anomaly score | Stat | Cauda superior do score no mesmo modelo |
| Normais x anômalos no tempo | Time series | Evolução dos volumes por janela |
| Taxa de anomalias no tempo | Time series | Mudanças de comportamento da rede |
| Distribuição por protocolo | Bar chart | Composição TCP/UDP/outros |
| Principais IPs de origem | Bar chart | Origens mais presentes nas anomalias |
| Portas de destino | Bar chart | Portas mais associadas às anomalias |
| Anomalias recentes | Table | Linhas para investigação operacional |
| Modelo ativo e limiar | Table | Rastreabilidade da decisão exibida |

Também foram definidos cinco endpoints futuros da FastAPI: visão geral, série
temporal, distribuições, anomalias recentes e estado do modelo. A fonte concreta
do Grafana ainda não foi escolhida nem provisionada; a especificação utiliza um
contrato JSON neutro para evitar acoplamento prematuro.

Dois painéis foram deliberadamente excluídos:

- **falsos positivos ao vivo**, porque um fluxo real não possui rótulo verdadeiro
  imediato;
- **categoria do ataque**, porque os modelos detectam anomalia, mas não foram
  treinados como classificadores de famílias de ataque.

### Artefatos do Marco 11

```text
reports/integration/inference_request.schema.json
reports/integration/inference_response.schema.json
reports/integration/mongodb_prediction.schema.json
reports/integration/grafana_dashboard_spec.json
reports/integration/MARCO_11_SUMMARY.md
reports/integration/marco_11_manifest.json
```

O manifesto registra que inferência estruturada, documento de monitoramento e
agregador de dashboard estão implementados. Registra também, sem ambiguidade,
que conexão MongoDB, servidor FastAPI, provisionamento do Grafana e extrator de
features de capturas OPNsense ainda não estavam implementados naquela etapa.
Esse registro é histórico do Marco 11; as etapas posteriores de replay e de
captura offline são documentadas separadamente neste README.

## Validação

Execute os testes a partir da raiz do projeto:

```powershell
python -m unittest discover -s tests -v
```

Os Marcos 2 a 11, o experimento de escala e a calibração operacional estão
validados quando:

1. os testes terminam com `OK`;
2. `python main.py` encontra os CSVs e termina sem erro;
3. a soma da distribuição de `label` é igual ao número de registros;
4. o arquivo `reports/metrics/dataset_inspection.json` é criado;
5. os CSVs em `data/raw/` permanecem inalterados.
6. `monday_features.parquet` e `monday_labels.parquet` têm o mesmo número de
   linhas;
7. `label` não aparece nas colunas do arquivo de features;
8. todas as features são numéricas e não contêm `NaN`, `inf` ou `-inf`;
9. `reports/metrics/monday_preprocessing.json` reconcilia todas as remoções.
10. `monday_selected_features.parquet` possui 502.650 linhas e 60 colunas;
11. o manifesto reaplica as features pelo nome e restaura a ordem esperada;
12. o SHA-256 do esquema selecionado corresponde ao manifesto;
13. o relatório confirma `labels_used: false` e `attack_records_used: false`.
14. treino contém somente `BENIGN`;
15. validação e teste contêm 50% BENIGN e 50% ataques;
16. as 14 categorias aparecem nos dois conjuntos de avaliação;
17. nenhum `record_hash` aparece em mais de um conjunto;
18. os três fingerprints de modelagem são iguais;
19. nenhum arquivo `X_*` contém `label`, ausentes ou infinitos.
20. o bundle contém 200 árvores, 60 features e a ordem do manifesto;
21. o SHA-256 calculado do `joblib` coincide com metadados e relatório;
22. as previsões não contêm rótulos e todos os escores são finitos;
23. `anomaly_score` é exatamente o negativo de `score_samples`;
24. o relatório confirma `labels_loaded: false`, `scaler_used: false` e
    `evaluation_deferred_to_marco_7: true`.
25. cada previsão de validação e teste encontra exatamente um `record_hash` em
    seu respectivo arquivo de rótulos;
26. o SHA-256 do modelo continua idêntico ao registrado no Marco 6;
27. o limiar calibrado é escolhido antes da abertura de `y_test`;
28. matriz de confusão, precision, recall, F1, FPR, ROC-AUC e AP são salvos;
29. as 14 categorias de ataque recebem contagens e taxas de detecção;
30. os dois Parquets avaliados e as três figuras são gerados sem alterar o
    modelo ou as previsões originais.
31. o bundle do LOF contém, nesta ordem, `StandardScaler` e
    `LocalOutlierFactor`;
32. o scaler foi ajustado apenas em `X_train` e suas 60 estatísticas são
    persistidas;
33. o modelo possui `novelty=True`, `n_neighbors=20` e nenhum método de
    novidade foi executado sobre o treino;
34. os hashes de treino, validação e teste permanecem sem sobreposição;
35. as previsões de validação e teste têm ordem, esquema, classes e escores
    coerentes, sem valores ausentes ou infinitos;
36. `anomaly_score` é exatamente o negativo de `score_samples` e
    `decision_function` é `score_samples - offset_`;
37. relatório e metadados confirmam `labels_loaded: false` e
    `evaluation_deferred_to_marco_9: true`;
38. o SHA-256 recalculado de `lof.joblib` coincide com o valor registrado.
39. os dois modelos são associados aos mesmos hashes e rótulos em cada split;
40. nenhum `.joblib` é carregado, retreinado ou modificado na comparação;
41. os dois limiares calibrados são congelados antes da abertura de `y_test`;
42. o limiar do Isolation Forest reproduz exatamente o relatório do Marco 7;
43. as métricas nativas e calibradas são preservadas separadamente;
44. ROC-AUC e Average Precision usam a mesma orientação de `anomaly_score`;
45. os Parquets pareados possuem 10.000 e 20.000 hashes únicos;
46. as 14 categorias são comparadas nos dois modelos e pontos operacionais;
47. as quatro figuras são geradas e permanecem visualmente legíveis;
48. modelos, previsões e rótulos de entrada preservam seus SHA-256 durante a
    avaliação.
49. a configuração expandida possui exatamente cinco vezes os registros de
    cada parcela do baseline;
50. o experimento expandido usa a mesma semente, esquema de features,
    hiperparâmetros e versões de bibliotecas;
51. o treino expandido contém apenas `BENIGN`, as 14 categorias estão presentes
    na avaliação e não há sobreposição de hashes entre splits;
52. os limiares expandidos são selecionados somente na validação e congelados
    antes da abertura do teste;
53. as tabelas possuem os dois experimentos, os dois modelos, os dois splits e
    os dois pontos operacionais;
54. os três gráficos comparativos são gerados e permanecem legíveis;
55. os hashes dos quatro artefatos protegidos do baseline são idênticos antes e
    depois da execução de 100k.
56. os quatro hashes de modelo coincidem com os relatórios e metadados de
    treinamento;
57. o inventário contém 47 fontes não vazias, separadas por experimento e
    categoria;
58. `metrics_summary.csv` contém 16 linhas de dados sem linhas vazias
    intermediárias;
59. `figure_catalog.csv` contém 17 figuras PNG com dimensões e SHA-256 válidos;
60. o manifesto confirma que modelos não foram carregados, retreinados ou
    modificados e que limiares não foram recalibrados;
61. os digests agregados calculados antes e depois da consolidação são iguais;
62. uma nova execução sem `--overwrite` é bloqueada antes de alterar os índices.
63. o hash do modelo é validado antes de sua desserialização;
64. os 60 nomes do bundle coincidem com o contrato e são restaurados na ordem
    treinada;
65. valores ausentes, extras, não numéricos ou não finitos são rejeitados;
66. `Label` e campos derivados da predição não entram no modelo;
67. datas de observação sem fuso horário são rejeitadas;
68. `anomaly_score` permanece exatamente `-score_samples` e nunca é apresentado
    como probabilidade;
69. o documento de monitoramento preserva modelo, limiar, score e contexto;
70. snapshots de dashboard não misturam modelos, versões ou pontos
    operacionais;
71. o contrato MongoDB possui validação, índices propostos e TTL desativado;
72. a especificação do Grafana possui 11 painéis fundamentais e cinco endpoints
    futuros;
73. falsos positivos e categorias de ataque não são inventados para dados sem
    rótulo;
74. os seis contratos são gerados sem alterar registro, metadados ou modelo;
75. o teste de fumaça carrega o Isolation Forest 100k no ponto operacional e
    produz uma resposta e um snapshot
    válidos sem consultar `Label`.
76. cada limiar operacional usa apenas os escores benignos da validação;
77. o teto de 1% considera a regra inclusiva `anomaly_score >= threshold` e
    trata empates sem exceder o orçamento;
78. a escolha entre Isolation Forest e LOF usa somente métricas da validação;
79. todos os limiares e o modelo recomendado são congelados antes da leitura do
    teste;
80. os pontos nativo e calibrado por F1 permanecem no registro derivado;
81. a sensibilidade compara 0,1%, 0,5%, 1%, 2% e 5% de FPR-alvo;
82. os hashes das previsões avaliadas e do registro-pai não mudam durante a
    calibração;
83. a inferência prefere o registro operacional e valida o hash do modelo antes
    da desserialização;
84. os contratos de integração e Grafana registram Isolation Forest,
    `validation_fpr_operational` e limiar `0,6158244399`.
85. o replay do Marco 12 lê as 60 features para recomputar `record_hash`, mas
    projeta somente seis campos contextuais para persistência;
86. `Label` e `binary_label` não são lidos do Parquet de proveniência;
87. o início e o namespace padrão do replay são congelados, permitindo
    idempotência também entre dias diferentes;
88. timestamps são normalizados para a precisão de milissegundos do BSON Date;
89. o mesmo `event_id` com conteúdo diferente é tratado como conflito;
90. a proteção contra sobrescrita do relatório ocorre antes de qualquer escrita;
91. o MongoDB recebe timestamps como BSON Date e cinco índices sem TTL;
92. o serviço recusa snapshots truncados, evitando totais e percentis parciais;
93. todas as consultas fixam experimento, modelo, SHA-256, ponto operacional,
    limiar e regra positiva;
94. as janelas temporais seguem `[start, end)` e exigem fuso horário;
95. a API diferencia janela solicitada de extensão efetivamente coberta por dados;
96. protocolo e IP ausentes retornam listas vazias e não valores fabricados;
97. o Grafana possui 11 painéis provisionados com o datasource Infinity;
98. dashboard, API, MongoDB e dependências Python possuem contratos reproduzíveis;
99. 5.000 registros reais dos artefatos congelados passaram por duas ingestões
    em memória, comprovando 5.000 inserções e depois 5.000 duplicatas;
100. os 79 testes dos Marcos 1–12 passaram sem falhas.

## Marco 12 — persistência operacional e dashboard Grafana

O Marco 12 transforma os contratos preparados no Marco 11 em uma implementação
executável. Ele não treina nem avalia novamente o modelo. Seu objetivo é mover
previsões congeladas para uma camada de monitoramento e disponibilizar apenas
indicadores operacionais — nunca a verdade do teste — para o Grafana.

O fluxo implementado é:

```text
X_test + previsões congeladas + proveniência sem rótulos
                         |
                         v
               replay determinístico
                         |
                         v
        MongoDB (ou fake em memória nos testes)
                         |
                         v
                     FastAPI
                         |
                         v
             Grafana + datasource Infinity
```

### Replay

`replay_to_mongodb.py` usa as previsões do Isolation Forest 100k já salvas. A
classificação operacional é reaplicada com:

```text
anomaly_score >= 0.615824439899627
```

O replay não abre o `.joblib`, não recalcula scores e não lê `Label` ou
`binary_label`. As 60 features são lidas somente para recomputar o hash da linha
e detectar troca, corrupção ou reordenação de `X_test`. Apenas porta de destino e
estatísticas de fluxo previamente selecionadas entram no contexto persistido por
padrão. IPs e protocolo podem ser enriquecidos pelos CSVs originais
`GeneratedLabelledFlows`, mas somente quando cada linha complementar corresponde
exatamente às 60 features do `X_test`; a validação falha antes de qualquer escrita
se houver divergência.

Use primeiro o modo sem escrita:

```powershell
python replay_to_mongodb.py `
  --dry-run `
  --limit 200 `
  --network-context-dir .\data\reference\generated_labelled_flows `
  --report-path reports/marco12/replay_dry_run_200.json `
  --overwrite-report
```

Para enviar 5.000 documentos ao MongoDB local:

```powershell
$env:TCC_MONGODB_URI = "mongodb://127.0.0.1:27017"
python replay_to_mongodb.py --limit 5000 --network-context-dir .\data\reference\generated_labelled_flows --overwrite-report
```

O padrão simula um evento por segundo a partir de
`2026-01-01T00:00:00Z`, no namespace
`cicids2017-test-expanded-100k-v1`. Alterar intencionalmente a sessão requer
informar `--start-time` e `--namespace`.

### MongoDB

`initialize_mongodb.py` cria ou atualiza a coleção
`network_flow_predictions`. O validador exige identidade completa do modelo,
decisão coerente e datas BSON; o índice único de `event_id` sustenta a
idempotência. Nenhum TTL é criado automaticamente porque a política de retenção
ainda não foi definida para o TCC.

### FastAPI

Inicie localmente com:

```powershell
python -m uvicorn run_dashboard_api:app --host 127.0.0.1 --port 8000
```

Rotas de dados:

- `/api/v1/dashboard/overview`;
- `/api/v1/dashboard/timeseries`;
- `/api/v1/dashboard/breakdowns`;
- `/api/v1/anomalies/recent`;
- `/api/v1/model/status`.

Também existem `/health/live`, `/health/ready`, `/docs` e `/openapi.json`. As
consultas aceitam datas com fuso, intervalo máximo de 31 dias e até 100 mil
documentos para agregação. Se houver mais dados, a API retorna erro explícito em
vez de exibir métricas parciais como totais.

### Grafana e composição local

O arquivo `infra/compose.yaml` declara MongoDB, inicializador one-shot, FastAPI e
Grafana. O dashboard provisionado possui 11 painéis e deixa visível que:

- os dados são um replay offline balanceado;
- os horários são simulados;
- o score não é probabilidade;
- IP e protocolo só aparecem quando foram validados a partir dos CSVs
  `GeneratedLabelledFlows`; eles nunca são inferidos ou fabricados.
- o resultado não representa prevalência de uma rede real.

As instruções completas estão em `infra/README.md`. O pacote de evidências está
em `reports/marco12/`, especialmente `MARCO_12_SUMMARY.md` e
`marco_12_manifest.json`.

## Próximos marcos

### Experimento de captura no laboratório (LAB02)

A captura HTTP controlada foi extraída com duas revisões oficiais do
CICFlowMeter e comparada com uma leitura independente do PCAP. Os nomes, tipos
e ordem das 60 features passam no contrato estrutural, mas a equivalência dos
cálculos com o CIC-IDS2017 ainda não foi estabelecida. Consulte
`reports/lab/LAB02_HISTORICAL_COMPARISON.md` para resultados, limitações e comandos
de reprodução com `extract_lab_flows.ps1` e `audit_lab_extractors.py`.

A primeira inferência exploratória V4 foi executada com os modelos e limiares
congelados: o IF sinalizou 0 de 20 segmentos e o LOF sinalizou 20 de 20. Isso não
constitui uma avaliação de eficácia em produção. O adaptador separa as 60
features dos metadados, ignora rótulos e exige `--accept-experimental-v4`.
Detalhes, avisos de integridade e comandos de `predict_lab_v4.py` estão em
`reports/lab/LAB02_V4_INFERENCE.md`. Os resultados ficam em `data/lab/`, separados
dos experimentos anteriores e sem gravação no banco.

Para ampliar a amostra com downloads HTTP benignos sequenciais, consulte
`reports/lab/LAB_CAPTURE_PLAN.md`. Os helpers estão em `lab_tools/`; as novas
capturas ainda devem ser executadas nas VMs e conferidas antes da inferência.

A primeira sessão LAB03/r1 foi validada: 30 downloads de 16 KiB, 663 pacotes e
60 segmentos V4. Nos limiares congelados, IF sinalizou 0/60 e LOF 39/60 (9/30
com payload e 30/30 sem payload). Consulte `reports/lab/LAB03_SMALL_R1.md` para
evidências, limitações e o próximo cenário; essas são taxas de sinalização,
não métricas supervisionadas de desempenho.

A sessão LAB04/r1 também foi validada: 12 downloads de 256 KiB, 2.474 pacotes
e 24 segmentos V4. IF operacional sinalizou 0/24 e LOF 24/24; IF nativo
sinalizou 12/24, mostrando a importância de identificar o ponto operacional.
Detalhes e próximos passos em `reports/lab/LAB04_MEDIUM_R1.md`.

LAB05/r1 foi validado: seis downloads de 2 MiB, 9.245 pacotes e 12 segmentos.
IF operacional sinalizou 6/12 (todos com payload) e LOF 12/12. As conexões
duraram cerca de 15,5 s, mas o payload passou em rajadas de milissegundos no
ponto capturado; não confundir tempo do cliente com envio sustentado na rede.
Veja `reports/lab/LAB05_SLOW_R1.md` e `reports/lab/lab_capture_summary.json`.

O LAB06/r1 foi coletado e validado nas VMs: seis downloads de 2 MiB,
10.116 pacotes e payload distribuído por cerca de 15,9 s em cada conexão.
Nos limiares congelados, IF sinalizou 6/12 segmentos (os com dados) e LOF 12/12.
Resultados em `reports/lab/LAB06_SERVERPACED_R1_RESULTS.md`; consolidado das
cinco rodadas em `reports/lab/lab_capture_summary_through_lab06.json`.
A ISO e o roteiro original estão em `reports/lab/LAB06_SERVER_PACING.md`.

O diagnóstico das 60 features contra os 100 mil registros de treinamento está
em `reports/lab/FEATURE_DIAGNOSTICS_R1.md`, com dados completos e gráfico em
`reports/lab/feature_diagnostics_r1/`. A referência transformada coincide com a
referência ajustada no LOF. A decomposição geométrica não é atribuição do score
nem importância no IF; modelos e limiares foram preservados. O roteiro das
próximas sessões está em `reports/lab/LAB_REPETITIONS_R2_R3.md`.

LAB03/r2 foi validado: 30 downloads de 16 KiB, 662 pacotes e 60 segmentos V4.
IF operacional sinalizou 0/60 e LOF 31/60 (1/30 com payload, 30/30 sem payload),
contra 39/60 do LOF em r1. Essa variação não demonstra melhora de desempenho.
Veja `reports/lab/LAB03_SMALL_R2.md` e o novo snapshot
`reports/lab/lab_capture_summary_through_lab03_r2.json`; resultados anteriores
foram preservados. Próxima coleta planejada: LAB04/r2.

LAB04/r2 foi validado: 12 downloads de 256 KiB, 2.459 pacotes e 24 segmentos V4.
As contagens operacionais repetiram r1: IF 0/24 e LOF 24/24, apesar da variação
dos scores e tempos. Detalhes em `reports/lab/LAB04_MEDIUM_R2.md`; novo snapshot
com sete sessões em `reports/lab/lab_capture_summary_through_lab04_r2.json`.
Próxima coleta planejada: LAB05/r2, mantendo o servidor HTTP comum.

LAB05/r2 foi validado: seis downloads de 2 MiB, 9.422 pacotes e 12 segmentos V4.
Repetiu as contagens operacionais de r1: IF 6/12 e LOF 12/12. A duração TCP
mediana foi 15,485686 s, mas o intervalo de payload do servidor teve mediana
de 7,461 ms. Veja `reports/lab/LAB05_SLOW_R2.md` e o consolidado com oito sessões
`reports/lab/lab_capture_summary_through_lab05_r2.json`. Próxima coleta: LAB06/r2,
com o helper dedicado e controle de envio no servidor.

LAB06/r2 foi validado com os cinco arquivos: seis downloads de 2 MiB, 10.087
pacotes e 12 segmentos. O payload foi observado ao longo de cerca de 15,9 s
por conexão, com logs do servidor coerentes. IF sinalizou 6/12 e LOF 12/12,
repetindo r1. Veja `reports/lab/LAB06_SERVERPACED_R2_RESULTS.md` e o snapshot
`reports/lab/lab_capture_summary_through_lab06_r2.json`. A segunda rodada dos
quatro cenários está concluída; próxima coleta proposta: LAB06/r3.

LAB06/r3 foi validado: seis downloads de 2 MiB, 10.098 pacotes e 12 segmentos.
O intervalo de payload teve mediana de 15,896079 s, reproduzindo o envio
controlado. As contagens repetiram as três sessões: IF 6/12 e LOF 12/12.
Veja `reports/lab/LAB06_SERVERPACED_R3_RESULTS.md` e o snapshot
`reports/lab/lab_capture_summary_through_lab06_r3.json`. Próxima coleta: LAB05/r3,
voltando ao servidor HTTP comum e ao helper com limite no cliente.

LAB05/r3 foi validado: seis downloads de 2 MiB, 9.358 pacotes e 12 segmentos.
As contagens repetiram r1/r2: IF 6/12 e LOF 12/12. O intervalo de payload teve
mediana de 6,837 ms, apesar de conexões de cerca de 15,5 s. Houve intervalo
de 65,884717 s entre os inícios do segundo e terceiro downloads; a causa não
foi determinada e a sessão foi preservada com ressalva. Veja
`reports/lab/LAB05_SLOW_R3.md` e `reports/lab/lab_capture_summary_through_lab05_r3.json`.
Próxima coleta: LAB04/r3.

LAB04/r3 foi validado: 12 downloads de 256 KiB, 2.482 pacotes e 24 segmentos.
As contagens operacionais repetiram as três sessões: IF 0/24 e LOF 24/24.
As cópias preservadas conferem com os hashes de importação; os três caminhos
originais em Downloads estavam indisponíveis na conferência final. Veja
`reports/lab/LAB04_MEDIUM_R3.md` e `reports/lab/lab_capture_summary_through_lab04_r3.json`.
Falta LAB03/r3 para completar as três repetições dos quatro cenários.

LAB03/r3 foi validado: 30 downloads de 16 KiB, 662 pacotes e 60 segmentos.
IF sinalizou 0/60 e LOF 33/60 (3/30 com payload e 30/30 sem payload).
A matriz LAB03–LAB06/r1–r3 está concluída: 12 sessões, 162 conexões e
324 segmentos, sem contar LAB02. Consulte `reports/lab/LAB03_SMALL_R3.md`,
`reports/lab/LAB_CAPTURE_MATRIX_R1_R3.md` e o snapshot completo
`reports/lab/lab_capture_summary_complete_r1_r3.json`. São resultados
exploratórios de sinalização, não validação de eficácia em produção.

O piloto de reconhecimento TCP LAB07 está planejado, não executado, em
`reports/lab/LAB07_PORTSCAN_PLAN.md`: Kali → único Windows-LAB, 16 portas,
connect scan com ritmo limitado, sem exploração ou autenticação. Antes da
execução, exige conferir switches/adaptadores, desconectar somente a WAN da
VM OPNsense e revisar a regra TCP restrita. Os validadores/consolidados HTTP
não são automaticamente aplicáveis a essa captura; modelos/limiares ficam
congelados e os resultados benignos são preservados.

LAB07/r1 foi recebido e auditado: 15 portas executadas (5985 ausente), todas
filtered/no-response; PCAP com 39 SYNs Kali→Windows, sem respostas TCP. A V4
exportou nove registros representando 18 pacotes; 21 grupos de um pacote
ficaram sem representação. Não houve inferência IF/LOF sobre essa extração
parcial. Veja `reports/lab/LAB07_TCP_CONNECT_R1_RESULTS.md`,
`validate_lab07_scan.py` e `audit_lab07_extraction.py`. Próximo passo: correlacionar
logs do OPNsense, sem atribuir automaticamente o bloqueio ao Windows.

Screenshots posteriores dos logs LAB07 mostram Pass na entrada KALI e saída
LAN para tuplas da varredura. As linhas bloqueadas visíveis são UDP para o
gateway:53, não o TCP para Windows. O diagnóstico segue para política efetiva
e listeners do Windows, somente leitura: a causa do silêncio ainda não foi
comprovada. Detalhes na seção 8 do relatório LAB07; imagens preservadas em
`data/lab/lab07_tcp_connect/r1/firewall_evidence/`. Não houve nova varredura
ou inferência sobre a extração parcial.

O diagnóstico TCP 135/r2 foi recebido: a captura LAN contém um SYN destinado
ao MAC anteriormente atribuído ao Windows-LAB; a janela declarada do ETL
abrange a sondagem, mas o TXT não contém eventos de pacote. A conversão local
adicional do ETL teve erros de formatação e não valida ausência de pacotes.
Resultado inconclusivo quanto ao recebimento Windows e à causa do silêncio.
Veja `reports/lab/LAB07_DIAG135_R2_RESULTS.md` e `audit_lab07_diag135.py`.
Próximo passo: conferir componentes/filtros Pktmon, somente leitura.

Atualização LAB08/r1: os quatro arquivos da sondagem de 16 portas foram
preservados e auditados. O PCAP contém 42 pacotes, quatro respostas SYN+ACK,
quatro grupos bidirecionais e 26 grupos de um pacote. Nmap registrou 135/139/445
abertas e as outras 13 filtered. Após o usuário iniciar o Docker, a extração
V4 concluiu, mas a auditoria confirmou cobertura parcial: quatro registros
representam 16 dos 42 pacotes; 26 grupos de um SYN ficaram sem representação
no CSV. Posteriormente, mediante autorização explícita, houve inferência
somente nos quatro registros exportados: IF operacional 0/4 e LOF 1/4.
Isso não mede detecção da sondagem completa. O comparativo com as 12 sessões
benignas está em `reports/lab/lab08_subset_comparison_v1.md` e JSON homônimo.
Não repetir a coleta automaticamente. Veja `reports/lab/LAB08_TCP_RESPONSIVE_R1_RESULTS.md`.

### Planejamento da integração

A implementação interna do Marco 12 está concluída. O próximo passo é a validação
externa do stack em uma máquina com Docker: subir os containers, gravar o replay
no MongoDB real, verificar o healthcheck do datasource Infinity e inspecionar
visualmente os 11 painéis. Depois disso, o Marco 13 deve substituir o replay por
um extrator das mesmas 60 features aplicado a fluxos de rede reais, com medição
de *data drift*, prevalência, orçamento de alertas, latência e tratamento de
dados sensíveis antes de qualquer aprovação de produção.
