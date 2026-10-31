# LAB02 — primeira inferencia exploratoria com CICFlowMeter V4

Data: 25/10/2026. Estado: implementacao e execucao concluidas.

## 1. Resultado principal

Os modelos congelados `expanded_100k` classificaram os mesmos 20 segmentos V4.
O Isolation Forest nao sinalizou segmentos; o LOF sinalizou os 20. Foram
mantidos os limiares operacionais existentes, sem selecionar valores nesta captura.

| Grupo de segmentos | Quantidade | IF sinalizados | LOF sinalizados |
| --- | ---: | ---: | ---: |
| Com payload | 10 | 0 | 10 |
| Sem payload | 10 | 0 | 10 |
| Total | 20 | 0 | 20 |

Os registros derivam de dez conexoes HTTP controladas, nao de vinte ataques ou
vinte requisicoes independentes. Cada conexao originou dois segmentos.

| Modelo | Limiar operacional | Score minimo | Score mediano | Score maximo |
| --- | ---: | ---: | ---: | ---: |
| Isolation Forest | 0,615824439899627 | 0,3580567819607792 | 0,38499732795238706 | 0,41440155117564814 |
| LOF | 91,08685969933371 | 94,54273724328003 | 251,30478256381687 | 1784,9793849242112 |

Regra: `anomaly_score >= threshold`. Score e `-score_samples`, nao probabilidade.
As escalas dos modelos nao sao comparaveis diretamente. A decisao nativa tambem
sinalizou 0 segmentos no IF e 20 no LOF; nao foi usada para ajustar limiares.

## 2. Como interpretar

O resultado demonstra respostas diferentes a esta captura. Nao estabelece
superioridade geral do IF, nem eficacia de deteccao de ataques. A atividade HTTP
foi planejada sem ataques, mas o adaptador nao converte esse contexto em rotulos
verdadeiros por segmento.

O LOF pode ser sensivel a diferencas entre treinamento e laboratorio, incluindo
a revisao do extrator. Essa e uma hipotese, nao uma causa isolada demonstrada:
ambiente e extracao mudaram juntos. Tampouco se demonstrou que o IF detectaria
ataques por ter deixado de sinalizar estes segmentos.

Nao foram calculadas acuracia, precisao, recall, F1 ou FPR. Os percentuais
observados sao taxas de sinalizacao (0% e 100%) nesta amostra pequena e
correlacionada. A meta de 1% de FPR usada para escolher limiares no CIC-IDS2017
nao constitui garantia no laboratorio.

## 3. Acoes realizadas e justificativas

### Passo 1 — reconhecimento explicito do experimento

O executavel exige `--accept-experimental-v4`. Sem essa opcao, para antes de
carregar modelos ou criar saidas. Isso permite o experimento autorizado, sem
homologar equivalencia semantica com o gerador historico do CIC-IDS2017.

O perfil fixa o commit `98a5ebad0df579cc8b43eedd3421b3ae87699901`. O manifesto
de extracao precisa declarar conclusao, repositorio oficial e timezone UTC.
A procedencia local e documentada por hashes; nao e uma assinatura externa.

### Passo 2 — validacao e adaptacao das features

`src/lab_v4_adapter.py` reutiliza a auditoria existente para verificar hashes
do PCAP/CSV e revisao declarada. Normaliza nomes, aplica os 11 aliases V4 e
rejeita colisoes. Confere nomes, ordem e tipos das 60 features contra os
manifestos congelados: 39 int64 e 21 float64.

Ausencias, NaN, infinitos, booleanos e fracoes em campos inteiros causam erro.
O perfil valida IPs IPv4, portas inteiras e protocolo TCP. Nao ha preenchimento
de valores, truncamento de flags, substituicao de janelas TCP, uniao de segmentos
ou descarte dos segmentos sem payload. Nao se ajustam features para caber no Monday.

### Passo 3 — separacao entre numeros e contexto

`features` contem exclusivamente os 60 numeros do modelo. `context` conserva
IPs, portas, protocolo, linha do CSV, grupo de endpoints, commit/imagem, hashes,
cenario e avisos. Cada registro carrega `production_approved=false`,
`semantic_compatibility=not_established` e `ground_truth_available=false`.

A coluna `Label`, inclusive `NeedManualLabel`, nao alimenta o modelo nem produz
verdade de referencia. Os agrupamentos com/sem payload sao apenas descritivos.

### Passo 4 — identidade e horario

O ID deriva da versao do adaptador, commit, hashes da captura/CSV e linha.
Linhas iguais em posicoes distintas nao colidem. Reexecutar o mesmo CSV conserva
os IDs; reordenar ou mudar o CSV muda os IDs.

`25/10/2026 07:22:16 PM` foi interpretado como `2026-10-25T19:22:16+00:00`,
segundo o UTC declarado pelo extrator. O CSV fornece precisao de segundos:
nao foram fabricados microssegundos nem usado o momento da inferencia como
horario observado. Segmentos distintos podem compartilhar timestamp e Flow ID.

### Passo 5 — inferencia sem novo treinamento

`predict_lab_v4.py` reutiliza `AnomalyInferenceService`, sem alterar esse servico.
Cada `.joblib` precisa coincidir com o SHA-256 registrado antes da
desserializacao; a ordem das features e comparada ao bundle.

O IF usa seu estimador existente. O LOF usa seu pipeline existente, incluindo
o StandardScaler ja ajustado no treinamento. Nao se chama `fit`, nao se aprende
outro scaler e nao se escolhe limiar com a captura. Ambos usam
`validation_fpr_operational` do registro operacional.

Os modelos, registro, manifestos e entradas sao novamente conferidos ao final.

### Passo 6 — arquivos separados e sem sobrescrita

Saida principal: `data/lab/lab02_http/inference_v4_run1/`:

- `model_inputs.json`: 20 objetos, com features e contexto separados;
- `isolation_forest_predictions.json`: decisoes e scores do IF;
- `lof_predictions.json`: decisoes e scores do LOF;
- `run_manifest.json`: limiares, resumos, runtime, hashes do codigo/arquivos,
  verificacoes de integridade e limitacoes.

A pasta precisa ser nova: nao ha sobrescrita. Os dados ficam sob `data/lab/`,
ja excluido do versionamento. Nao foram modificados MongoDB, PostgreSQL,
Grafana, firewall ou configuracoes das VMs.

## 4. Pendencia dos JSONs auxiliares de metadados

Na verificacao inicial, os dois `*_metadata.json` nao coincidiram com os hashes
historicos do registro. A causa exata nao foi estabelecida; nao foi possivel
atribuir conclusivamente a diferenca apenas ao rename ou a finais de linha.
Esses arquivos e seus hashes registrados nao foram alterados.

Os dois `.joblib` coincidem exatamente com os hashes registrados. A inferencia
usa bundle, registro e contrato validado; nao le esses JSONs auxiliares para
obter parametros ou executar predicoes. O bloqueio por divergencia no modelo
foi mantido. A divergencia auxiliar e um aviso explicito no manifesto, com
hashes esperado/observado e `used_for_inference=false`.

Os JSONs auxiliares tambem entram na comparacao antes/depois e permaneceram
inalterados durante o experimento. Isso nao significa que estejam identicos as
versoes historicas. A pendencia de procedencia permanece registrada.

## 5. Testes e repeticao

Passaram 31 testes: 12 do adaptador/runner, 10 da auditoria, 4 de alinhamento/
divisao e 5 do servico existente. Incluem dados invalidos, separacao de rotulos,
preservacao de segmentos, identidade deterministica, sobrescrita e integridade.

A inferencia real foi repetida em `data/lab/lab02_http/inference_v4_batch7/`,
com lotes de sete em vez do lote unico inicial. Entradas, IDs e decisoes foram
iguais. A diferenca maxima absoluta dos scores foi 0 no IF e
`4.547473508864641e-13` no LOF, compativel com arredondamento numerico, sem mudar
classificacoes. Horarios de processamento diferem entre execucoes.

Foram verificados depois da execucao os hashes de entradas, modelos,
manifestos, codigo e saidas contra o manifesto principal.

## 6. Como repetir

Na raiz do projeto, usando a extracao V4 existente e uma pasta de saida nova:

```powershell
.\.venv\Scripts\python.exe -B predict_lab_v4.py `
  --pcap .\data\lab\lab02_http\input\47788496-de5d-46de-b0cd-64f201001a38_hn2.pcap `
  --extraction-dir .\data\lab\lab02_http\extracted `
  --output-dir .\data\lab\lab02_http\inference_v4_run2 `
  --scenario lab02_http_controlled `
  --accept-experimental-v4
```

Esse passo nao exige Docker: o CSV ja existe. Uma nova captura exige antes
`extract_lab_flows.ps1`, conforme a documentacao da extracao.

Para ler o resumo existente sem recalcular:

```powershell
$labRun = Get-Content .\data\lab\lab02_http\inference_v4_run1\run_manifest.json -Raw | ConvertFrom-Json
$labRun.models.isolation_forest.summary.all_segments
$labRun.models.lof.summary.all_segments
$labRun.integrity.warnings
```

Testes:

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_lab_v4_adapter tests.test_lab_flow_audit tests.test_data_split tests.test_inference_service -v
```

O runtime emitiu avisos sobre a localizacao original do Python e a consulta de
nucleos fisicos via WMIC indisponivel. Nestas execucoes nao foram fatais:
houve codigo zero, resultados finitos e repeticao consistente. Nao se alterou
o ambiente Python para eliminar esses avisos nesta etapa.

## 7. Uso no TCC e proximo experimento

Relato adequado: "Na captura HTTP controlada, os modelos congelados
apresentaram taxas de sinalizacao distintas: 0 de 20 segmentos para o Isolation
Forest e 20 de 20 para o LOF, nos limiares operacionais previamente definidos.
A amostra deriva de dez conexoes e emprega extrator com diferencas conhecidas
em relacao ao gerador historico do treinamento. Os resultados demonstram a
integracao tecnica, mas nao estabelecem desempenho em producao."

Proxima etapa recomendada: ampliar capturas benignas controladas com variedade
de duracoes, volumes e servicos, preservando modelos e limiares. Depois,
comparar distribuicoes das features e scores com o treinamento para investigar
os alertas do LOF. Nao ajustar limiares apenas para fazer alertas desaparecerem.
Experimentos de ataque ficam separados e dependem de escopo e rotulagem definidos.
