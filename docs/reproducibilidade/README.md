# Materiais complementares do TCC

Este diretório orienta a conferência dos resultados do artigo e a reprodução
dos procedimentos. O trabalho separa avaliação histórica, replay de previsões
e diagnóstico de capturas locais. Não valida monitoramento contínuo em produção.

## Organização

- `src/` e scripts na raiz: implementação de preparação, treino, avaliação,
  calibração, inferência e auditoria. `tests/`: testes automatizados.
- `data/processed/`: Parquet derivados, rótulos separados e manifesto ordenado
  das 60 características.
- `experiments/scale_100k/`: divisão ampliada, modelos, previsões e relatórios.
- `models/`: modelos do experimento inicial e metadados.
- `data/lab/`: PCAP, fluxos extraídos, registros de execução e inferência das
  sessões controladas que passaram pela revisão de publicação.
- `reports/`: relatórios de pré-processamento, modelos, limiares, integração e
  laboratório. `docs/artigo/`: artigo revisado e figuras.
- `docs/reproducibilidade/publication_manifest.json`: inventário de hashes dos
  arquivos distribuídos, com hashes originais quando houve remoção de caminhos
  pessoais dos metadados. A transformação não altera métricas ou decisões.

## Origem dos dados históricos

A fonte é o [CIC-IDS2017 da University of New Brunswick](https://www.unb.ca/cic/datasets/ids-2017.html).
Os CSVs originais não são duplicados no histórico Git. Consulte
`docs/reproducibilidade/original_data_manifest.json` para nomes, tamanhos e
SHA-256 dos arquivos usados. Baixe a base na fonte oficial e respeite seus
termos e a referência solicitada pelos autores. Os Parquet e os resultados
derivados publicados permitem conferir as matrizes e métricas sem baixar a
base completa. O treinamento utilizou Monday benigno; validação e teste
utilizaram os demais dias.

## Relação entre artigo e evidências

| Elemento | Evidência principal |
| --- | --- |
| Quadro 1 — divisão dos dados | `reports/metrics/data_split_report.json`; `experiments/scale_100k/metrics/data_split_report.json`; respectivos `split_manifest.json` |
| Quadro 2 e Figura 1 — métricas | `experiments/scale_100k/metrics/model_comparison.json` |
| Quadro 3 e Figura 2 — tempos | `reports/metrics/model_comparison.json`; `experiments/scale_100k/metrics/model_comparison.json` |
| Quadro 4 e Figura 3 — FPR-alvo | `reports/operational/operational_calibration.json` |
| Quadro 5 — 14 categorias | `experiments/scale_100k/metrics/model_comparison.json`, campo `models.*.splits.test.attack_categories` |
| Figura 4 — dashboard | `docs/artigo/figuras/figura4_dashboard_original.png`; `infra/grafana/dashboards/` |
| Quadro 6 — replay | `reports/marco12/replay_weekly_mongodb.json`; `grafana_contract_validation.json`; `in_memory_integration_validation.json` |
| Quadro 7 — benignos locais | `reports/lab/lab_capture_summary_complete_r1_r3.json`; `LAB_CAPTURE_MATRIX_R1_R3.md`; `data/lab/lab03_small/` a `lab06_serverpaced/` |
| Quadro 8 — cobertura LAB08 | `data/lab/lab08_tcp_responsive/r1/extraction_audit.json`; `extracted/extraction_run.json`; PCAP da mesma sessão |
| Quadro 9 — sinalizações | `reports/lab/lab08_subset_comparison_v1.json`; manifestos de inferência de cada sessão |

Os diretórios efetivamente distribuídos constam do inventário de publicação.
As fontes numéricas originais das Figuras 1–3 são os JSONs acima; os PNGs desta
revisão foram regenerados desses valores, sem alterar os resultados.
O código está em `tools/generate_article_figures.py`. Com Matplotlib instalado,
execute `python tools/generate_article_figures.py --output-dir output/figuras_conferencia`
para gerar cópias em uma pasta nova, sem sobrescrever as figuras publicadas.

## Protocolo e limites

Amostragem por prioridade determinística do hash de 64 bits das 60 entradas,
sem reposição, semente 42; embaralhamento de treino/validação/teste com
42/43/44. Cotas mínimas por ataque e conjunto: cinco quando disponíveis, com
distribuição proporcional do restante. Não há sobreposição de hashes entre
partições, mas não houve separação por sessão/campanha/tempo. Isso não elimina
dependência entre fluxos nem demonstra independência estatística. A seleção
das características examinou Monday antes da subamostragem do treino.

O ajuste dos estimadores é one-class/benigno. A seleção de limiar por F1 é
supervisionada pelos rótulos de validação. O limiar de FPR usa a parcela de
validação identificada como benigna; ataques dessa validação são usados para
recomendar o modelo. O teste não escolhe o limiar. Não houve novos treinos ou
calibrações na revisão do artigo.

Os parâmetros completos e versões declaradas estão nos metadados dos modelos.
O escore é `-score_samples`; maior significa mais anormal. O critério nativo
usa `decision_function < 0`; critérios calibrados usam `score >= limiar`.
Limiares integrais operacionais: IF `0.615824439899627`; LOF
`91.08685969933371`. Escores não são probabilidades e as escalas não são
comparáveis diretamente.

As versões informadas nos JSONs históricos e as do runtime local pertencem a
etapas diferentes; a conferência da identidade dos modelos deve usar SHA-256.
As divergências de metadados auxiliares estão preservadas nos relatórios locais.

O laboratório não demonstra equivalência semântica do extrator. LAB08 tem
42 pacotes e 30 grupos; o CSV representa 16 pacotes e quatro grupos. Os outros
26 grupos não receberam predição. `1/4` é uma sinalização nesse recorte, não
recall, precisão, FPR ou detecção da sondagem inteira. As três repetições
benignas não equivalem a repetições independentes do benchmark histórico.

## Conferência sem executar modelos

Na raiz do checkout, use Python e as dependências de `requirements.lock.txt`:

```powershell
python tools/verify_publication.py
python -m unittest discover -s tests -v
```

O primeiro comando confere os hashes publicados. O segundo verifica os testes
locais; não cria a base MongoDB. Para executar o projeto, consulte o README
da raiz e os resumos de cada marco. Não use `docker compose down --volumes`
se quiser preservar os dados do MongoDB.

Para gerar saídas novas, mantenha os artefatos congelados e use diretórios de
saída diferentes. Os relatórios registram a execução original; não confunda
tempos novos de sua máquina com os tempos publicados no artigo. A reprodução
integral entre sistemas operacionais não foi homologada nesta revisão.

## Privacidade e conservação

Não publicar `.env`, credenciais, volumes de banco, ambientes virtuais,
feedback privado do orientador, áudio, caches, imagens de desktop ou ISOs.
As capturas distribuídas pertencem ao laboratório controlado; endereços privados
e MACs virtuais são contexto experimental, não tráfego corporativo fornecido
por terceiros. Caminhos pessoais em registros textuais foram removidos na cópia
de distribuição. Os originais locais não foram alterados.

Conserve o repositório e a versão vinculada ao artigo. Não substitua arquivos
de uma versão publicada por resultados de novos experimentos. Licenças de
dependências e dados de terceiros continuam válidas; a disponibilização dos
artefatos não concede direitos adicionais sobre esses materiais.
