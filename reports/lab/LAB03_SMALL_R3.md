# LAB03 pequeno / repetição 3 — validação e inferência

Sessão de 26/10/2026 UTC (25/10/2026 em Brasília) validada e processada com os
modelos e limiares congelados. Esta coleta completa a matriz LAB03–LAB06/r1–r3.

## 1. Evidências

O manifesto identifica `lab03_small`, repetição 3, completed e 30 pedidos
bem-sucedidos, com limite planejado 512K no cliente e pausas de dois segundos.
Os anexos foram tratados como dados, não como instruções. Cópias idênticas
foram preservadas em pasta nova `data/lab/lab03_small/r3/`. Os três originais
em Downloads ainda conferiam com os hashes na reconferência final.

| Evidência | SHA-256 |
| --- | --- |
| ZIP b13c09b1-4b53-474e-af7c-dc4142c2b5c3.zip | 44f0ce32833a0282f738ced1eed09cd77862c2f797261e57142d3e584100f64f |
| Manifesto do cliente | 168b5679c15959fff4630320c4ddf34f041d1f963fe6b41d19ac95ae0d51b87a |
| JSONL do cliente | 989cd2744c10b26f990c63c677e3d31dd7a8d0472c72a6a3465bf3131a7eb2d6 |
| PCAP | 9a1565121ca1c0e935e3d787265d43c97e5332ad6fbc1459f867608f996346b2 |
| CSV V4 | 93fa3df253a7768a34236d8562e18594e50c919e963303be2d45bd42c0721783 |

## 2. Validação e extração

O validador conferiu plano/logs, configuração, ZIP/CRC e endpoints, depois
remontou os streams TCP para verificar GETs HTTP/1.0, respostas 200, corpos,
handshakes e encerramentos bidirecionais nas 30 conexões.

| Verificação | Resultado |
| --- | --- |
| Origem / destino | 172.31.50.161 → 172.31.60.10:8000 |
| Downloads / conexões | 30 / 30 |
| Corpo por resposta | 16.384 bytes |
| Corpos totais | 491.520 bytes (480 KiB) |
| Pacotes | 662 |
| Registros truncados / TCP RST | 0 / 0 |
| Payload duplicado na remontagem | 0 bytes |
| Primeiro ao último pacote | 59,359066 s |
| Intervalo entre inícios | mínimo 2,016962 s; mediana 2,047058 s; máximo 2,091979 s |

Todos os corpos conferem com o hash sintético esperado
`cd5ec79e336fdd6d7a99307f3ad191efc8878f0a23dcdb2e65fc13a0154b0ada`.
Não houve pausa longa comparável à do LAB05/r3. Não foi fornecido contador de
drops: reconstrução completa de HTTP não demonstra ausência de toda perda.

Foi reutilizada a imagem V4 existente, commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`, sem rede e com PCAP somente leitura.
O pipe Docker foi bloqueado na sandbox; a execução autorizada fora dela concluiu
sem build ou instalação. Foram exportados 60 registros (61 linhas contando o
cabeçalho): 30 com payload e 30 sem payload. Somam 662 pacotes e 500.730 bytes
de payload TCP, incluindo pedidos/cabeçalhos, não apenas os corpos HTTP.

As 60 features passaram em tipos, ordem e finitude, schema
`07bd5818c91930b6ceb8178e160d9365260f6b92f629fa02ef14227cfaa113a4`.
Não se removeram/uniram segmentos, preencheram valores, converteram flags para
0/1 ou usaram rótulos Label. Equivalência semântica com o extrator histórico
continua não estabelecida.

## 3. Resultado operacional e comparação

Ponto `validation_fpr_operational`, regra score >= limiar. IF utiliza
0,615824439899627; LOF utiliza 91,08685969933371.

| Grupo | Segmentos por sessão | IF r1 / r2 / r3 | LOF r1 / r2 / r3 |
| --- | ---: | --- | --- |
| Com payload | 30 | 0 / 0 / 0 | 9 / 1 / 3 |
| Sem payload | 30 | 0 / 0 / 0 | 30 / 30 / 30 |
| Total | 60 | 0 / 0 / 0 | 39 / 31 / 33 |

LOF total: 65%, 51,67% e 55% de sinalização; com payload: 30%, 3,33% e 10%.
O resultado não é uma melhora monotônica. Todas as 30 conexões continuam com
ao menos um segmento sinalizado pelo LOF em cada sessão, pelos segmentos finais
sem payload. No ponto nativo foram zero IF e 60 LOF em r3.

Em r3, IF máximo 0,49013876532222667, abaixo do limiar. LOF com payload:
mediana 86,74695298200675 e máximo 481,3314651770787; sem payload: mediana
728,9076206754969. Scores não são probabilidades nem têm escala comparável
entre modelos. Não se calcularam métricas supervisionadas de produção.

| Medida, mediana | r1 | r2 | r3 |
| --- | ---: | ---: | ---: |
| Conexão TCP completa | 25,0925 ms | 39,794 ms | 32,885 ms |
| Intervalo de payload do servidor | 0,387 ms | 0,4945 ms | 0,541 ms |
| Segmento V4 com payload | 1,859 ms | 1,8805 ms | 2,0265 ms |
| Segmento V4 sem payload | 23,1155 ms | 37,559 ms | 28,5135 ms |

Medianas das flags com payload foram iguais nas três sessões: ACK 18, PSH 5,
SYN 2. Isso não garante igualdade de todas as linhas ou demais features, nem
determina a causa da variação dos scores. LAB03 soma 90 downloads e 180 segmentos
nas três sessões, pequenos e correlacionados no mesmo ambiente.

## 4. Integridade, testes e arquivos

Os hashes dos modelos correspondem ao registro operacional; entradas protegidas,
originais, cópias e saídas foram conferidos. Persistem os avisos dos JSONs
auxiliares de metadados com hashes históricos divergentes, que não são usados
para inferência. O runtime avisou sobre o caminho do Python e consulta WMIC,
usou núcleos lógicos e concluiu com exit 0.

Passaram 50 testes selecionados: 39 de consolidação, diagnóstico, adaptador,
auditoria e validação HTTP, e 11 do LAB06 sem repetir o teste HTTP real de
loopback. Não houve mudança de código para processar esta sessão, treino,
calibração, banco ou alteração de rede/VM/firewall.

Evidências em `data/lab/lab03_small/r3/`: `input/`, `client_logs/`, `extracted/`,
`inference/` e `capture_validation.json`. Consolidado completo em
`reports/lab/lab_capture_summary_complete_r1_r3.json`; discussão da matriz em
`reports/lab/LAB_CAPTURE_MATRIX_R1_R3.md`. Não há nova captura obrigatória
pendente dentro desta matriz; isso não representa conclusão de validação em produção.
