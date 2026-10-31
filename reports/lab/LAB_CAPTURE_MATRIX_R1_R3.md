# Fechamento da matriz de capturas — LAB03–LAB06, r1–r3

## 1. Escopo concluído

Foram recebidas, preservadas, validadas e processadas as 12 sessões planejadas:
quatro cenários HTTP sintéticos, com três repetições cada, entre Windows-LAB
172.31.50.161 e Kali 172.31.60.10:8000, observados em hn2/KALI no OPNsense.
São **162 downloads/conexões e 324 segmentos V4**. O teste inicial LAB02 fica
fora dessa matriz; incluindo-o, o snapshot tem 13 sessões, 172 conexões e
344 segmentos. Não confundir downloads, conexões e segmentos exportados.

O snapshot reproduzível é `lab_capture_summary_complete_r1_r3.json`. O
consolidador conferiu hashes das saídas, PCAPs e a mesma identidade dos modelos,
ponto operacional e limiares antes de reunir os dados. As durações de conexão
e de payload foram reconstruídas do PCAP, não substituídas pelo tempo do cliente.

## 2. Método preservado

Cada recepção passou pela validação de plano/logs, ZIP/CRC, filtro/endpoints,
reconstrução TCP, conteúdo e hash dos corpos HTTP, handshakes e encerramentos.
LAB06 também exigiu marcador no cliente/PCAP, logs do servidor e critério
temporal previamente definido. Arquivos recebidos não foram executados como
instruções. Conteúdos das respostas correspondem aos payloads sintéticos.

A mesma imagem V4 do commit `98a5ebad0df579cc8b43eedd3421b3ae87699901` extraiu
os fluxos, sem rede e com entrada somente leitura. As 60 features seguiram o
mesmo contrato estrutural. Não houve imputação, clipping de flags, remoção/união
de segmentos ou uso da coluna Label como verdade de referência.

Modelos congelados:

- IF SHA-256 `d6f7754e14bbc7adb453eb298559efeebdccad98f59143283dc74a78211b4f40`;
- LOF SHA-256 `6c014381d6dc5fc70a46941a450e2a60dc7b83b1bb0fcee43a7653107814df41`.

Ponto `validation_fpr_operational`, decisão score >= limiar: IF
0,615824439899627; LOF 91,08685969933371. Não houve treino, novo scaler,
calibração, atualização de banco ou alteração de rede pelo processamento.

## 3. Resultado das decisões

Cada célula abaixo contém segmentos sinalizados / segmentos exportados por sessão.

| Cenário | Conteúdo por download | Downloads por sessão | IF r1 / r2 / r3 | LOF r1 / r2 / r3 |
| --- | --- | ---: | --- | --- |
| LAB03 | 16 KiB | 30 | 0/60 · 0/60 · 0/60 | 39/60 · 31/60 · 33/60 |
| LAB04 | 256 KiB | 12 | 0/24 · 0/24 · 0/24 | 24/24 · 24/24 · 24/24 |
| LAB05 | 2 MiB, limite no cliente | 6 | 6/12 · 6/12 · 6/12 | 12/12 · 12/12 · 12/12 |
| LAB06 | 2 MiB, controle no servidor | 6 | 6/12 · 6/12 · 6/12 | 12/12 · 12/12 · 12/12 |

O IF repetiu as contagens e os grupos sinalizados em cada cenário. Em LAB05/06,
os sinalizados foram todos os segmentos com payload, não os sem payload.
No LOF, a contagem variou em LAB03: 9, 1 e 3 segmentos com payload sinalizados,
além de 30/30 sem payload em todas as sessões. Nos demais cenários todos os
segmentos foram sinalizados. Consequentemente, todas as conexões da matriz
têm ao menos um segmento sinalizado pelo LOF; isso não é um novo rótulo real.

São taxas de sinalização exploratórias, não precisão, recall, F1, acurácia ou
FPR de uma rede real. Não apresentar a média agregada de cenários heterogêneos
como índice de qualidade. O IF ter sinalizado menos não basta para declará-lo
mais eficaz: a matriz não mede detecção de ataques. Tampouco classificar os
resultados como ataques ou atribuir causalidade a uma única feature.

## 4. Resultado temporal

Valores abaixo são medianas dentro de cada sessão, não intervalos de confiança.

| Cenário | Conexão TCP r1 / r2 / r3 (s) | Intervalo de payload r1 / r2 / r3 (s) |
| --- | --- | --- |
| LAB03 | 0,0250925 / 0,039794 / 0,032885 | 0,000387 / 0,0004945 / 0,000541 |
| LAB04 | 0,026547 / 0,038539 / 0,025239 | 0,0019085 / 0,002255 / 0,002025 |
| LAB05 | 15,489380 / 15,485686 / 15,485365 | 0,0072275 / 0,007461 / 0,006837 |
| LAB06 | 15,899808 / 15,898840 / 15,8993945 | 15,8968775 / 15,896014 / 15,896079 |

LAB05 reproduziu conexões longas, mas payload em rajada de milissegundos no
ponto capturado. LAB06 reproduziu payload distribuído ao longo de cerca de
15,9 s nas 18 conexões das três sessões, com trace de 128 blocos por GET.
Isso demonstra a necessidade de verificar o comportamento no ponto de captura:
limite configurado no cliente não substitui observação do envio em rede.

Envio em blocos com pausas não é taxa perfeitamente uniforme em qualquer janela.
Controle de envio, volume, ambiente e particularidades da extração não foram
isolados como causas independentes de cada score. A semelhança das contagens
LAB05/06 não elimina suas diferenças temporais.

## 5. Limitações e ocorrências preservadas

1. **Compatibilidade semântica não estabelecida.** O diagnóstico das 60 features
   (`FEATURE_DIAGNOSTICS_R1.md`) demonstrou flags históricas limitadas a 0/1 e
   contagens V4 maiores. A decomposição geométrica naquele relatório não é
   atribuição do score LOF nem importância no IF. Não houve conversão artificial
   das flags para reduzir alertas.
2. **Amostra restrita.** Três sessões por cenário, mesmo ambiente e endpoints,
   HTTP sintético, segmentos correlacionados e tráfego filtrado não representam
   sete dias de uma empresa. Não tratar 324 segmentos como 324 sessões
   independentes nem produzir inferência estatística robusta a partir deles.
3. **Pausas maiores.** LAB03/r1 teve máximo de cerca de 10,07 s entre inícios;
   LAB04/r1, cerca de 9,59 s; LAB05/r3, 65,884717 s entre o segundo/terceiro
   inícios, sendo cerca de 50,391833 s entre conclusão do segundo e início do
   terceiro no cliente. Causas não determinadas; ocorrências preservadas nos
   relatórios, sem selecionar somente sessões com tempos favoráveis.
4. **Perdas e cobertura.** Não foram fornecidos contadores de drops. Conteúdo
   HTTP completo e ausência de registros truncados não provam ausência de toda
   perda nem observação do tráfego fora dos filtros.
5. **Rastreabilidade.** Os originais de LAB04/r3 ficaram indisponíveis em
   Downloads após importação; as cópias preservadas conferem com os hashes de
   recepção. Não houve remoção por este processamento. Persistem avisos dos
   JSONs auxiliares de metadados com hashes históricos divergentes, que não
   são usados para inferência; os modelos joblib foram conferidos.
6. **Operacional não é nativo.** LAB04 tem IF nativo sinalizando os segmentos
   com payload, embora o ponto operacional não sinalize nenhum. Identificar
   sempre o limiar utilizado. Scores não são probabilidades nem têm escalas
   diretamente comparáveis entre IF e LOF.

## 6. Arquivos, testes e encerramento desta etapa

Os dados brutos e inferências ficam separados em `data/lab/<cenário>/r1|r2|r3/`,
com recibos de validação, ZIP/PCAP, logs, extrações e manifestos de inferência.
Os relatórios de cada sessão documentam os hashes e suas ocorrências.
Os snapshots anteriores foram mantidos, sem sobrescrita.

Na última recepção passaram 50 testes selecionados: 39 de consolidação,
diagnóstico, adaptador, auditoria e validação HTTP, mais 11 do LAB06 sem repetir
o teste HTTP real de loopback. Avisos conhecidos de localização do Python e
consulta WMIC tiveram fallback e não impediram a conclusão com exit 0.

A matriz planejada de coleta benigna está concluída. Não há captura adicional
obrigatória para fechá-la. Isso não conclui a validação de segurança em produção.
O material sustenta uma discussão acadêmica de transferência de domínio,
compatibilidade de extração, segmentação e variabilidade de sinalização.
Uma próxima etapa pode organizar essas evidências para apresentação; ataques,
mudanças de modelos ou integração em banco exigem escopo próprio e não foram
iniciados automaticamente.

Reprodução do snapshot na raiz, com saída nova:

```powershell
.\.venv\Scripts\python.exe -B summarize_lab_captures.py --include-run lab03_small_r2=data/lab/lab03_small/r2/inference --include-run lab04_medium_r2=data/lab/lab04_medium/r2/inference --include-run lab05_slow_r2=data/lab/lab05_slow/r2/inference --include-run lab06_serverpaced_r2=data/lab/lab06_serverpaced/r2/inference --include-run lab06_serverpaced_r3=data/lab/lab06_serverpaced/r3/inference --include-run lab05_slow_r3=data/lab/lab05_slow/r3/inference --include-run lab04_medium_r3=data/lab/lab04_medium/r3/inference --include-run lab03_small_r3=data/lab/lab03_small/r3/inference --output reports/lab/lab_capture_summary_complete_r1_r3_recheck.json
```
