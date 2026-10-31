# LAB08/r1 — reconhecimento com respostas, extração parcial

Estado atualizado: após autorização explícita do usuário, IF e LOF foram
executados somente nos quatro registros exportados, não na sondagem completa.
No ponto operacional, IF sinalizou 0/4 e LOF 1/4. A cobertura segue parcial:
16 dos 42 pacotes representados; os 26 grupos de um SYN não foram exportados.
Auditorias anteriores permanecem preservadas. O comparativo está em
`lab08_subset_comparison_v1.md` e no JSON homônimo. As seções abaixo conservam
a cronologia, distinguindo o estado anterior da análise restrita autorizada.

## Resultado confirmado

Recebidos e preservados quatro arquivos em `data/lab/lab08_tcp_responsive/r1/`.
O ZIP passou no CRC e nas verificações de nomes, tipos e limites de tamanho;
contém apenas JSON de configuração e PCAP. Os três formatos Nmap concordam
quanto ao comando, alvo e estados de todas as 16 portas do plano. Nenhum
comando contido nos arquivos recebidos foi executado.

Nmap 7.99, TCP connect, alvo exclusivo 172.31.50.161, entre 20:50:04 e
20:50:08 de 26/10/2026 (Brasília), duração declarada 4,12 s. Portas 135, 139
e 445 abertas (reason syn-ack); as outras 13 filtered (reason no-response).
Os nomes de serviços são associações de tabela, não detecção de versões.
O status geral up/reason user-set não é evidência adicional de resposta.

| Medida independente do PCAP | Resultado |
| --- | ---: |
| Pacotes TCP/IPv4 | 42 |
| Kali → Windows | 38 |
| Windows → Kali | 4 |
| SYN / SYN+ACK / ACK / RST+ACK | 30 / 4 / 4 / 4 |
| Payload TCP | 0 bytes |
| Grupos de endpoints | 30 |
| Grupos com quatro pacotes | 4 |
| Grupos com somente um pacote | 26 |
| Registros truncados | 0 |
| Intervalo entre primeiro/último pacote | 3,901459 s |

Os quatro grupos bidirecionais são dois destinados à porta 135, um à 139 e
um à 445. São 3 pacotes forward e 1 backward em cada grupo. Não confundir
16 portas, 30 grupos, 42 pacotes ou quatro grupos bidirecionais com quantidade
de ataques independentes. Não houve exploração, autenticação ou payload.

Configuração: hn2/KALI, IPv4/TCP, host 172.31.50.161, porta vazia,
snaplen 65535, count 10000, descrição lab08_tcp_responsive_r1. Primeiro
pacote 2026-10-26T23:50:04.863926+00:00 e último
2026-10-26T23:50:08.765385+00:00. Janela compatível com o Nmap, com tolerância
de um segundo para seus timestamps inteiros; isso não prova sincronização
independente dos relógios. Contadores de perdas da captura não fornecidos.

O PCAP mostra respostas com IP de origem do Windows nas três portas abertas.
Não permite identificar a causa de filtered nas outras portas. A antiga
evidência de DROP do diagnóstico TCP135 não deve ser generalizada para esta
nova sessão, executada após uma mudança planejada de política.

## Histórico: indisponibilidade inicial do Docker

O script de extração foi chamado com a imagem V4 existente, mas o acesso ao
pipe dockerDesktopLinuxEngine falhou porque ele não foi encontrado. A mesma
tentativa autorizada fora da sandbox também falhou. Não houve processo
Docker Desktop/backend na consulta local posterior. Não se iniciou Docker,
reconectou WAN, instalou/compilou extrator ou alterou uma VM automaticamente.
A mensagem genérica do script sugerindo compilar imagem não demonstra falta
da imagem: primeiro é necessário disponibilizar o Engine.

Naquele momento não existia CSV V4 desta sessão nem resultado IF/LOF. A cobertura permanecia
desconhecida: os 26 grupos de pacote único são um risco conhecido de omissão,
não uma omissão já medida neste LAB08. Não criar registros artificiais nem
tratar um eventual subconjunto exportado como a varredura completa.

Após o usuário iniciar o Docker, os comandos abaixo foram concluídos a partir
da raiz do projeto. Registro de execução, não instrução para sobrescrever a saída:

```powershell
& .\extract_lab_flows.ps1 -PcapPath ".\data\lab\lab08_tcp_responsive\r1\input\3cd2b79b-5189-4314-8a17-e91d3083fc84_hn2.pcap" -OutputDirectory ".\data\lab\lab08_tcp_responsive\r1\extracted" -ExtractorProfile v4
.\.venv\Scripts\python.exe -B audit_lab07_extraction.py --session data/lab/lab08_tcp_responsive/r1
```

## Extração e auditoria concluídas antes da autorização de análise parcial

O Engine passou a estar disponível, mas a sandbox bloqueou o acesso ao pipe.
A repetição autorizada fora dela concluiu em contêiner sem rede, entrada
somente leitura, imagem e commit V4 congelados. O hash do PCAP permaneceu
inalterado. O CSV tem quatro linhas de dados (o contador de progresso do
extrator não é a contagem validada de linhas).

| Resultado auditado | Valor |
| --- | ---: |
| Registros CSV / features selecionadas | 4 / 60 |
| Pacotes representados / capturados | 16 / 42 (38,10%) |
| Grupos representados / capturados | 4 / 30 (13,33%) |
| Pacotes/grupos ausentes do CSV | 26 / 26 |
| Todos os grupos ausentes têm somente um pacote | Sim |
| Contrato estrutural e finitude | Aprovados |
| Cobertura da sondagem inteira | Parcial |
| Compatibilidade semântica com o extrator histórico | Não estabelecida |
| Inferência IF/LOF executada | Não |

As contagens forward/backward e durações dos quatro registros correspondem
aos grupos independentes no PCAP. Os quatro têm 3 pacotes forward e 1 backward,
sem payload; incluem dois grupos para 135, um para 139 e um para 445.
Os demais dados continuam preservados no PCAP; não se geraram substitutos
artificiais para SYNs isolados, nem se alteraram flags, features ou limiares.

CSV SHA256: `173cb66d04db948b40808409ebf1060cd846cf673c389316e6028e51fc55f3d1`.
`extraction_run.json` registra a execução e `extraction_audit.json` registra
o estado `partial_extraction_inference_not_performed`, incluindo cada grupo
não representado. Não sobrescrever essas evidências.

Próximo passo: não repetir r2/r3 automaticamente, pois repetir as mesmas
condições não resolve a limitação identificada. Para encerrar rapidamente,
pode-se manter esta sondagem como resultado de cobertura e limitação do
pipeline, junto dos comparativos benignos concluídos. Outra opção, mediante
decisão explícita, é comparar IF/LOF exclusivamente sobre os quatro registros
exportados, com denominador quatro e seleção condicionada à exportação, sem
denominar o resultado detecção/recall da sondagem completa. Essa análise
restrita ainda não havia sido autorizada nem executada naquele momento. Quatro registros correlacionados
não sustentam uma estimativa robusta de desempenho de detecção de ataques.

Manter a regra temporária TCC-LAB08-SCAN desabilitada fora de uma coleta
autorizada; a recepção dos arquivos não comprova a execução desse encerramento.
Não há necessidade de nova captura Pktmon para processar este PCAP.

## Rastreabilidade e testes

O recibo `scan_validation.json` guarda hashes das quatro fontes e confirma que
as cópias conferem com os originais no momento da importação. Seu campo
`windows_reachability_established=false` é conservador e não nega as respostas
observadas; `capture.reverse_packets_observed=true` registra a evidência bruta.
Não interpretar esse campo genérico como ausência de SYN+ACK.

- ZIP SHA256: `7f713558068e3bfaa30604f93155173f172a1b402e43646bb1fff19d91b74c03`.
- PCAP SHA256: `bf12f11f3237aa30dd26e54965560f6b819a5b3fb71dd9b6f07c7aed2836a677`.

O validador recebeu perfil fechado lab08_r1: exige caminho /tmp/lab08-r1/scan
e as 16 portas; o perfil padrão LAB07 continua separado. Dois testes novos
verificam separação de perfis e rejeição de portas/caminho divergentes.
Passaram 57 testes selecionados, incluindo regressões LAB07, diagnóstico,
auditoria, adaptador V4, validação HTTP, consolidação e diagnóstico de features.
Testes unitários não substituem a auditoria de cobertura, agora concluída.

## Análise parcial autorizada e concluída

Após o usuário autorizar o recorte, os modelos congelados foram carregados
e executados sem treino/recalibração. A entrada preservou todos os quatro
registros do CSV, sem selecionar por score, corrigir features ou mudar flags.
O novo manifesto em `inference_exported_subset/run_manifest.json` contém
`methodology.evaluation_scope.population=exported_records_only`, cobertura
recalculada a partir do PCAP e da auditoria original, autorização explícita
e `whole_scan_detection_measured=false`. As entradas e predições também
carregam a população avaliada no contexto. Não se sobrescreveu a auditoria
anterior que registra a decisão de não inferir a varredura completa.

IF operacional: 0/4, scores de 0,3666999943954883 a 0,39503515618629975.
LOF operacional: 1/4, scores de 35,98158848857759 a 222,22343337436564.
O registro sinalizado pelo LOF tem destino 139 e origem 56628; não inferir
causalidade a partir da porta. No critério nativo o LOF sinaliza 4/4, mas
o comparativo conserva o ponto operacional, não mistura os dois critérios.

O script `compare_lab08_subset.py` conferiu hashes de saídas e manifestos e
a mesma identidade de modelos/limiares nas 12 sessões benignas antes de
produzir o relatório e JSON comparativos. LAB02 ficou fora da matriz principal.
Não se calcula taxa de detecção da sondagem nem métricas supervisionadas.
Nenhuma alteração no MongoDB, Grafana, regras ou serviços foi executada.
