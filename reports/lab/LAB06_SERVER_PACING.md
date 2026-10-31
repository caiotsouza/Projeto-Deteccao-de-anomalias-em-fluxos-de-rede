# LAB06 — envio HTTP pausado no servidor

Estado: implementado, testado localmente e ISO verificada. **Ainda nao executado
nas VMs.** Nao houve alteracao em modelos, limiares, bancos, firewall ou interfaces.

Atualizacao posterior: a captura LAB06/r1 foi recebida e validada, incluindo
pacing observado no PCAP. Extracao e inferencia estao documentadas em
`reports/lab/LAB06_SERVERPACED_R1_RESULTS.md`. O restante deste arquivo conserva
o roteiro e o estado da preparacao anterior a coleta.

## 1. O que muda e por que

No LAB05, conexoes de cerca de 15,5 s continham payload observado em rajadas de
milissegundos. O LAB06 move o controle para as escritas do servidor Kali:

| Parametro | LAB06 |
| --- | --- |
| Origem / destino | Windows 172.31.50.161 -> Kali 172.31.60.10:8000 |
| Protocolo e arquivo | HTTP/1.0, mesmo sintetico de 2 MiB |
| Requisicoes | Seis, sequenciais, sem retries ou redirects |
| Envio no Kali | 128 blocos de 16 KiB |
| Pausa entre blocos | 0,125 s; 127 pausas, nominalmente 15,875 s |
| Limite de velocidade no cliente | Nenhum; nao usar --limit-rate |
| Pausa entre requisicoes | Tres segundos |
| Identificador | lab06_serverpaced_r1 |

O servidor da um flush por bloco e espera antes do proximo, sem compensar
atrasos com rajadas. A taxa nominal e proxima de 128 KiB/s, mas entrega e
temporizacao no PCAP continuam precisando de verificacao.

Isso nao isola perfeitamente uma unica causa: tambem muda a implementacao do
servidor e acrescenta cabecalhos de identificacao. Nao atribuir uma futura
mudanca no score exclusivamente a duracao sem analise adicional.

## 2. Arquivos preparados e protecoes

- `lab_tools/lab06_server.py`: servidor padrao Python, sem pacotes adicionais.
- `lab_tools/run_lab06_http.ps1`: cliente novo; o helper anterior foi preservado.
- `data/lab/transfer_iso/tcc_lab06_server.iso`: somente o servidor Python.
- `data/lab/transfer_iso/tcc_lab06_server.verification.json`: leitura independente.

O servidor vincula somente 172.31.60.10:8000, aceita apenas o IP Windows-LAB,
serve apenas o caminho do payload conhecido e verifica tamanho/hash antes de
servi-lo. Nao disponibiliza pastas pessoais, listagens ou uploads. HEAD nao
consome a cota; depois de seis tentativas GET, recusa tentativas extras.

O cliente exige o IP Windows-LAB e o reconhecimento humano da captura. Confere
HTTP 200, 2.097.152 bytes, endpoints e `X-TCC-Pacing: server-128k-v1`. Se o
servidor antigo ainda estiver ativo, a falta desse marcador causa interrupcao.
Nao ha retry automatico nem alteracao de politica permanente do PowerShell.

ISO: 59.392 bytes (58 KiB), nao inicializavel, um unico arquivo verificado
identico byte a byte a origem. Nenhuma unidade virtual foi alterada pelo agente.

- SHA-256 ISO: `ffc6290b8c3acb4fd63a4aec5180591a12a00c1537a829ee9e9828110b074182`.
- SHA-256 servidor: `1f1f3deaad867c97361bb9af70000d6758026ecf5f74c1eb05846b7cff50123a`.

## 3. Trocar o servidor no Kali, manualmente

Espere qualquer teste anterior terminar. No terminal em que o antigo
`python3 -m http.server` esta rodando, pressione Ctrl+C. Nao mate todos os
processos Python nem altere o firewall para resolver conflito de porta.

No Hyper-V, substitua a imagem do DVD do Kali pela ISO nova, sem mudar rede ou
ordem de boot. Caminho no Windows pessoal:

`.\data\lab\transfer_iso\tcc_lab06_server.iso`

No Kali, para a unidade sr0 ainda nao montada:

```bash
sudo mkdir -p /mnt/tcc
sudo mount -o ro /dev/sr0 /mnt/tcc
ls /mnt/tcc
```

Deve aparecer somente `lab06_server.py`. Se a unidade tiver outro nome,
confira com `lsblk` antes de montar. Nao execute a ISO antiga por engano.

Inicie o servidor:

```bash
sudo python3 /mnt/tcc/lab06_server.py
```

Ele usa o payload existente `/lab-http/benign-v1/large_2m.bin` e uma pasta nova
de logs `/tmp/lab06-r1`. Deve mostrar `LAB06 pronto` e o endereco esperado.
Deixe o terminal e a ISO abertos ate concluir os downloads. Nenhum trafego
e gerado apenas por iniciar o servidor.

Se a porta estiver ocupada, confira o servidor anterior. Se a pasta de logs
ja existir, nao a apague: preserve a tentativa e escolha outro nome, por
exemplo `--log-dir /tmp/lab06-r1-tentativa2`, registrando que foi nova tentativa.
Hash errado ou payload ausente causam erro antes de servir arquivos.

## 4. Preparar o novo cliente no Windows-LAB

Copie o conteudo de `lab_tools/run_lab06_http.ps1` para
`C:\TCC\run_lab06_http.ps1` na VM Windows-LAB. Nao substitua o arquivo anterior.
E preciso usar este helper novo: ele nao limita a leitura do cliente.

Antes de iniciar a captura:

```powershell
curl.exe --noproxy "*" --max-time 10 --fail --head http://172.31.60.10:8000/benign-v1/large_2m.bin
```

Confirme HTTP 200, Content-Length 2097152 e os cabecalhos:

```text
X-TCC-Pacing: server-128k-v1
X-TCC-Chunk-Bytes: 16384
X-TCC-Pause-Seconds: 0.125
```

Se nao aparecerem, pare: nao esta confirmado o servidor correto. Esse HEAD e
registrado no Kali, nao consome um GET e deve ficar fora da captura do experimento.

## 5. Capturar e executar

Crie um job **novo** no OPNsense:

| Campo | Valor |
| --- | --- |
| Interface | Apenas hn2 [KALI] |
| Promiscuous e inversoes | Desmarcados |
| Familia / protocolo | IPv4 only / TCP |
| Host / porta | 172.31.50.161 / 8000 |
| Packet Length / Count | 65535 / 50000 |
| Description | lab06_serverpaced_r1 |

Inicie o job e confirme atividade. Entao, no Windows-LAB:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_lab06_http.ps1" -Repetition 1 -CaptureStarted
```

Esperado: seis respostas HTTP 200, 2.097.152 bytes cada, marcador confirmado e
tempos proximos de 16 s, alem das pausas entre requisicoes. Sao estimativas,
nao dados ja medidos nas VMs. Nao use o comando antigo do LAB05.

Se houver erro, preserve captura e logs da tentativa. Nao troque limiares,
preencha valores ou selecione apenas tentativas com menos alertas.

Ao terminar: espere cinco segundos, pare o job no OPNsense e baixe o ZIP.
Somente depois pressione Ctrl+C no terminal do servidor Kali. Isso finaliza
`server_manifest.json` com status stopped e os contadores da sessao.

## 6. Recuperar os logs do Kali sem mudar a rede

O cliente preserva `requests.jsonl`, `run_manifest.json` e seis arquivos de
cabecalhos em uma pasta nova de Documentos\TCC-Lab-Capturas.

No Kali, os outros dois arquivos ficam em `/tmp/lab06-r1`:

- `server_manifest.json`: plano, hash do programa, inicio/fim e contadores;
- `server_requests.jsonl`: HEAD/GET, sucesso/erro e eventos dos 128 blocos.

Como a area de transferencia nao funciona no Kali, podemos recupera-los pela
mesma rota HTTP ja permitida, **depois que a captura foi parada**. Com o
servidor LAB06 ja encerrado, execute no Kali:

```bash
python3 -m http.server 8000 --bind 172.31.60.10 --directory /tmp/lab06-r1
```

Esse servidor temporario expoe somente a pasta dos logs sinteticos, nao a pasta
pessoal ou a raiz. No Windows-LAB, crie uma pasta de evidencias nova. Se ja
existir, pare e escolha outro nome, sem sobrescrever:

```powershell
New-Item -ItemType Directory -Path C:\TCC\LAB06_r1
curl.exe --noproxy "*" --fail --max-time 10 --output C:\TCC\LAB06_r1\server_manifest.json http://172.31.60.10:8000/server_manifest.json
curl.exe --noproxy "*" --fail --max-time 10 --output C:\TCC\LAB06_r1\server_requests.jsonl http://172.31.60.10:8000/server_requests.jsonl
```

Depois use Ctrl+C para encerrar tambem esse servidor temporario. A exportacao
nao deve entrar no PCAP LAB06 e nao abre uma conexao de rede do host pessoal
para o Kali; usa somente Windows-LAB -> Kali ja permitido.

## 7. O que enviar e como sera validado

Envie cinco arquivos, sem misturar com rodadas anteriores:

1. ZIP do OPNsense do job LAB06.
2. `requests.jsonl` do cliente Windows.
3. `run_manifest.json` do cliente Windows.
4. `server_requests.jsonl` do Kali.
5. `server_manifest.json` do Kali, apos encerrar o servidor.

Os cabecalhos individuais do cliente podem ser guardados como evidencia extra.
Nao envie senhas, pastas pessoais ou configuracao completa das VMs.

O validador foi ampliado para exigir marcador no cliente **e no PCAP**, fonte
do servidor conhecida, seis GETs completos e trace com 128 blocos. Para
considerar o objetivo temporal demonstrado, cada conexao precisa ter intervalo
de pelo menos 12 s entre primeiro/ultimo pacote com payload do servidor.
Esse piso e um criterio operacional deste ensaio (com folga sobre o nominal
15,875 s), nao uma metrica de seguranca ou classificacao.

Se o HTTP estiver completo mas o intervalo no PCAP for curto, o resultado sera
`validated_http_but_server_pacing_not_observed`. Preservaremos a captura e
investigaremos; nao a apresentaremos como envio sustentado nem corrigiremos
as features para fazer o criterio passar.

## 8. Testes realizados e limites

Passaram 45 testes: as 33 verificacoes anteriores e 12 novas de servidor,
cliente e validacao do LAB06. Incluem relogio simulado, conteudo/headers,
limite de GETs, cliente incorreto, payload desconhecido, interrupcao, ausencia
de marcador, protocolo de logs e PCAP sintetico com pacing versus rajada.

Um teste HTTP real usou exclusivamente 127.0.0.1 e porta efemera no host,
com o IP permitido substituido apenas em memoria durante o teste. Transferiu
2 MiB identicos em mais de 15,5 s. A sandbox bloqueou o socket; a execucao
fora dela foi autorizada. O socket foi encerrado ao fim. Isso nao prova o
comportamento das VMs ou do ponto hn2: a captura real ainda precisa ocorrer.

A ISO foi conferida por leitura independente. Nao se instalou pacote, nao se
anexou DVD automaticamente e nao se alterou servico algum nas VMs. Os modelos,
limiares, resultados anteriores e o helper LAB03-LAB05 foram preservados.

Referencias de implementacao:

- https://docs.python.org/3.13/library/http.server.html
- https://docs.python.org/3.13/library/time.html#time.monotonic
- https://curl.se/docs/manpage.html

`http.server` nao e recomendado para producao. Este helper serve somente este
ensaio isolado e nao e uma proposta de servidor corporativo.
