# Repetições r2 e r3 — capturas HTTP controladas

Atualização após recepção dos arquivos: os quatro cenários r2 foram coletados,
validados e processados. Resultados em `LAB03_SMALL_R2.md`, `LAB04_MEDIUM_R2.md`,
`LAB05_SLOW_R2.md` e `LAB06_SERVERPACED_R2_RESULTS.md`. O roteiro abaixo preserva
o plano original. LAB06/r3 também foi validado e processado; resultados em
`LAB06_SERVERPACED_R3_RESULTS.md`. LAB05/r3 também foi processado, com ressalva
sobre uma pausa maior entre pedidos (`LAB05_SLOW_R3.md`). A próxima sessão é
LAB03/r3. LAB04/r3 foi validado (`LAB04_MEDIUM_R3.md`), com cópias preservadas
conferidas e ressalva de indisponibilidade posterior dos originais em Downloads.
LAB03/r3 também foi validado (`LAB03_SMALL_R3.md`), concluindo as 12 sessões.
O fechamento está em `LAB_CAPTURE_MATRIX_R1_R3.md`; não há coleta pendente
para completar esta matriz. As instruções abaixo ficam como registro do plano.

## 1. O que repetir e por quê

Repetir LAB03, LAB04, LAB05 e LAB06 duas vezes, mantendo payloads, endereços,
porta, helpers, captura, extrator V4, modelos e limiares. São oito novas sessões
e 108 downloads planejados. O LAB02, baseado numa listagem de diretório, fica
como teste inicial e não entra nessa matriz. Não presumir antecipadamente o
número de segmentos que o extrator produzirá.

| Cenário | Downloads por sessão | Conteúdo por download | Pausa do cliente | Controle de velocidade |
| --- | ---: | ---: | ---: | --- |
| lab03_small | 30 | 16 KiB | 2 s | Cliente: 512K |
| lab04_medium | 12 | 256 KiB | 3 s | Cliente: 512K |
| lab05_slow | 6 | 2 MiB | 3 s | Cliente: 128K |
| lab06_serverpaced | 6 | 2 MiB | 3 s | Servidor: 128 blocos de 16 KiB, pausas de 0,125 s |

Ordem previamente proposta: r2 = LAB03 → LAB04 → LAB05 → LAB06;
r3 = LAB06 → LAB05 → LAB04 → LAB03. A inversão reduz o alinhamento entre cenário
e ordem, mas não é randomização completa nem elimina efeitos de cache ou carga.
Registrar a ordem e os horários reais; preservar tentativas com falhas. Não
repetir seletivamente até obter menos alertas.

## 2. Antes de cada sessão

1. Manter OPNsense, Windows-LAB e Kali ligados. Windows permanece apenas em
   LAB-LAN, Kali apenas em LAB-ATAQUE. Não adicionar adaptador externo às duas
   VMs, não abrir regra para qualquer destino e não compartilhar o disco pessoal.
2. Conferir Windows `172.31.50.161`, Kali `172.31.60.10`, respectivos gateways
   `172.31.50.1` e `172.31.60.1`. Se o DHCP mudar o Windows, interromper:
   helpers e regras têm origem fixa. Planejar uma reserva antes de prosseguir.
3. Não executar capturas simultâneas ou outros geradores de tráfego. Identificar
   e encerrar com Ctrl+C somente o servidor de teste anterior, após guardar seus
   logs. Não assumir que o servidor temporário de exportação serve os payloads.
4. Confirmar o servidor com HEAD **antes** de iniciar a captura. Isso evita
   misturar o teste de disponibilidade com os downloads medidos.

## 3. Primeira ação: LAB03/r2

No Kali, com a porta 8000 livre, iniciar o servidor original dos LAB03–LAB05:

```bash
python3 -m http.server 8000 --bind 172.31.60.10 --directory /lab-http
```

Esse terminal deve permanecer aberto. Os payloads já preparados ficam em
`/lab-http/benign-v1`. Não é necessário instalar pacote ou acessar a internet.

No Windows-LAB, conferir o arquivo pequeno:

```powershell
curl.exe --noproxy "*" --fail --max-time 10 -I http://172.31.60.10:8000/benign-v1/small_16k.bin
```

Esperado: HTTP 200 e Content-Length 16384. Em caso de falha, não iniciar a
coleta. Confirmar também que `C:\TCC\run_benign_http.ps1` é o helper já utilizado.

## 4. Captura no OPNsense

Criar um **novo job** para cada sessão, sem reiniciar os jobs antigos:

| Campo | Valor |
| --- | --- |
| Interface | hn2 [KALI] |
| Address Family | IPv4 only |
| Protocol | TCP |
| Host Address | 172.31.50.161 |
| Port | 8000 |
| Packet Length | 65535 |
| Count | 50000 |
| Promiscuous / inversões | Desmarcados |
| Description inicial | lab03_small_r2 |

Iniciar o job. O limite de pacotes é um teto, não o número esperado: se a
captura atingir o teto antes do fim, preservar a tentativa e investigar.

Somente após iniciar a captura, executar no Windows-LAB:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab03_small -Repetition 2 -CaptureStarted
```

O Bypass vale apenas nesse processo, sem mudar a política permanente do Windows.
Não exige abrir o terminal como administrador para essa finalidade. Não copiar
os caracteres de prompt `PS>` ou `>>`.

Esperado: 30 downloads concluídos, HTTP 200, 16384 bytes cada. O cliente cria
uma pasta própria em Documentos\TCC-Lab-Capturas com `requests.jsonl` e
`run_manifest.json`. Guardar a pasta da sessão correta, não apenas os arquivos
com o mesmo nome que já estão em Downloads.

Ao finalizar, esperar cinco segundos, parar o job e baixar o ZIP do OPNsense.
Separar os três arquivos por sessão: ZIP + manifesto do cliente + JSONL do
cliente. Enviar primeiro **somente LAB03/r2** para conferência antes dos demais.

## 5. Demais cenários com servidor comum

Após validar a primeira coleta, repetir o procedimento com novo job e novo nome:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab04_medium -Repetition 2 -CaptureStarted
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_benign_http.ps1" -Scenario lab05_slow -Repetition 2 -CaptureStarted
```

Não executar as duas linhas seguidas sob o mesmo job: cada uma é uma sessão
separada com preparação, captura e exportação próprias. Em r3 usar `-Repetition 3`
e os nomes terminados em `_r3`, respeitando a ordem proposta. A opção PlanOnly
do helper permite consultar o plano antes da coleta.

## 6. LAB06 exige servidor diferente e logs adicionais

Parar o servidor comum. O script `lab06_server.py` precisa estar disponível
na ISO já preparada, montada somente para leitura em `/mnt/tcc`, ou em uma cópia
local previamente conferida. Não iniciar a VM pela ISO. Se não estiver montada,
seguir o roteiro de transferência em `LAB06_SERVER_PACING.md`.

Para r2, no Kali:

```bash
sudo python3 /mnt/tcc/lab06_server.py --log-dir /tmp/lab06-r2
```

A pasta deve ser nova; não apagar uma sessão existente. O servidor aceita seis
GETs de dados: reiniciar para cada repetição, com `/tmp/lab06-r3` em r3. HEAD
não consome esse limite. Antes da captura, no Windows:

```powershell
curl.exe --noproxy "*" --fail --max-time 10 -I http://172.31.60.10:8000/benign-v1/large_2m.bin
```

Conferir HTTP 200, Content-Length 2097152 e `X-TCC-Pacing: server-128k-v1`.
Criar o job `lab06_serverpaced_r2` com os mesmos filtros; iniciar e executar:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\TCC\run_lab06_http.ps1" -Repetition 2 -CaptureStarted
```

Usar o helper dedicado, sem `-Scenario` nem controle de taxa no cliente.
Esperados seis downloads de 2 MiB, perto de 16 s cada, mais as pausas; os tempos
reais serão conferidos no PCAP, não presumidos pelo tempo do cliente.

Ao terminar: esperar cinco segundos, parar/baixar a captura, depois Ctrl+C no
servidor para finalizar seu manifesto. Exportar `server_requests.jsonl` e
`server_manifest.json` conforme a seção 6 de `LAB06_SERVER_PACING.md`, usando
a pasta `/tmp/lab06-r2` e um destino Windows novo. Essa exportação acontece
**fora da captura**. Encerrar o servidor temporário de exportação ao terminar.

LAB06 gera cinco evidências obrigatórias por repetição: ZIP, dois arquivos do
cliente e dois do servidor. Guardar também os cabeçalhos como evidência extra.

## 7. O que será analisado depois

Validar integridade, conteúdo, logs, reconstrução TCP e duração do payload em
cada sessão antes de extrair as mesmas 60 features. Comparar resultados por
sessão e por grupo com/sem payload. Descrever mediana e variação entre sessões,
sem tratar segmentos correlacionados como observações independentes.

Os resultados r1 e o diagnóstico de features serão preservados. Os modelos e
limiares continuam congelados; esta coleta não autoriza recalibrá-los. Nenhuma
captura r2/r3 foi realizada automaticamente por este roteiro.
