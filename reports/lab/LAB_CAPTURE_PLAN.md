# Ampliacao das capturas benignas — LAB03, LAB04 e LAB05

## Objetivo e limites

Variar volume e duracao mantendo HTTP/1.0, os mesmos endpoints e uma requisicao
por vez. Isso amplia a observacao sem introduzir simultaneamente novos servicos,
TLS, destinos externos ou ataques. Ainda nao representa uma rede corporativa
completa nem substitui uma avaliacao temporal de sete dias.

Nenhum trafego novo foi gerado nas VMs por esta preparacao. Foram criados os
helpers e testados tamanhos/hashes, protecao contra sobrescrita e o cliente com
curl simulado no Windows PowerShell. Os testes nao demonstram que o servidor ou
o firewall atual das VMs estejam prontos; isso sera conferido pelo preflight.

## 1. Topologia a conferir

- Windows-LAB: `172.31.50.161`, somente LAB-LAN.
- Kali: `172.31.60.10`, somente LAB-ATAQUE.
- OPNsense: LAN `172.31.50.1`, KALI `172.31.60.1`.
- LAB-LAN e LAB-ATAQUE precisam continuar com tipo **Private** no Hyper-V.
- Destino de todos os downloads: `172.31.60.10:8000`.
- Os experimentos nao precisam de internet, DNS externo ou adaptadores novos.

Switches privados nao impedem por si so o roteamento pelo OPNsense ate a rede
domestica. Regras amplas LAN-to-any nao garantem esse bloqueio. Para uma rodada
inteiramente offline, pode-se desconectar apenas o adaptador WAN da VM OPNsense
no Hyper-V, sem excluir o switch e sem alterar LAN/KALI. Isso e uma acao manual
opcional de isolamento; nao foi executada pelo assistente. Nenhuma regra nova
de firewall e necessaria para estes destinos se a regra HTTP anterior continua.

Se IPs ou vinculos diferirem, pare e confira antes de executar. Nao conecte
Windows/Kali ao Default Switch ou ao switch externo para facilitar a copia.

## 2. Matriz inicial

| Cenario | Arquivo | Requisicoes | Intervalo apos cada transferencia | Limite por transferencia | Corpo total por sessao |
| --- | --- | ---: | ---: | ---: | ---: |
| lab03_small | 16 KiB | 30 | 2 s | 512 KiB/s | 480 KiB |
| lab04_medium | 256 KiB | 12 | 3 s | 512 KiB/s | 3 MiB |
| lab05_slow | 2 MiB | 6 | 3 s | 128 KiB/s | 12 MiB |

Ha somente uma transferencia de cada vez, sem retries nem redirects. As pausas
ocorrem entre requisicoes, nao dentro do envio dos cabecalhos HTTP. O LAB05 e
um download normal com velocidade limitada, nao Slowloris nem teste de carga.

Estimativas: aproximadamente um minuto, quarenta segundos e dois minutos,
respectivamente, dependendo das VMs. O limite do curl e uma media, nao uma
garantia de ritmo exato de cada pacote. Contagem de requisicoes nao equivale a
contagem de fluxos ou segmentos exportados pelo CICFlowMeter.

Faca primeiro LAB03/r1. Depois de validar captura e logs, prossiga com LAB04/r1
e LAB05/r1. Uma segunda etapa pode repetir cada cenario tres vezes, com capturas
separadas e nomes r1/r2/r3: seriam nove sessoes e 144 requisicoes planejadas,
aproximadamente 46,4 MiB de corpos HTTP, fora cabecalhos/ACKs. Nao sao milhares
de observacoes independentes nem sete dias de uso real.

## 3. Preparar o Kali — somente dados sinteticos

Copie o conteudo de `lab_tools/prepare_http_payloads.py` para
`/tmp/prepare_http_payloads.py` dentro do Kali, sem adicionar interfaces de rede.
O script usa somente a biblioteca padrao do Python e nao instala pacotes.

Se a area de transferencia do Hyper-V nao funcionar, a ISO de transferencia
ja foi criada e verificada. Consulte `reports/lab/OFFLINE_SCRIPT_TRANSFER.md`;
esse caminho nao exige internet ou sessao aprimorada.

```bash
python3 /tmp/prepare_http_payloads.py --directory /lab-http/benign-v1
```

Ele exige uma pasta nova para nao sobrescrever arquivos anteriores. Cria:

- `/lab-http/benign-v1/small_16k.bin`: 16.384 bytes;
- `/lab-http/benign-v1/medium_256k.bin`: 262.144 bytes;
- `/lab-http/benign-v1/large_2m.bin`: 2.097.152 bytes;
- `/lab-http/benign-v1/payload_manifest.json`: tamanhos e hashes SHA-256.

Se a pasta ja existe porque esta preparacao foi feita antes, nao apague para
contornar a protecao: confira o manifesto ou informe o estado antes de repetir.
Guarde uma copia do manifesto junto das evidencias do experimento.

Mantenha o servidor anterior aberto, se ele ainda atende `/lab-http` no mesmo
IP e porta. Se estiver parado, inicie:

```bash
python3 -m http.server 8000 --bind 172.31.60.10 --directory /lab-http
```

Nao inicie dois servidores na porta 8000. Nao use `--bind 0.0.0.0` nem sirva a
pasta pessoal. Este servidor simples e somente para o laboratorio. Ele usa
HTTP/1.0 por padrao nas versoes documentadas; o cliente tambem pede HTTP/1.0.

## 4. Preparar o Windows-LAB e fazer preflight

Abra o PowerShell **dentro da VM Windows-LAB**, nao no computador pessoal.
Copie `lab_tools/run_benign_http.ps1` para `C:\TCC-Lab\run_benign_http.ps1`.
Pode-se abrir o arquivo no chat e copiar seu conteudo para o Bloco de Notas da
VM. Use o metodo de copia ja disponivel, sem criar uma ponte com a rede domestica.

Confira:

```powershell
ipconfig
curl.exe --version
curl.exe --noproxy "*" --max-time 10 --fail --head http://172.31.60.10:8000/benign-v1/small_16k.bin
```

O ultimo comando deve mostrar HTTP 200 e `Content-Length: 16384`. Execute esse
preflight **antes da nova captura** para nao mistura-lo com as 30 requisicoes.
Se houver erro 404, timeout ou outro IP, nao prossiga; confira servidor, pasta e
regra existente. Nao libere trafego para `any` como tentativa de correcao.

Para ver o plano sem enviar pacotes:

```powershell
Set-Location C:\TCC-Lab
.\run_benign_http.ps1 -Scenario lab03_small -PlanOnly
```

Se o PowerShell bloquear o script, pode-se invocar somente este processo com
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_benign_http.ps1 ...`.
Isso nao altera a politica permanente e nao exige abrir o terminal como admin.
Use apenas para este helper revisado; nao execute scripts desconhecidos assim.

## 5. Configurar uma captura nova no OPNsense

Em Interfaces > Diagnostics > Packet Capture, para LAB03/r1:

| Campo | Valor |
| --- | --- |
| Interface | Apenas hn2 [KALI] |
| Promiscuous | Desmarcado |
| Address Family | IPv4 only |
| Protocol | TCP |
| Invert Protocol / Invert Port | Desmarcados |
| Host Address | 172.31.50.161 |
| Port | 8000 |
| Packet Length | 65535 |
| Count | 50000 |
| Description | lab03_small_r1 |

O limite anterior de 2.000 pacotes pode cortar as transferencias maiores antes
de terminarem. Aqui 50.000 e um teto de seguranca, nao uma meta a atingir. Pare
manualmente ao fim da sessao. Se o teto for atingido, marque a captura como
potencialmente incompleta e repita separadamente; nao misture com capturas completas.

O valor 65535 preserva os pacotes desta rede sem o `0` rejeitado anteriormente
pela sua interface. Nao use snaplen 64/128 para reduzir tamanho, pois cortaria
payload necessario as features. Capture uma interface apenas para evitar
contabilizar duas vezes a passagem do mesmo trafego pelo firewall.

## 6. Iniciar LAB03/r1

1. Clique Start no OPNsense e confirme que o job esta ativo.
2. No Windows-LAB, espere tres segundos e execute:

```powershell
Start-Sleep -Seconds 3
Set-Location C:\TCC-Lab
.\run_benign_http.ps1 -Scenario lab03_small -Repetition 1 -CaptureStarted
```

3. A saida deve ir de `[1/30]` a `[30/30]`, sempre HTTP 200 e 16.384 bytes.
4. Espere cinco segundos apos concluir e pare o job no OPNsense.
5. Baixe o ZIP; nao reinicie/reutilize o job antes de preservar essa evidencia.

`-CaptureStarted` e uma confirmacao humana: o helper nao controla nem verifica
automaticamente o job do OPNsense. Ele verifica o IP local, fixa o bind do curl
em `172.31.50.161`, ignora proxy e envia apenas para `172.31.60.10:8000`.

Se qualquer transferencia falhar ou retornar tamanho/status inesperado, o
helper interrompe, registra a falha e nao faz retries. Preserve tambem a captura
interrompida; nao a apresente como sessao completa.

Os logs ficam em uma pasta nova dentro de
`%USERPROFILE%\Documents\TCC-Lab-Capturas\`:

- `requests.jsonl`: horario UTC, status, bytes, duracao, IPs e erro por tentativa;
- `run_manifest.json`: plano e totais tentados/concluidos, sem gerar rotulos.

Na sessao LAB03 completa, espere `status=completed`, `attempted_requests=30`
e `successful_requests=30`. Corpos HTTP somam 491.520 bytes; o PCAP sera maior
por incluir cabecalhos e pacotes de controle. O tempo de cada requisicao no log
nao deve substituir `flow_duration` calculado a partir dos pacotes.

## 7. Proximas sessoes — somente depois de conferir LAB03

Crie um job novo com descricao correspondente e repita a mesma sequencia:

```powershell
.\run_benign_http.ps1 -Scenario lab04_medium -Repetition 1 -CaptureStarted
.\run_benign_http.ps1 -Scenario lab05_slow -Repetition 1 -CaptureStarted
```

Esses comandos pertencem a **capturas separadas**, nao devem ser colados juntos
com um unico job. Confirme o encerramento e o ZIP da primeira antes da seguinte.
Repeticoes posteriores usam `-Repetition 2` ou `3`, sempre com outro job/ZIP.

## 8. Evidencias a trazer para analise

Para a primeira sessao, envie o ZIP do OPNsense e os dois logs do Windows-LAB.
Guarde tambem o manifesto dos payloads do Kali. Nao inclua senhas, configuracao
completa do firewall, arquivos pessoais ou capturas da WAN.

Organizacao sugerida no projeto:

```text
data/lab/lab03_small/r1/
  input/       ZIP original, JSON de captura e PCAP
  client_logs/ requests.jsonl e run_manifest.json
  extracted/   somente depois, resultado V4
  inference/   somente depois, resultados dos modelos
```

Nessa etapa conferiremos contagem, erros, truncamentos, endpoints e integridade
antes de executar os scripts V4 existentes. Os resultados anteriores serao
preservados. Scores nao serao usados para selecionar apenas capturas que deem
o resultado desejado; falhas tecnicas serao registradas, nao escondidas.

## Referencias de configuracao

- OPNsense, campos e ciclo de vida da captura:
  https://wiki.opnsense.org/manual/diagnostics_interfaces.html
- Modelo atual dos campos snaplen/count (a documentacao textual ainda menciona
  snaplen 0, mas o modelo consultado exige minimo 1):
  https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Diagnostics/PacketCapture.xml
- Python, bind/directory e HTTP/1.0 por padrao:
  https://docs.python.org/3.12/library/http.server.html
- curl, limite de taxa, timeouts, proxy e demais opcoes:
  https://curl.se/docs/manpage.html
