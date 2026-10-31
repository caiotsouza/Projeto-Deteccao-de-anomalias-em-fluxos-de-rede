# Transferencia offline do script para o Kali

ISO criada: `data/lab/transfer_iso/tcc_lab_scripts.iso` (53.248 bytes, 52 KiB).
Contem exclusivamente `prepare_http_payloads.py`, sem arquivos pessoais,
credenciais, configuracoes de rede ou modelos. Nao e uma imagem de instalacao
nem de boot. Criacao via IMAPI nativo do Windows, sem instalar dependencias.

SHA-256 da ISO:
`57a044dd34b4bd429c3f295a3d7810e53ae0649448713dfdcd35885bd034b7b9`

SHA-256 do unico arquivo:
`20116eef7ca4b4d56016a024b7309d16c2d17d1b9291b2dd2f66d86bdf900813`

A leitura independente do diretorio Joliet confirmou exatamente um arquivo,
identico byte a byte a origem e com sintaxe Python valida. Evidencia:
`data/lab/transfer_iso/tcc_lab_scripts.verification.json`.

Nenhuma ISO foi anexada automaticamente a VM; nenhuma configuracao das VMs,
firewall, rede ou modelos foi modificada. A imagem e um arquivo de dados: ao
anexa-la como DVD, o guest a le como midia optica; a origem ISO no host continua
sendo um arquivo comum que o usuario pode remover depois de desanexar.

## Anexar no Hyper-V (Windows pessoal)

1. Abra as configuracoes da VM Kali-LAB.
2. Em Controlador SCSI > Unidade de DVD, selecione Arquivo de imagem.
3. Escolha o caminho absoluto:
   `.\data\lab\transfer_iso\tcc_lab_scripts.iso`.
4. Aplique. Nao altere os adaptadores nem a ordem de boot.
5. Se nao houver DVD, desligue normalmente o Kali, adicione a unidade no
   controlador SCSI, anexe a ISO e inicie novamente. Nao force o desligamento.

O Hyper-V permite usar uma ISO como midia da unidade virtual:
https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vmdvddrive

## Ler no Kali (comandos curtos, digitados manualmente)

Identifique a unidade:

```bash
lsblk -o NAME,TYPE,LABEL,MOUNTPOINTS
```

A unidade optica normalmente aparece como `sr0`, tipo `rom`, com rotulo
`TCC_LAB_FILES`. Se o nome for diferente ou a unidade nao aparecer, confira a
ISO no Hyper-V antes de prosseguir. Se ja estiver montada pelo gerenciador de
arquivos, pode usar o ponto de montagem mostrado, sem monta-la novamente.

Para uma unidade `sr0` ainda nao montada:

```bash
sudo mkdir -p /mnt/tcc
sudo mount -o ro /dev/sr0 /mnt/tcc
ls /mnt/tcc
```

Deve aparecer apenas `prepare_http_payloads.py`. E possivel executa-lo
diretamente da ISO, sem copiar ou sobrescrever um arquivo em /tmp:

```bash
sudo python3 /mnt/tcc/prepare_http_payloads.py --directory /lab-http/benign-v1
```

O sudo permite criar a pasta dentro de `/lab-http`, que pode pertencer a root.
O script cria somente os tres payloads sinteticos e o manifesto nessa pasta.
Exige uma pasta nova; se ela ja existir, nao a apague apenas para contornar o
erro. Confira o estado primeiro. Ele nao inicia servidores nem gera trafego.

Depois de confirmar a criacao:

```bash
sudo umount /mnt/tcc
```

Retire a ISO da unidade de DVD nas configuracoes do Hyper-V. Volte ao passo
de servidor/preflight do `reports/lab/LAB_CAPTURE_PLAN.md`.
