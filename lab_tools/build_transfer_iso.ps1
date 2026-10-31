param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateSet('prepare_http_payloads.py','lab06_server.py')]
    [string]$ScriptName='prepare_http_payloads.py'
)

$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot $ScriptName
$isoPath = [System.IO.Path]::GetFullPath($OutputPath)
if ([System.IO.Path]::GetExtension($isoPath) -ne '.iso') { throw 'A saida deve terminar em .iso.' }
if (Test-Path -LiteralPath $isoPath) { throw 'ISO existente: escolha outro caminho para nao sobrescrever.' }
if (Test-Path -LiteralPath "$isoPath.json") { throw 'Manifesto existente: escolha outro caminho.' }
$sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
$parent = Split-Path -Parent $isoPath
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }

if (-not ('TccIsoStreamWriter' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class TccIsoStreamWriter {
    public static void Save(object source, string path) {
        IStream input = (IStream)source;
        input.Seek(0, 0, IntPtr.Zero);
        IntPtr count = Marshal.AllocHGlobal(4);
        try {
            using (FileStream output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                byte[] block = new byte[65536];
                while (true) {
                    Marshal.WriteInt32(count, 0);
                    input.Read(block, block.Length, count);
                    int read = Marshal.ReadInt32(count);
                    if (read == 0) break;
                    if (read < 0 || read > block.Length) throw new IOException("Invalid COM stream length.");
                    output.Write(block, 0, read);
                }
            }
        } finally { Marshal.FreeHGlobal(count); }
    }
}
'@
}

$image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$image.FileSystemsToCreate = 3 # ISO9660 + Joliet; preserva o nome longo no Linux.
$image.VolumeName = 'TCC_LAB_FILES'
$inputStream = New-Object -ComObject ADODB.Stream
$inputStream.Type = 1
$inputStream.Open()
try {
    $inputStream.LoadFromFile($sourcePath)
    # Nao usar AddTree: inclui exclusivamente este arquivo, nunca a pasta do projeto.
    $image.Root.AddFile($ScriptName, $inputStream)
    $result = $image.CreateResultImage()
    [TccIsoStreamWriter]::Save($result.ImageStream, $isoPath)
} finally { $inputStream.Close() }

if ((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceHash) {
    throw 'O script de origem mudou durante a criacao.'
}
$manifest = [ordered]@{
    created_at_utc=[DateTime]::UtcNow.ToString('o');
    purpose='offline script transfer to Kali-LAB'; bootable=$false;
    volume_label='TCC_LAB_FILES'; filesystem='ISO9660+Joliet';
    iso_sha256=(Get-FileHash -LiteralPath $isoPath -Algorithm SHA256).Hash.ToLowerInvariant();
    iso_size_bytes=(Get-Item -LiteralPath $isoPath).Length;
    included_files=@([ordered]@{ name=$ScriptName; sha256=$sourceHash;
                              size_bytes=(Get-Item -LiteralPath $sourcePath).Length });
    vm_configuration_changed=$false; models_changed=$false;
    content_verification='pending independent readback'
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$isoPath.json" -Encoding UTF8
Write-Host "ISO criada: $isoPath"
Write-Host "SHA256 do script: $sourceHash"
