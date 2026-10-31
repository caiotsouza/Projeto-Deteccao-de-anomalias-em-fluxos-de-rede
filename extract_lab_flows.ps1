param(
    [Parameter(Mandatory = $true)][string]$PcapPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [ValidateSet('v4', 'legacy_pre2019')][string]$ExtractorProfile = 'v4'
)

$ErrorActionPreference = 'Stop'
$profiles = @{
    v4 = @{
        image = 'tcc-cicflowmeter:98a5ebad'
        commit = '98a5ebad0df579cc8b43eedd3421b3ae87699901'
    }
    legacy_pre2019 = @{
        image = 'tcc-cicflowmeter:99dc8276'
        commit = '99dc82768a0ebbf2be63a506b185113f52ab1edf'
    }
}
$image = $profiles[$ExtractorProfile].image
$commit = $profiles[$ExtractorProfile].commit
$pcapFile = Get-Item -LiteralPath $PcapPath
if ($pcapFile.PSIsContainer -or $pcapFile.Extension -ne '.pcap') {
    throw 'PcapPath deve apontar para um arquivo .pcap.'
}
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
if ($pcapFile.Directory.FullName.Contains(',') -or $outputPath.Contains(',')) {
    throw 'Os caminhos de montagem Docker nao podem conter virgulas.'
}
if (Test-Path -LiteralPath $outputPath) {
    if (-not (Get-Item -LiteralPath $outputPath).PSIsContainer) {
        throw 'OutputDirectory nao e um diretorio.'
    }
    if (Get-ChildItem -LiteralPath $outputPath -Force | Select-Object -First 1) {
        throw 'A pasta de saida deve estar vazia para preservar resultados anteriores.'
    }
}
$imageId = & docker image inspect $image --format '{{.Id}}'
if ($LASTEXITCODE -ne 0) { throw 'Compile a imagem em infra/flow_extractor primeiro.' }
$revision = & docker image inspect $image --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
if ($LASTEXITCODE -ne 0 -or $revision.Trim() -ne $commit) {
    throw 'A imagem nao identifica o commit oficial esperado.'
}
if (-not (Test-Path -LiteralPath $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath | Out-Null
}
$beforeHash = (Get-FileHash -LiteralPath $pcapFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$started = [DateTime]::UtcNow.ToString('o')
$dockerArgs = @(
    'run', '--rm', '--network', 'none', '--read-only',
    '--cpus', '1', '--memory', '1g', '--pids-limit', '128',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,mode=1777',
    '--tmpfs', '/work:rw,nosuid,nodev,size=32m,mode=1777',
    '--mount', "type=bind,src=$($pcapFile.Directory.FullName),dst=/input,readonly",
    '--mount', "type=bind,src=$outputPath,dst=/output",
    $image, "/input/$($pcapFile.Name)", '/output'
)
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) { throw 'O extrator falhou; preserve a saida para diagnostico.' }
$afterHash = (Get-FileHash -LiteralPath $pcapFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($beforeHash -ne $afterHash) { throw 'O PCAP mudou durante a extracao.' }
$csvFiles = @(Get-ChildItem -LiteralPath $outputPath -Filter '*.csv' -File)
if ($csvFiles.Count -eq 0) { throw 'O extrator terminou sem produzir CSV.' }
$report = [ordered]@{
    status = 'extraction_completed'
    compatibility_status = 'not_yet_validated'
    extractor_profile = $ExtractorProfile
    source_repository = 'https://github.com/ahlashkari/CICFlowMeter'
    source_commit = $commit
    image = $image
    image_id = $imageId.Trim()
    started_at_utc = $started
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    pcap = $pcapFile.Name
    pcap_sha256_before = $beforeHash
    pcap_sha256_after = $afterHash
    network = 'none'
    timezone = 'UTC'
    model_loaded = $false
    model_retrained = $false
    csv_files = @($csvFiles | ForEach-Object {
        [ordered]@{
            name = $_.Name
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputPath 'extraction_run.json') -Encoding UTF8
Write-Host "Extracao concluida: $outputPath"
Write-Host 'O CSV ainda precisa de validacao semantica antes da inferencia.'
