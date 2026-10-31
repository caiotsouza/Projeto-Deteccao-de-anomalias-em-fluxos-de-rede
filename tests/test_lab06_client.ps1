param([Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$runner=Join-Path $PSScriptRoot '..\lab_tools\run_lab06_http.ps1'
$global:MockAddress='172.31.50.161'
$global:MockCalls=0
$global:MockMode='ok'
function global:Get-NetIPAddress { [pscustomobject]@{IPAddress=$global:MockAddress} }
function global:Start-Sleep {}
function global:curl.exe {
    $global:MockCalls++
    if ($args -contains '--limit-rate') { throw 'LAB06 nao deve limitar o cliente.' }
    if ($args[-1] -ne 'http://172.31.60.10:8000/benign-v1/large_2m.bin') { throw 'Destino incorreto.' }
    $global:LASTEXITCODE=0
    if ($global:MockMode -eq 'curl_error') { $global:LASTEXITCODE=7; return '' }
    $headers='HTTP/1.0 200 OK' + "`r`nContent-Length: 2097152`r`n"
    if ($global:MockMode -eq 'ok') { $headers+="X-TCC-Pacing: server-128k-v1`r`n" }
    $dumpIndex=[array]::IndexOf($args,'--dump-header')
    [System.IO.File]::WriteAllText($args[$dumpIndex+1],$headers)
    return '200|2097152|15.88|172.31.60.10|172.31.50.161'
}
& $runner -PlanOnly | Out-Null
$blocked=$false
try { & $runner } catch { $blocked=$true }
if (-not $blocked -or $global:MockCalls) { throw 'Reconhecimento da captura nao exigido.' }
$global:MockAddress='192.168.1.20'
$blocked=$false
try { & $runner -CaptureStarted } catch { $blocked=$true }
if (-not $blocked -or $global:MockCalls) { throw 'Host pessoal nao bloqueado.' }
$global:MockAddress='172.31.50.161'
& $runner -CaptureStarted -OutputRoot $OutputRoot
if ($global:MockCalls -ne 6) { throw 'Deveriam ser seis GETs.' }
foreach ($mode in @('old_server','curl_error')) {
    $global:MockMode=$mode
    $blocked=$false
    try { & $runner -CaptureStarted -Repetition 2 -OutputRoot $OutputRoot } catch { $blocked=$true }
    if (-not $blocked) { throw 'Nao interrompeu ao encontrar erro/servidor antigo.' }
}
if ($global:MockCalls -ne 8) { throw 'Foram enviadas tentativas extras apos falha.' }
$manifests=@(Get-ChildItem -LiteralPath $OutputRoot -Recurse -Filter run_manifest.json | ForEach-Object {
    Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
})
$good=@($manifests|Where-Object{$_.status -eq 'completed'})
$bad=@($manifests|Where-Object{$_.status -eq 'failed'})
if ($good.Count -ne 1 -or $bad.Count -ne 2 -or $good[0].successful_requests -ne 6) { throw 'Totais incorretos.' }
if ($good[0].definition.maximum_transfer_rate -ne $null) { throw 'Limite inesperado no cliente.' }
Write-Host 'LAB06 client: OK (mocked requests only).'
