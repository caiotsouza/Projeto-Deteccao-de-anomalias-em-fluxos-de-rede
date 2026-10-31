param([Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot '..\lab_tools\run_benign_http.ps1'
$global:MockAddress = '172.31.50.161'
$global:MockRequests = 0
$global:FailAt = 0

# Somente mocks: nenhum pacote de rede e enviado e nao ha esperas reais.
function global:Get-NetIPAddress { [pscustomobject]@{ IPAddress=$global:MockAddress } }
function global:Start-Sleep { }
function global:curl.exe {
    $global:MockRequests++
    if (-not ($args -contains '--interface') -or -not ($args -contains '--noproxy')) {
        throw 'Flags de isolamento ausentes.'
    }
    $url = $args[-1]
    if ($url -notlike 'http://172.31.60.10:8000/benign-v1/*') { throw 'Destino inesperado.' }
    $bytes = 16384
    if ($url -like '*medium*') { $bytes=262144 }
    if ($url -like '*large*') { $bytes=2097152 }
    $global:LASTEXITCODE = 0
    if ($global:FailAt -and $global:MockRequests -eq $global:FailAt) {
        $global:LASTEXITCODE = 7
        return ''
    }
    return "200|$bytes|0.05|172.31.60.10|172.31.50.161"
}

& $runner -Scenario lab03_small -PlanOnly | Out-Null
if ($global:MockRequests -ne 0) { throw 'PlanOnly enviou requisicoes.' }
$blocked = $false
try { & $runner -Scenario lab03_small } catch { $blocked=$true }
if (-not $blocked) { throw 'Faltou bloquear ausencia de CaptureStarted.' }
$global:MockAddress = '192.168.1.20'
$blocked = $false
try { & $runner -Scenario lab03_small -CaptureStarted } catch { $blocked=$true }
if (-not $blocked -or $global:MockRequests) { throw 'Faltou bloquear o host pessoal.' }
$global:MockAddress = '172.31.50.161'
foreach ($scenario in @('lab03_small', 'lab04_medium', 'lab05_slow')) {
    & $runner -Scenario $scenario -CaptureStarted -OutputRoot $OutputRoot
}
if ($global:MockRequests -ne 48) { throw 'Quantidade incorreta de requisicoes.' }
$global:FailAt = 51
$blocked = $false
try { & $runner -Scenario lab03_small -Repetition 2 -CaptureStarted -OutputRoot $OutputRoot } catch { $blocked=$true }
if (-not $blocked -or $global:MockRequests -ne 51) { throw 'Nao interrompeu apos a falha.' }
$manifests = @(Get-ChildItem -LiteralPath $OutputRoot -Recurse -Filter run_manifest.json | ForEach-Object {
    Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
})
if (@($manifests | Where-Object { $_.status -eq 'completed' }).Count -ne 3) { throw 'Manifestos incompletos.' }
$failed = @($manifests | Where-Object { $_.status -eq 'failed' })
if ($failed.Count -ne 1 -or $failed[0].attempted_requests -ne 3 -or $failed[0].successful_requests -ne 2) {
    throw 'Registro da sessao interrompida incorreto.'
}
Write-Host 'HTTP script self-test: OK (mocked requests only).'
