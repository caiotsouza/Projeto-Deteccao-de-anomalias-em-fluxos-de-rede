param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('lab03_small', 'lab04_medium', 'lab05_slow')]
    [string]$Scenario,
    [ValidateRange(1, 3)][int]$Repetition = 1,
    [string]$OutputRoot = (Join-Path $env:USERPROFILE 'Documents\TCC-Lab-Capturas'),
    [switch]$CaptureStarted,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
$plans = @{
    lab03_small = @{ file='small_16k.bin'; bytes=16384; requests=30; interval=2; rate='512K' }
    lab04_medium = @{ file='medium_256k.bin'; bytes=262144; requests=12; interval=3; rate='512K' }
    lab05_slow = @{ file='large_2m.bin'; bytes=2097152; requests=6; interval=3; rate='128K' }
}
$plan = $plans[$Scenario]
$sourceIp = '172.31.50.161'
$targetIp = '172.31.60.10'
$url = "http://${targetIp}:8000/benign-v1/$($plan.file)"
$definition = [ordered]@{
    scenario=$Scenario; repetition=$Repetition; source_ip=$sourceIp; target_ip=$targetIp;
    url=$url; requests=$plan.requests; expected_bytes_per_request=$plan.bytes;
    expected_total_body_bytes=($plan.requests * $plan.bytes);
    interval_seconds=$plan.interval; maximum_transfer_rate=$plan.rate;
    concurrency=1; http_version='1.0'; redirects=$false; retries=0;
    purpose='controlled benign HTTP activity; no inferred ground-truth labels'
}
if ($PlanOnly) {
    $definition | ConvertTo-Json -Depth 5
    return
}
if (-not $CaptureStarted) {
    throw 'Inicie a captura no OPNsense e informe -CaptureStarted. Nenhuma requisicao foi enviada.'
}
# Impede executar por engano no computador pessoal. Nao altera interfaces.
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)
if (-not ($addresses | Where-Object { $_.IPAddress -eq $sourceIp })) {
    throw "Execute dentro do Windows-LAB com IP $sourceIp. Nenhuma requisicao foi enviada."
}
Get-Command curl.exe -ErrorAction Stop | Out-Null
$rootPath = [System.IO.Path]::GetFullPath($OutputRoot)
$session = '{0}_r{1}_{2}' -f $Scenario, $Repetition, ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
$sessionPath = Join-Path $rootPath $session
if (Test-Path -LiteralPath $sessionPath) { throw 'Pasta de sessao ja existe.' }
New-Item -ItemType Directory -Path $sessionPath -Force | Out-Null
$logPath = Join-Path $sessionPath 'requests.jsonl'
$manifestPath = Join-Path $sessionPath 'run_manifest.json'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$requestLog = New-Object System.Collections.Generic.List[object]
$started = [DateTime]::UtcNow.ToString('o')
$status = 'failed'
$failure = $null
try {
    for ($index=1; $index -le $plan.requests; $index++) {
        $requestStart = [DateTime]::UtcNow.ToString('o')
        $argsCurl = @(
            '--ipv4', '--http1.0', '--noproxy', '*', '--proto', '=http',
            '--interface', $sourceIp, '--connect-timeout', '5', '--max-time', '90',
            '--fail', '--silent', '--show-error', '--limit-rate', $plan.rate,
            '--output', 'NUL', '--write-out',
            '%{http_code}|%{size_download}|%{time_total}|%{remote_ip}|%{local_ip}', $url
        )
        $raw = $null
        $curlExit = $null
        $requestError = $null
        $httpStatus = $null
        $bytes = $null
        $seconds = $null
        $remote = $null
        $local = $null
        try {
            $raw = & curl.exe @argsCurl
            $curlExit = $LASTEXITCODE
            if ($curlExit -ne 0) { throw "curl terminou com codigo $curlExit." }
            $parts = ([string]$raw).Trim().Split('|')
            if ($parts.Count -ne 5) { throw 'Resposta de diagnostico curl inesperada.' }
            $culture = [System.Globalization.CultureInfo]::InvariantCulture
            $httpStatus = [int]$parts[0]
            $bytes = [double]::Parse($parts[1], $culture)
            $seconds = [double]::Parse($parts[2], $culture)
            $remote, $local = $parts[3], $parts[4]
            if ($httpStatus -ne 200 -or $bytes -ne $plan.bytes) {
                throw "Esperado HTTP 200 e $($plan.bytes) bytes; recebido $httpStatus e $bytes."
            }
            if ($remote -ne $targetIp -or $local -ne $sourceIp) {
                throw 'Endpoints observados nao correspondem ao laboratorio.'
            }
        } catch {
            $requestError = $_.Exception.Message
        }
        $entry = [ordered]@{
            request_number=$index; started_at_utc=$requestStart;
            completed_at_utc=[DateTime]::UtcNow.ToString('o');
            url=$url; http_status=$httpStatus; body_bytes=$bytes; duration_seconds=$seconds;
            remote_ip=$remote; local_ip=$local; curl_exit_code=$curlExit;
            success=($null -eq $requestError); error=$requestError
        }
        $requestLog.Add($entry)
        [System.IO.File]::AppendAllText($logPath, (($entry | ConvertTo-Json -Compress) + [Environment]::NewLine), $utf8)
        if ($requestError) { throw $requestError }
        Write-Host "[$index/$($plan.requests)] HTTP $httpStatus | $bytes bytes | ${seconds}s"
        if ($index -lt $plan.requests) { Start-Sleep -Seconds $plan.interval }
    }
    $status = 'completed'
} catch {
    $failure = $_.Exception.Message
} finally {
    $manifest = [ordered]@{
        schema_version=1; status=$status; definition=$definition;
        started_at_utc=$started; completed_at_utc=[DateTime]::UtcNow.ToString('o');
        attempted_requests=$requestLog.Count;
        successful_requests=@($requestLog | Where-Object { $_.success }).Count;
        error=$failure; ground_truth_labels_generated=$false;
        capture_started_acknowledged=[bool]$CaptureStarted
    }
    [System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 8), $utf8)
    Write-Host "Logs preservados em: $sessionPath"
    Write-Host 'Espere 5 segundos, pare a captura no OPNsense e baixe um ZIP novo.'
}
if ($status -ne 'completed') { throw "Sessao interrompida: $failure" }
