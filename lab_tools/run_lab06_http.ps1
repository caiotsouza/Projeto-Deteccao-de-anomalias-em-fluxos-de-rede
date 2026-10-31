param(
    [ValidateRange(1,3)][int]$Repetition=1,
    [string]$OutputRoot=(Join-Path $env:USERPROFILE 'Documents\TCC-Lab-Capturas'),
    [switch]$CaptureStarted,
    [switch]$PlanOnly
)
$ErrorActionPreference='Stop'
$sourceIp='172.31.50.161'
$targetIp='172.31.60.10'
$url="http://${targetIp}:8000/benign-v1/large_2m.bin"
$marker='server-128k-v1'
$definition=[ordered]@{
    scenario='lab06_serverpaced'; repetition=$Repetition; source_ip=$sourceIp; target_ip=$targetIp;
    url=$url; requests=6; expected_bytes_per_request=2097152; expected_total_body_bytes=12582912;
    interval_seconds=3; maximum_transfer_rate=$null; concurrency=1; http_version='1.0';
    redirects=$false; retries=0; pacing_location='server'; required_server_marker=$marker;
    expected_server_chunk_bytes=16384; expected_server_pause_seconds=0.125;
    purpose='controlled HTTP with server pacing; no inferred ground-truth labels'
}
if ($PlanOnly) { $definition | ConvertTo-Json -Depth 5; return }
if (-not $CaptureStarted) { throw 'Inicie a captura no OPNsense antes de informar -CaptureStarted.' }
if (-not (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $sourceIp })) {
    throw "Execute dentro do Windows-LAB com IP $sourceIp. Nenhuma requisicao enviada."
}
Get-Command curl.exe -ErrorAction Stop | Out-Null
$session='lab06_serverpaced_r{0}_{1}' -f $Repetition,([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
$folder=Join-Path ([System.IO.Path]::GetFullPath($OutputRoot)) $session
if (Test-Path -LiteralPath $folder) { throw 'Pasta de sessao existente.' }
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$utf8=New-Object System.Text.UTF8Encoding($false)
$rows=New-Object System.Collections.Generic.List[object]
$started=[DateTime]::UtcNow.ToString('o')
$status='failed'
$failure=$null
try {
    for ($index=1; $index -le 6; $index++) {
        $requestStart=[DateTime]::UtcNow.ToString('o')
        $headerFile=Join-Path $folder ('headers_{0:00}.txt' -f $index)
        # Intencionalmente SEM --limit-rate: o pacing deve estar no servidor.
        $curlArgs=@('--ipv4','--http1.0','--noproxy','*','--proto','=http',
                    '--interface',$sourceIp,'--connect-timeout','5','--max-time','90',
                    '--fail','--silent','--show-error','--output','NUL',
                    '--dump-header',$headerFile,'--write-out',
                    '%{http_code}|%{size_download}|%{time_total}|%{remote_ip}|%{local_ip}',$url)
        $errorText=$null
        $curlExit=$null
        $httpStatus=$bytes=$seconds=$remote=$local=$null
        $verified=$false
        try {
            $raw=& curl.exe @curlArgs
            $curlExit=$LASTEXITCODE
            if ($curlExit -ne 0) { throw "curl terminou com codigo $curlExit." }
            $parts=([string]$raw).Trim().Split('|')
            if ($parts.Count -ne 5) { throw 'Diagnostico curl inesperado.' }
            $culture=[System.Globalization.CultureInfo]::InvariantCulture
            $httpStatus=[int]$parts[0]
            $bytes=[double]::Parse($parts[1],$culture)
            $seconds=[double]::Parse($parts[2],$culture)
            $remote,$local=$parts[3],$parts[4]
            if ($httpStatus -ne 200 -or $bytes -ne 2097152 -or $remote -ne $targetIp -or $local -ne $sourceIp) {
                throw 'Status, tamanho ou endpoints nao correspondem ao LAB06.'
            }
            $headers=[System.IO.File]::ReadAllText($headerFile)
            if ($headers -notmatch '(?im)^X-TCC-Pacing:[ \t]*server-128k-v1[ \t]*\r?$') {
                throw 'Marcador LAB06 ausente: confira se o servidor antigo foi substituido.'
            }
            $verified=$true
        } catch { $errorText=$_.Exception.Message }
        $entry=[ordered]@{
            request_number=$index; started_at_utc=$requestStart; completed_at_utc=[DateTime]::UtcNow.ToString('o');
            url=$url; http_status=$httpStatus; body_bytes=$bytes; duration_seconds=$seconds;
            remote_ip=$remote; local_ip=$local; curl_exit_code=$curlExit;
            success=($null -eq $errorText); error=$errorText; server_marker_verified=$verified;
            response_header_file=[System.IO.Path]::GetFileName($headerFile)
        }
        $rows.Add($entry)
        [System.IO.File]::AppendAllText((Join-Path $folder 'requests.jsonl'),(($entry|ConvertTo-Json -Compress)+[Environment]::NewLine),$utf8)
        if ($errorText) { throw $errorText }
        Write-Host "[$index/6] HTTP $httpStatus | $bytes bytes | ${seconds}s | servidor LAB06 confirmado"
        if ($index -lt 6) { Start-Sleep -Seconds 3 }
    }
    $status='completed'
} catch { $failure=$_.Exception.Message }
finally {
    $manifest=[ordered]@{
        schema_version=1; status=$status; definition=$definition; started_at_utc=$started;
        completed_at_utc=[DateTime]::UtcNow.ToString('o'); attempted_requests=$rows.Count;
        successful_requests=@($rows|Where-Object{$_.success}).Count; error=$failure;
        ground_truth_labels_generated=$false; capture_started_acknowledged=[bool]$CaptureStarted
    }
    [System.IO.File]::WriteAllText((Join-Path $folder 'run_manifest.json'),($manifest|ConvertTo-Json -Depth 8),$utf8)
    Write-Host "Logs preservados em: $folder"
    Write-Host 'Espere 5 segundos, pare o job no OPNsense e preserve outro ZIP.'
}
if ($status -ne 'completed') { throw "Sessao interrompida: $failure" }
