# Fetch CVE -> CVSS base score from the NVD API 2.0 in bulk, resumable.
#
# Writes data/real/nvd_cvss.csv with columns: cve,cvss,cvss_version
# (cvss empty + version "none" = NVD has not scored the CVE -> the "NVD gap").
# Prefers CVSS v3.1 > v3.0 > v2.0. Respects the keyless rate limit (5 req/30s)
# and is resumable via data/real/nvd_cvss.ckpt (last completed startIndex).
#
# Usage: powershell -File scripts/fetch_nvd_cvss.ps1   (run from the eval crate)

$ErrorActionPreference = 'Stop'
$dir = Join-Path $PSScriptRoot '..\data\real'
$out = Join-Path $dir 'nvd_cvss.csv'
$ckptFile = Join-Path $dir 'nvd_cvss.ckpt'
$log = Join-Path $dir 'nvd_cvss.log'
$page = 2000
$base = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

function Log($m) { "$([DateTime]::UtcNow.ToString('HH:mm:ss')) $m" | Tee-Object -FilePath $log -Append }

# Resume from checkpoint, or start fresh with a header.
$start = 0
if ((Test-Path $ckptFile) -and (Test-Path $out)) {
    $start = [int](Get-Content $ckptFile)
    Log "resuming from startIndex=$start"
} else {
    'cve,cvss,cvss_version' | Out-File -FilePath $out -Encoding utf8
    Log 'starting fresh'
}

$total = [int]::MaxValue
while ($start -lt $total) {
    $url = "$base`?resultsPerPage=$page&startIndex=$start"
    $resp = $null
    for ($try = 1; $try -le 6; $try++) {
        try { $resp = Invoke-RestMethod -Uri $url -TimeoutSec 90; break }
        catch {
            Log "page $start try $try failed: $($_.Exception.Message)"
            Start-Sleep -Seconds (20 * $try)
        }
    }
    if ($null -eq $resp) { Log "page $start gave up after retries"; exit 1 }
    $total = [int]$resp.totalResults

    $lines = foreach ($item in $resp.vulnerabilities) {
        $m = $item.cve.metrics
        $score = ''; $ver = 'none'
        if ($m.cvssMetricV31) { $score = $m.cvssMetricV31[0].cvssData.baseScore; $ver = '3.1' }
        elseif ($m.cvssMetricV30) { $score = $m.cvssMetricV30[0].cvssData.baseScore; $ver = '3.0' }
        elseif ($m.cvssMetricV2) { $score = $m.cvssMetricV2[0].cvssData.baseScore; $ver = '2.0' }
        "$($item.cve.id),$score,$ver"
    }
    $lines | Out-File -FilePath $out -Encoding utf8 -Append

    $start += $page
    $start | Out-File -FilePath $ckptFile -Encoding utf8
    Log "wrote up to $start / $total"
    Start-Sleep -Seconds 2
}
Log "done: $total CVEs"
