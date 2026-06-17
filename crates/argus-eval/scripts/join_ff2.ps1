# Join the three real sources into the FF2 harness format.
#
# Inputs (in data/real/, fetched separately):
#   epss.csv      - FIRST.org EPSS    (cve,epss,percentile; leading #model line)
#   kev.json      - CISA KEV catalog  (.vulnerabilities[].cveID)
#   nvd_cvss.csv  - NVD CVSS          (cve,cvss,cvss_version; from fetch_nvd_cvss.ps1)
# Output:
#   ff2-real.csv  - cve_id,cvss,epss,kev   (empty cvss = NVD gap)
#
# The universe is every CVE with an EPSS score; CVSS is joined where NVD has it
# (empty otherwise), KEV is the exploited-ground-truth flag.
#
# Usage: powershell -File scripts/join_ff2.ps1   (run from the eval crate)

$ErrorActionPreference = 'Stop'
$dir = Join-Path $PSScriptRoot '..\data\real'
$epss = Join-Path $dir 'epss.csv'
$kevJson = Join-Path $dir 'kev.json'
$nvd = Join-Path $dir 'nvd_cvss.csv'
$out = Join-Path $dir 'ff2-real.csv'

# KEV ground truth -> set.
$kev = [System.Collections.Generic.HashSet[string]]::new()
foreach ($v in (Get-Content $kevJson -Raw | ConvertFrom-Json).vulnerabilities) { [void]$kev.Add($v.cveID) }

# NVD CVSS -> map (value may be empty string for an unscored CVE).
$cvss = @{}
foreach ($line in [System.IO.File]::ReadAllLines($nvd)) {
    $p = $line.Split(',')
    if ($p.Length -ge 2 -and $p[0] -ne 'cve') { $cvss[$p[0]] = $p[1] }
}

# Stream EPSS -> joined output.
$sw = [System.IO.StreamWriter]::new($out)
$sw.WriteLine('cve_id,cvss,epss,kev')
$n = 0; $withCvss = 0; $kevCount = 0
foreach ($line in [System.IO.File]::ReadAllLines($epss)) {
    if ($line.StartsWith('#') -or $line.StartsWith('cve,')) { continue }
    $p = $line.Split(',')
    if ($p.Length -lt 2) { continue }
    $id = $p[0]; $e = $p[1]
    $c = ''
    if ($cvss.ContainsKey($id)) { $c = $cvss[$id] }
    $k = 'false'
    if ($kev.Contains($id)) { $k = 'true'; $kevCount++ }
    $sw.WriteLine("$id,$c,$e,$k")
    $n++; if ($c -ne '') { $withCvss++ }
}
$sw.Close()
Write-Output "wrote $n rows -> $out ($withCvss with CVSS, $($n - $withCvss) NVD-gap, $kevCount KEV)"
