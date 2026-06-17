# Generate catalog CveRecord blocks from verified candidate records, enriching
# CVSS/EPSS/KEV from the authoritative downloaded datasets.
#
# Inputs (data/real/):
#   new_records.json - the catalog-expand workflow's "valid" records
#   epss.csv         - FIRST.org EPSS    (cve -> epss score)
#   kev.json         - CISA KEV          (cve -> exploited flag)
#   nvd_cvss.csv     - NVD CVSS          (cve -> base score; optional, preferred over the candidate's)
# Dedups against the live catalog.rs (cve_id regex) and within the input.
# Output: data/real/new_records.rs - paste-ready CveRecord blocks.
#
# Usage: powershell -File scripts/gen_catalog_records.ps1   (run from the eval crate)

$ErrorActionPreference = 'Stop'
$inv = [Globalization.CultureInfo]::InvariantCulture
$dir = Join-Path $PSScriptRoot '..\data\real'
$catalog = Join-Path $PSScriptRoot '..\..\argus-vuln\src\catalog.rs'
$recordsJson = Join-Path $dir 'new_records.json'
$out = Join-Path $dir 'new_records.rs'

# Existing cve_ids (dedup target).
$existing = [System.Collections.Generic.HashSet[string]]::new()
foreach ($m in [regex]::Matches((Get-Content $catalog -Raw), 'cve_id:\s*"([^"]+)"')) { [void]$existing.Add($m.Groups[1].Value) }

# EPSS score map.
$epssMap = @{}
foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $dir 'epss.csv'))) {
    if ($line.StartsWith('#') -or $line.StartsWith('cve,')) { continue }
    $p = $line.Split(','); if ($p.Length -ge 2) { $epssMap[$p[0]] = $p[1] }
}
# KEV set.
$kev = [System.Collections.Generic.HashSet[string]]::new()
foreach ($v in (Get-Content (Join-Path $dir 'kev.json') -Raw | ConvertFrom-Json).vulnerabilities) { [void]$kev.Add($v.cveID) }
# NVD CVSS map (authoritative, preferred; may be partial if the fetch is mid-run).
$cvssMap = @{}
$nvd = Join-Path $dir 'nvd_cvss.csv'
if (Test-Path $nvd) {
    foreach ($line in [System.IO.File]::ReadAllLines($nvd)) {
        $p = $line.Split(','); if ($p.Length -ge 2 -and $p[0] -ne 'cve' -and $p[1] -ne '') { $cvssMap[$p[0]] = $p[1] }
    }
}

function Sev($c) { if ($c -ge 9.0) { 'Critical' } elseif ($c -ge 7.0) { 'High' } elseif ($c -ge 4.0) { 'Medium' } elseif ($c -gt 0.0) { 'Low' } else { 'None' } }
function Esc($s) { (($s -replace '\\', '\\') -replace '"', '\"') -replace '\r?\n', ' ' }
function Rng($r) {
    switch ($r.range_kind) {
        'Any' { 'VersionRange::Any' }
        'LessThan' { "VersionRange::LessThan(`"$($r.range_high)`")" }
        'AtMost' { "VersionRange::AtMost(`"$($r.range_high)`")" }
        'Range' { "VersionRange::Range(`"$($r.range_low)`", `"$($r.range_high)`")" }
        'Exact' { "VersionRange::Exact(`"$($r.range_high)`")" }
        default { $null }
    }
}

$records = Get-Content $recordsJson -Raw | ConvertFrom-Json
$seen = [System.Collections.Generic.HashSet[string]]::new()
$sb = [System.Text.StringBuilder]::new()
$added = 0; $skipped = 0
foreach ($r in $records) {
    if ($existing.Contains($r.cve_id) -or -not $seen.Add($r.cve_id)) { $skipped++; continue }
    $rng = Rng $r
    if ($null -eq $rng) { Write-Warning "skip $($r.cve_id): unknown range_kind"; $skipped++; continue }
    if ($r.range_kind -ne 'Any' -and [string]::IsNullOrWhiteSpace($r.range_high)) { Write-Warning "skip $($r.cve_id): missing range_high"; $skipped++; continue }
    if ($r.range_kind -eq 'Range' -and [string]::IsNullOrWhiteSpace($r.range_low)) { Write-Warning "skip $($r.cve_id): missing range_low"; $skipped++; continue }

    $cvss = if ($cvssMap.ContainsKey($r.cve_id)) { [double]$cvssMap[$r.cve_id] } else { [double]$r.cvss }
    $epss = if ($epssMap.ContainsKey($r.cve_id)) { [double]$epssMap[$r.cve_id] } else { 0.0 }
    $k = if ($kev.Contains($r.cve_id)) { 'true' } else { 'false' }

    [void]$sb.AppendLine('    CveRecord {')
    [void]$sb.AppendLine("        cve_id: `"$($r.cve_id)`",")
    [void]$sb.AppendLine("        product: `"$(Esc $r.product)`",")
    [void]$sb.AppendLine("        affected: $rng,")
    [void]$sb.AppendLine("        cvss: $($cvss.ToString('0.0', $inv)),")
    [void]$sb.AppendLine("        epss: $($epss.ToString('0.0###', $inv)),")
    [void]$sb.AppendLine("        kev: $k,")
    [void]$sb.AppendLine("        severity: Severity::$(Sev $cvss),")
    [void]$sb.AppendLine("        summary: `"$(Esc $r.summary)`",")
    [void]$sb.AppendLine('    },')
    $added++
}
[System.IO.File]::WriteAllText($out, $sb.ToString())
Write-Output "added $added records, skipped $skipped (dup/existing/invalid) -> $out"
