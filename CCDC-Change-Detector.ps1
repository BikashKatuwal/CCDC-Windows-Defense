# CCDC Windows Change Detector v2.0
# Read-only inventory and differential alerts. Windows PowerShell 5.1+.
# IMPORTANT: Establish the reference only after reviewing the host for compromise.
[CmdletBinding()]
param(
    [string]$Root = 'C:\CCDC-ChangeDetection',
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'
$hostname = $env:COMPUTERNAME
$hostFolder = Join-Path $Root $hostname
$referencePath = Join-Path $hostFolder 'reference.json'
$historyPath = Join-Path $hostFolder 'History'
New-Item -Path $historyPath -ItemType Directory -Force | Out-Null
$errors = [System.Collections.Generic.List[string]]::new()

function Capture-Section([string]$Name, [scriptblock]$Collector) {
    try {
        $items = @(& $Collector)
        return @($items | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    } catch {
        $errors.Add("${Name}: $($_.Exception.Message)")
        return $null
    }
}

$now = Get-Date
$captures = [ordered]@{}
$captures['DomainAdmins'] = Capture-Section 'DomainAdmins' {
    if (-not (Get-Module -ListAvailable ActiveDirectory)) { throw 'ActiveDirectory module unavailable' }
    Import-Module ActiveDirectory
    Get-ADGroupMember -Identity 'Domain Admins' -Recursive | ForEach-Object { "$($_.ObjectClass)|$($_.SID.Value)|$($_.SamAccountName)" }
}
$captures['DomainUsers'] = Capture-Section 'DomainUsers' {
    if (-not (Get-Module -ListAvailable ActiveDirectory)) { throw 'ActiveDirectory module unavailable' }
    Import-Module ActiveDirectory
    Get-ADUser -Filter * -Properties Enabled | ForEach-Object { "$($_.SID.Value)|$($_.SamAccountName)|Enabled=$($_.Enabled)" }
}
$captures['LocalAdministrators'] = Capture-Section 'LocalAdministrators' {
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { return }
    Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { "$($_.ObjectClass)|$($_.SID.Value)|$($_.Name)" }
}
$captures['Services'] = Capture-Section 'Services' {
    Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name)|$($_.StartMode)|$($_.PathName)" }
}
$captures['ScheduledTasks'] = Capture-Section 'ScheduledTasks' {
    Get-ScheduledTask | ForEach-Object {
        $action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        "$($_.TaskPath)$($_.TaskName)|$action"
    }
}
$captures['TcpListeners'] = Capture-Section 'TcpListeners' {
    # Exclude PID because process IDs routinely change on reboot.
    Get-NetTCPConnection -State Listen | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }
}
$captures['FirewallProfiles'] = Capture-Section 'FirewallProfiles' {
    Get-NetFirewallProfile | ForEach-Object { "$($_.Name)|Enabled=$($_.Enabled)|Inbound=$($_.DefaultInboundAction)|Outbound=$($_.DefaultOutboundAction)" }
}

$snapshot = [pscustomobject]@{
    Version = '2.0'
    ComputerName = $hostname
    CapturedAt = $now.ToString('o')
    Sections = $captures
    CollectionErrors = @($errors)
}
$stamp = $now.ToString('yyyyMMdd_HHmmss_fff')
$snapshotFile = Join-Path $historyPath "snapshot_$stamp.json"
$snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $snapshotFile -Encoding UTF8

if (-not (Test-Path -LiteralPath $referencePath)) {
    Copy-Item -LiteralPath $snapshotFile -Destination $referencePath
    Write-Host "Reference created: $referencePath" -ForegroundColor Yellow
    Write-Host 'IMPORTANT: Review the reference before trusting it as clean.'
    if ($errors.Count) { Write-Warning "Some sections were not collected: $($errors -join '; ')" }
    Write-Host 'Run this script again later to compare with the reference.'
    exit 0
}

$reference = Get-Content -LiteralPath $referencePath -Raw | ConvertFrom-Json
if ($reference.ComputerName -ne $hostname) { throw 'Reference belongs to another host. Comparison aborted.' }
$results = [System.Collections.Generic.List[object]]::new()
$categories = @('DomainAdmins','DomainUsers','LocalAdministrators','Services','ScheduledTasks','TcpListeners','FirewallProfiles')
foreach ($category in $categories) {
    $before = $reference.Sections.PSObject.Properties[$category]
    $after = $snapshot.Sections[$category]
    # Never report an absent section as an empty inventory: that creates false mass-removal alerts.
    if ($null -eq $before -or $null -eq $before.Value -or $null -eq $after) {
        $results.Add([pscustomobject]@{ Category=$category; Change='SKIPPED'; Detail='Data unavailable in one snapshot' })
        continue
    }
    $oldItems = @($before.Value | ForEach-Object { [string]$_ })
    $newItems = @($after | ForEach-Object { [string]$_ })
    foreach ($item in (Compare-Object -ReferenceObject $oldItems -DifferenceObject $newItems)) {
        $change = if ($item.SideIndicator -eq '=>') { 'ADDED' } else { 'REMOVED' }
        $results.Add([pscustomobject]@{ Category=$category; Change=$change; Detail=[string]$item.InputObject })
    }
}
$reportPath = Join-Path $historyPath "changes_$stamp.txt"
$lines = @(
    'CCDC Windows Change Detector v2.0',
    "Host: $hostname",
    "Compared against: $($reference.CapturedAt)",
    "Current capture: $($snapshot.CapturedAt)",
    'Changes are NOT proof of compromise; investigate before remediation.',
    ''
)
if ($results.Count -eq 0) { $lines += 'No differences in collected categories.' }
else { $lines += ($results | Format-Table -AutoSize -Wrap | Out-String -Width 240) }
if ($errors.Count) { $lines += ''; $lines += 'Collection errors:'; $lines += @($errors) }
$lines | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Host "Comparison complete. Findings: $($results.Count)" -ForegroundColor Cyan
Write-Host "Report: $reportPath" -ForegroundColor Green
Write-Host "Reference: $referencePath"
if ($errors.Count) { Write-Warning 'Some audit sections failed; see report.' }
if ($OpenReport) { Start-Process notepad.exe -ArgumentList ('"' + $reportPath + '"') }
