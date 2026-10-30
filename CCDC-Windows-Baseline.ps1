# CCDC Windows Baseline v1.0
# Read-only collection. Designed for Windows Server / Windows 11, including domain controllers.
# Run from elevated Windows PowerShell 5.1 or newer.
[CmdletBinding()]
param(
    [string]$OutputRoot = 'C:\CCDC-Baselines',
    [int]$SecurityHours = 12
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$computer = $env:COMPUTERNAME -replace '[^a-zA-Z0-9_-]', '_'
$folder = Join-Path $OutputRoot "${computer}_${stamp}"
New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop | Out-Null
$issues = New-Object System.Collections.Generic.List[string]

function Save-Report {
    param([string]$Name, [scriptblock]$Command)
    $path = Join-Path $folder ($Name + '.txt')
    try {
        & $Command 2>&1 | Out-String -Width 300 | Out-File -FilePath $path -Encoding UTF8
        Write-Host "[OK] $Name"
    } catch {
        $message = "$Name : $($_.Exception.Message)"
        $issues.Add($message)
        $message | Out-File -FilePath $path -Encoding UTF8
        Write-Warning $message
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Not elevated: some security data and event logs may be unavailable.'
}

Save-Report '00-Host-and-IP' {
    Get-ComputerInfo | Select-Object CsName, CsDomain, CsDomainRole, WindowsProductName, WindowsVersion, OsBuildNumber
    Get-NetIPConfiguration | Format-List *
    Get-DnsClientServerAddress | Format-Table -AutoSize
    w32tm /query /status
}
Save-Report '01-Local-Accounts-and-Groups' {
    # Domain controllers do not have the usual local SAM user database.
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
        'Domain controller: local SAM accounts do not apply.'
    } else {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Format-Table -AutoSize
        Get-LocalGroupMember -Group 'Administrators' | Format-Table -AutoSize
    }
}
Save-Report '02-Domain-Users-and-Admins' {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator
        Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet |
            Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet |
            Sort-Object SamAccountName | Format-Table -AutoSize
        Get-ADGroupMember -Identity 'Domain Admins' -Recursive |
            Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize
        Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive -ErrorAction SilentlyContinue |
            Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize
    } else {
        'ActiveDirectory PowerShell module not installed; domain report skipped.'
    }
}
Save-Report '03-Network-Listeners-and-Connections' {
    Get-NetTCPConnection | Sort-Object LocalPort, State |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        Format-Table -AutoSize
    Get-NetUDPEndpoint | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}
Save-Report '04-Services' {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
        Sort-Object Name | Format-Table -Wrap
}
Save-Report '05-Scheduled-Tasks' {
    Get-ScheduledTask | Select-Object TaskPath, TaskName, State, @{N='Actions';E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}} |
        Sort-Object TaskPath, TaskName | Format-Table -Wrap
}
Save-Report '06-Firewall-Profiles' {
    Get-NetFirewallProfile | Format-List Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName
}
Save-Report '07-Firewall-Rules' {
    Get-NetFirewallRule -Enabled True |
        Select-Object DisplayName, Direction, Action, Profile, Enabled |
        Sort-Object Direction, DisplayName | Format-Table -Wrap
}
Save-Report '08-DNS' {
    Get-DnsClientServerAddress | Format-Table -AutoSize
    if (Get-Service -Name DNS -ErrorAction SilentlyContinue) {
        Get-Service DNS | Format-List *
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone | Format-Table -AutoSize
        }
    } else {
        'DNS Server service not installed.'
    }
}
Save-Report '09-Shares' {
    Get-SmbShare | Select-Object Name, Path, Description, Special | Format-Table -Wrap
}
Save-Report '10-Processes' {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
        Sort-Object Name | Format-Table -Wrap
}
Save-Report '11-Startup-Entries' {
    Get-CimInstance Win32_StartupCommand |
        Select-Object Name, Command, Location, User | Format-Table -Wrap
}
Save-Report '12-Certificate-Summary' {
    Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint | Format-Table -Wrap
}
Save-Report '13-Recent-Security-Events' {
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4624,4625,4672,4720,4726,4728,4732,1102
        StartTime = (Get-Date).AddHours(-$SecurityHours)
    } -MaxEvents 300 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message | Format-List
}
Save-Report '14-Recent-System-Service-Events' {
    Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id = 7045,7036,7040
        StartTime = (Get-Date).AddHours(-$SecurityHours)
    } -MaxEvents 200 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message | Format-List
}

$metadata = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    CollectedAtLocal = (Get-Date).ToString('o')
    SecurityHours = $SecurityHours
    OutputFolder = $folder
    IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    ScriptVersion = '1.0'
    ReadOnlyCollection = $true
}
$metadata | ConvertTo-Json | Set-Content -Path (Join-Path $folder 'manifest.json') -Encoding UTF8
$issues | Out-File (Join-Path $folder 'collection-errors.txt') -Encoding UTF8
Write-Host ''
Write-Host "Baseline completed: $folder" -ForegroundColor Green
Write-Host 'Review collection-errors.txt; share reports only after removing sensitive account, IP and command-line details.'
