# Koala DFIR Script for Windows 10/11, works on Windows Server 2022.
# Author: Gracchi - CAS
# This is a Comprehensive system information gathering for DFIR investigations. 

param(
    [string]$OutputPath = "C:\Koala_DFIR_Output"
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Koala requires administrator privileges for complete information gathering."
}

if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "$OutputPath\DFIR_Report_$timestamp.txt"

function Write-Output {
    param([string]$Message)
    $Message | Tee-Object -FilePath $outputFile -Append
}

Write-Output "======================================"
Write-Output "KOALA DFIR SCRIPT - GRACCHI"
Write-Output "Analysis Date: $(Get-Date)"
Write-Output "======================================"

Write-Output "`n[SYSTEM INFORMATION]"
Write-Output "Computer Name: $env:COMPUTERNAME"
Write-Output "Domain: $env:USERDOMAIN"
Write-Output "OS Version: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
Write-Output "Build Number: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber)"
Write-Output "Architecture: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)"

$uptime = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
$lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($uptime)
$currentUptime = (Get-Date) - $lastBoot
Write-Output "Last Boot Time: $lastBoot"
Write-Output "System Uptime: $($currentUptime.Days) days, $($currentUptime.Hours) hours, $($currentUptime.Minutes) minutes"

Write-Output "`n[CURRENT USER INFORMATION]"
Write-Output "Current User: $env:USERNAME"
Write-Output "User Domain: $env:USERDOMAIN"
Write-Output "User Profile: $env:USERPROFILE"

$sessions = quser 2>$null
if ($sessions) {
    Write-Output "`nActive User Sessions:"
    $sessions | ForEach-Object { Write-Output $_ }
}

Write-Output "`n[USER ACCOUNTS]"
$users = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True"
foreach ($user in $users) {
    Write-Output "Username: $($user.Name)"
    Write-Output "  Description: $($user.Description)"
    Write-Output "  Disabled: $($user.Disabled)"
    Write-Output "  Password Changeable: $($user.PasswordChangeable)"
    Write-Output "  Password Expires: $($user.PasswordExpires)"
    Write-Output "  SID: $($user.SID)"
    
   
    try {
        $userSID = $user.SID
        $profilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSID"
        if (Test-Path $profilePath) {
            $profileData = Get-ItemProperty $profilePath -ErrorAction SilentlyContinue
            if ($profileData.ProfileImagePath) {
                Write-Output "  Profile Path: $($profileData.ProfileImagePath)"
            }
        }
    } catch {
        Write-Output "  Profile creation date: Unable to determine"
    }
    Write-Output ""
}

Write-Output "`n[NETWORK INFORMATION]"
Write-Output "Network Adapters:"
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | ForEach-Object {
    Write-Output "  Adapter: $($_.Description)"
    Write-Output "  IP Address: $($_.IPAddress -join ', ')"
    Write-Output "  MAC Address: $($_.MACAddress)"
    Write-Output "  DHCP Enabled: $($_.DHCPEnabled)"
    if ($_.DefaultIPGateway) {
        Write-Output "  Default Gateway: $($_.DefaultIPGateway -join ', ')"
    }
    Write-Output ""
}

Write-Output "Internet Connectivity Test:"
try {
    $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
    Write-Output "  Internet Connection: $(if($ping){'CONNECTED'}else{'DISCONNECTED'})"
} catch {
    Write-Output "  Internet Connection: UNABLE TO TEST"
}

Write-Output "`nDNS Configuration:"
$dnsServers = Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 2}
foreach ($dns in $dnsServers) {
    Write-Output "  Interface: $($dns.InterfaceAlias)"
    Write-Output "  DNS Servers: $($dns.ServerAddresses -join ', ')"
}

Write-Output "`n[RUNNING PROCESSES]"
Write-Output "Top 20 processes by CPU usage:"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | ForEach-Object {
    Write-Output "  $($_.ProcessName) (PID: $($_.Id)) - CPU: $($_.CPU)"
}

Write-Output "`n[SUSPICIOUS SERVICES]"
Write-Output "Non-Microsoft services:"
Get-Service | Where-Object {$_.DisplayName -notlike "*Microsoft*" -and $_.Status -eq "Running"} | Select-Object -First 15 | ForEach-Object {
    Write-Output "  $($_.Name) - $($_.DisplayName) - Status: $($_.Status)"
}

Write-Output "`n[STARTUP PROGRAMS]"
Write-Output "Registry Startup Items:"
$startupPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Write-Output "  Registry Path: $path"
        Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | Where-Object {$_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider"} | ForEach-Object {
                Write-Output "    $($_.Name): $($_.Value)"
            }
        }
        Write-Output ""
    }
}

Write-Output "`n[RECENT FILE ACTIVITY]"
Write-Output "Recently Modified Files (Last 24 hours):"
$yesterday = (Get-Date).AddDays(-1)
try {
    Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object {$_.LastWriteTime -gt $yesterday} | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 20 | 
    ForEach-Object {
        Write-Output "  $($_.FullName) - Modified: $($_.LastWriteTime)"
    }
} catch {
    Write-Output "  Unable to scan recent files - Access Denied"
}

Write-Output "`n[SECURITY EVENT ANALYSIS]"
Write-Output "Recent Security Events (Last 24 hours):"
try {
    $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$yesterday} -MaxEvents 50 -ErrorAction SilentlyContinue
    $securityEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Output "  Event ID $($_.Name): $($_.Count) occurrences"
    }
} catch {
    Write-Output "  Unable to read Security Event Log"
}

Write-Output "`n[NETWORK CONNECTIONS]"
Write-Output "Active Network Connections:"
try {
    Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object -First 15 | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        Write-Output "  $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($process.ProcessName)]"
    }
} catch {
    Write-Output "  Unable to enumerate network connections"
}

Write-Output "`n[USB DEVICE HISTORY]"
Write-Output "USB Storage Devices:"
try {
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.FriendlyName) {
            Write-Output "  Device: $($_.FriendlyName)"
            Write-Output "  Hardware ID: $($_.HardwareID -join ', ')"
            Write-Output ""
        }
    }
} catch {
    Write-Output "  Unable to enumerate USB devices"
}

Write-Output "`n[INSTALLED SOFTWARE]"
Write-Output "Recently Installed Programs (Last 30 days):"
$30daysAgo = (Get-Date).AddDays(-30)
try {
    Get-WmiObject Win32_Product | Where-Object {$_.InstallDate -and [DateTime]::ParseExact($_.InstallDate, "yyyyMMdd", $null) -gt $30daysAgo} | ForEach-Object {
        Write-Output "  $($_.Name) - Installed: $($_.InstallDate) - Vendor: $($_.Vendor)"
    }
} catch {
    Write-Output "  Unable to enumerate recently installed software"
}

Write-Output "`n[BROWSER ARTIFACTS]"
$chromeHistoryPath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
$edgeHistoryPath = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History"

if (Test-Path $chromeHistoryPath) {
    Write-Output "  Chrome history file found: $chromeHistoryPath"
    Write-Output "  Last Modified: $((Get-Item $chromeHistoryPath).LastWriteTime)"
}

if (Test-Path $edgeHistoryPath) {
    Write-Output "  Edge history file found: $edgeHistoryPath"
    Write-Output "  Last Modified: $((Get-Item $edgeHistoryPath).LastWriteTime)"
}

Write-Output "`n[SYSTEM INTEGRITY]"
Write-Output "Checking for potential indicators of compromise..."

$suspiciousLocations = @(
    "$env:TEMP",
    "$env:USERPROFILE\Downloads",
    "C:\Windows\Temp"
)

foreach ($location in $suspiciousLocations) {
    if (Test-Path $location) {
        $recentFiles = Get-ChildItem $location -File -ErrorAction SilentlyContinue | 
                      Where-Object {$_.LastWriteTime -gt $yesterday} | 
                      Sort-Object LastWriteTime -Descending | 
                      Select-Object -First 5
        
        if ($recentFiles) {
            Write-Output "  Recent files in $($location):"
            $recentFiles | ForEach-Object {
                Write-Output "    $($_.Name) - Modified: $($_.LastWriteTime) - Size: $($_.Length) bytes"
            }
        }
    }
}

Write-Output "`n======================================"
Write-Output "KOALA ANALYSIS COMPLETE"
Write-Output "Report saved to: $outputFile"
Write-Output "======================================"

Write-Output "`n[ADDITIONAL FORENSIC ARTIFACTS]"
Write-Output "Prefetch files location: C:\Windows\Prefetch"
Write-Output "Recent items: $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent"
Write-Output "Jump lists: $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"

Write-Output "`n[MEMORY USAGE]"
$memory = Get-WmiObject Win32_OperatingSystem
$totalMemGB = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
$freeMemGB = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
$usedMemGB = $totalMemGB - $freeMemGB

Write-Output "Total Physical Memory: $totalMemGB GB"
Write-Output "Free Physical Memory: $freeMemGB GB"
Write-Output "Used Physical Memory: $usedMemGB GB"
Write-Output "Memory Usage Percentage: $([math]::Round(($usedMemGB / $totalMemGB) * 100, 2))%"

Write-Host "`nDFIR data collection completed successfully!" -ForegroundColor Green
Write-Host "Output file: $outputFile" -ForegroundColor Yellow