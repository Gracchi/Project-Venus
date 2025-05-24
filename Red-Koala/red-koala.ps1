#!/usr/bin/env powershell

<#
    Red Koala is a network investigator and domain name resolution script, its netstat on steroids .
    It will provides a quick basic forensic friendly view of the device network activity with resolution and process details.
.AUTHOR
    Gracchi - CAS
#>

param(
    [ValidateSet("TCP", "UDP", "All")]
    [string]$Protocol = "All",
    
    [ValidateSet("Listen", "Established", "TimeWait", "CloseWait", "All")]
    [string]$State = "All",
    
    [switch]$ShowListening,
    [switch]$ShowEstablished,
    [switch]$NoResolve,
    [string]$ExportCsv,
    [switch]$SaveToText
)

$Colors = @{
    Header = "Cyan"
    TCP = "Green"
    UDP = "Yellow"
    Listening = "Blue"
    Established = "Magenta"
    Process = "White"
    Warning = "Red"
}

$DnsCache = @{}

function Resolve-IPAddress {
    param([string]$IPAddress)
    
    if ($NoResolve) { return $IPAddress }
    if ([string]::IsNullOrEmpty($IPAddress) -or $IPAddress -eq "0.0.0.0" -or $IPAddress -eq "::") {
        return $IPAddress
    }
    
   
    if ($DnsCache.ContainsKey($IPAddress)) {
        return $DnsCache[$IPAddress]
    }
    
    try {
        $resolved = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        $DnsCache[$IPAddress] = $resolved
        return $resolved
    }
    catch {
        $DnsCache[$IPAddress] = $IPAddress
        return $IPAddress
    }
}

function Get-ProcessInfo {
    param([int]$ProcessId)
    
    if ($ProcessId -eq 0) {
        return @{
            Name = "System"
            Path = "System Process"
            Description = "Windows System Process"
        }
    }
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        return @{
            Name = $process.ProcessName
            Path = $process.Path
            Description = $process.Description
        }
    }
    catch {
        return @{
            Name = "Unknown"
            Path = "N/A"
            Description = "Process not accessible"
        }
    }
}

function Format-Address {
    param([string]$Address, [int]$Port)
    
    if ([string]::IsNullOrEmpty($Address) -or $Address -eq "0.0.0.0") {
        return "*:$Port"
    }
    
    $resolved = Resolve-IPAddress $Address
    if ($resolved -ne $Address) {
        return "$resolved (${Address}):$Port"
    }
    return "${Address}:$Port"
}

function Get-EnhancedNetConnections {
    Write-Host "Gathering network connection information..." -ForegroundColor $Colors.Header
    
    $connections = @()
    
    if ($Protocol -eq "TCP" -or $Protocol -eq "All") {
        Write-Host "`nRetrieving TCP connections..." -ForegroundColor $Colors.TCP
        
        $tcpConnections = Get-NetTCPConnection | ForEach-Object {
            $processInfo = Get-ProcessInfo $_.OwningProcess
            
            [PSCustomObject]@{
                Protocol = "TCP"
                LocalAddress = Format-Address $_.LocalAddress $_.LocalPort
                RemoteAddress = Format-Address $_.RemoteAddress $_.RemotePort
                State = $_.State
                ProcessId = $_.OwningProcess
                ProcessName = $processInfo.Name
                ProcessPath = $processInfo.Path
                ProcessDescription = $processInfo.Description
                CreationTime = $_.CreationTime
            }
        }
        $connections += $tcpConnections
    }
    
    if ($Protocol -eq "UDP" -or $Protocol -eq "All") {
        Write-Host "Retrieving UDP connections..." -ForegroundColor $Colors.UDP
        
        $udpConnections = Get-NetUDPEndpoint | ForEach-Object {
            $processInfo = Get-ProcessInfo $_.OwningProcess
            
            [PSCustomObject]@{
                Protocol = "UDP"
                LocalAddress = Format-Address $_.LocalAddress $_.LocalPort
                RemoteAddress = "*:*"
                State = "N/A"
                ProcessId = $_.OwningProcess
                ProcessName = $processInfo.Name
                ProcessPath = $processInfo.Path
                ProcessDescription = $processInfo.Description
                CreationTime = $_.CreationTime
            }
        }
        $connections += $udpConnections
    }
    
    if ($State -ne "All") {
        $connections = $connections | Where-Object { $_.State -eq $State }
    }
    
    if ($ShowListening) {
        $connections = $connections | Where-Object { $_.State -eq "Listen" -or $_.Protocol -eq "UDP" }
    }
    
    if ($ShowEstablished) {
        $connections = $connections | Where-Object { $_.State -eq "Established" }
    }
    
    return $connections | Sort-Object Protocol, LocalAddress
}

function Display-Connections {
    param([array]$Connections)

    $outputBuffer = @()

    $outputLine = "`n" + "="*120
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $outputLine = "Red Koala DFIR NETWORK CONNECTIONS REPORT"
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $outputLine = "Generated: $(Get-Date)"
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $outputLine = "Total Connections: $($Connections.Count)"
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $outputLine = "="*120
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $format = "{0,-8} {1,-35} {2,-45} {3,-12} {4,-8} {5,-20} {6}"
    $outputLine = $format -f "Protocol", "Local Address", "Remote Address", "State", "PID", "Process", "Description"
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $outputLine = "-" * 120
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    foreach ($conn in $Connections) {
        $color = switch ($conn.Protocol) {
            "TCP" { switch ($conn.State) {
                "Listen" { $Colors.Listening }
                "Established" { $Colors.Established }
                default { $Colors.TCP }
            } }
            "UDP" { $Colors.UDP }
            default { $Colors.Process }
        }

        $line = $format -f $conn.Protocol, 
                         $conn.LocalAddress, 
                         $conn.RemoteAddress, 
                         $conn.State, 
                         $conn.ProcessId, 
                         $conn.ProcessName,
                         $conn.ProcessDescription

        Write-Host $line -ForegroundColor $color
        $outputBuffer += $line
    }

    $outputLine = "`n" + "="*120
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $outputLine = "SUMMARY STATISTICS"
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $outputLine = "="*120
    Write-Host $outputLine -ForegroundColor $Colors.Header
    $outputBuffer += $outputLine

    $stats = $Connections | Group-Object Protocol | ForEach-Object {
        "$($_.Name): $($_.Count) connections"
    }
    $stats | ForEach-Object {
        Write-Host $_ -ForegroundColor $Colors.Process
        $outputBuffer += $_
    }

    if ($Protocol -eq "TCP" -or $Protocol -eq "All") {
        $tcpStates = $Connections | Where-Object Protocol -eq "TCP" | Group-Object State | ForEach-Object {
            "TCP $($_.Name): $($_.Count)"
        }
        $tcpStates | ForEach-Object {
            Write-Host $_ -ForegroundColor $Colors.TCP
            $outputBuffer += $_
        }
    }

    if ($SaveToText) {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $outputFile = Join-Path -Path $desktopPath -ChildPath "DeviceConnection.txt"
        $outputBuffer | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "`nReport saved to $outputFile" -ForegroundColor $Colors.Header
    }
}

try {
    Clear-Host
    Write-Host "Red Koala DFIR Network Connections Analyser" -ForegroundColor $Colors.Header
    Write-Host "===========================================" -ForegroundColor $Colors.Header
    
    if (-not $NoResolve) {
        Write-Host "Note: DNS resolution enabled. Use -NoResolve for faster execution." -ForegroundColor $Colors.Warning
    }
    
    $connections = Get-EnhancedNetConnections
    Display-Connections $connections
    
    if ($ExportCsv) {
        $connections | Export-Csv -Path $ExportCsv -NoTypeInformation
        Write-Host "`nResults exported to: $ExportCsv" -ForegroundColor $Colors.Header
    }
    
    Write-Host "`nDNS Cache entries: $($DnsCache.Count)" -ForegroundColor $Colors.Process
}
catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor $Colors.Warning
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor $Colors.Warning
}

# including a usage example for cvs output flag, as I find it personally useful.
<#
    .\red-koala.ps1 -ExportCsv "redkoala.csv"
    #>