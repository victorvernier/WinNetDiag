#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false, HelpMessage='Optional: Pre-populates Hostname/IP for option [4] Advanced Diagnostics.')]
    [string]$TargetHost,
    [Parameter(Mandatory=$false, HelpMessage='Optional: Pre-populates TCP Port for option [4] Advanced Diagnostics.')]
    [int]$TargetPort,
    [Parameter(Mandatory=$false, HelpMessage='If present when choosing option [3], skips confirmation before Deep Resets (Use with EXTREME CAUTION!).')]
    [switch]$ForceDeepReset, # CAUTION!
    [Parameter(Mandatory=$false, HelpMessage='Suppresses most informational and action messages for quieter output.')]
    [switch]$Quiet,
    [Parameter(Mandatory=$false, HelpMessage='Specifies the base directory for saving all logs. Defaults to a "Logs" subfolder in the script directory.')]
    [string]$CentralLogBasePath = $null
)

<#
.SYNOPSIS
    Windows network diagnostics and repair script v1.9.1 (Menu Driven, Config File, Log Rotation, Quiet Mode, Fixes).

.DESCRIPTION
    Provides an interactive menu to diagnose and repair Windows network connectivity issues.
    Reads settings from WinNetDiag.config.json (if found). Performs log rotation. Implements -Quiet parameter.
    Includes Initial Checks, Basic Tests, Progressive Fixes, Targeted Diagnostics, Connection Viewing.
    Generates detailed logs.

.NOTES
    Requires execution as Administrator.
    DEEP RESETS (in option [3]) REQUIRE MANUAL REBOOT AFTERWARDS.
    Creates/Uses 'WinNetDiag.config.json' in the script directory for defaults.
#>

#region Global Script State Variables
$script:logPath = $null
$script:rebootRequired = $false
$script:config = $null # Initialize config variable
#endregion

#region Helper Functions

Function Load-Configuration {
    <# .SYNOPSIS Loads configuration from JSON file or creates default. #>
    param(
        [string]$ScriptPath,
        [switch]$IsQuiet
    )
    $configFileName = "WinNetDiag.config.json"
    $configFilePath = Join-Path -Path $ScriptPath -ChildPath $configFileName
    $loadedConfig = $null

    if (Test-Path $configFilePath -PathType Leaf) {
        try {
            $loadedConfig = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json -ErrorAction Stop
            if (-not $IsQuiet) { Write-Host "INFO: Loaded configuration from '$configFileName'." -ForegroundColor DarkGray }
        } catch {
            Write-Warning "WARNING: Failed to load or parse '$configFileName'. Using script defaults. Error: $($_.Exception.Message)"
            $loadedConfig = $null
        }
    } else {
        if (-not $IsQuiet) { Write-Host "INFO: Configuration file '$configFileName' not found. Using defaults & attempting creation." -ForegroundColor DarkGray }
        $defaultConfig = @{
          Defaults = @{ TestTargetHost="www.google.com"; TestExternalIP="8.8.8.8"; TestIPv6TargetHost="ipv6.google.com"; RelativeLogFolderName="Logs" }
          Checks = @{ ServicesToCheck=@("Dhcp","Dnscache","NlaSvc"); EventLogLookbackHours=24 }
          Logging = @{ LogRetentionDays=30 }
        }
        try {
            $defaultConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath $configFilePath -Encoding UTF8 -ErrorAction Stop
            Write-Host "INFO: Created default configuration file: '$configFilePath'" -ForegroundColor Green
            $loadedConfig = $defaultConfig
        } catch {
            Write-Warning "WARNING: Could not create default configuration file at '$configFilePath'. Check permissions. Using internal defaults. Error: $($_.Exception.Message)"
            $loadedConfig = $defaultConfig # Use defaults in memory
        }
    }
    # Ensure config structure integrity
    if ($null -eq $loadedConfig) { $loadedConfig = @{} }
    if ($null -eq $loadedConfig.Defaults) { $loadedConfig.Defaults = @{} }
    if ($null -eq $loadedConfig.Checks) { $loadedConfig.Checks = @{} }
    if ($null -eq $loadedConfig.Logging) { $loadedConfig.Logging = @{} }

    return $loadedConfig
}

Function Cleanup-OldLogs {
    <# .SYNOPSIS Removes old log files based on retention days. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$MachineLogDir,
        [string]$LogUser,
        [int]$RetentionDays,
        [switch]$IsQuiet
    )
    if ($RetentionDays -gt 0 -and (Test-Path -Path $MachineLogDir -PathType Container)) {
        $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $IsQuiet){ Write-Host "`n[$stepTime] Action: Checking for old log files (>$($RetentionDays) days) in '$MachineLogDir'..." -ForegroundColor Yellow }
        try {
            $cutoffDate = (Get-Date).AddDays(-$RetentionDays); $logPattern = "$($LogUser)_*.log"
            $oldLogs = Get-ChildItem -Path $MachineLogDir -Filter $logPattern -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoffDate }
            if ($oldLogs) {
                Write-Warning "  INFO: Found $($oldLogs.Count) old log file(s) to remove."
                foreach ($logFile in $oldLogs) {
                    if ($pscmdlet.ShouldProcess($logFile.FullName, "Remove Old Log File")) {
                        try {
                            Remove-Item -Path $logFile.FullName -Force -ErrorAction Stop
                            if (-not $IsQuiet) { Write-Host "    -> Removed: $($logFile.Name)" -ForegroundColor DarkGray }
                        } catch { Write-Warning "    -> FAILED to remove '$($logFile.Name)': $($_.Exception.Message)" }
                    }
                }
                if (-not $IsQuiet) { Write-Host "  RESULT: Old log cleanup attempt finished." -ForegroundColor Green }
            } else { if (-not $IsQuiet){ Write-Host "  RESULT: No old log files found to remove." -ForegroundColor Green } }
        } catch { Write-Warning "  RESULT: ERROR during old log cleanup: $($_.Exception.Message)" }
        # No separator line here, part of setup block
    } elseif ($RetentionDays -le 0 -and (-not $IsQuiet)) {
        Write-Host "INFO: Log rotation disabled (RetentionDays <= 0)." -ForegroundColor Yellow
    }
}

Function Show-MainMenu {
    <# .SYNOPSIS Displays the interactive menu options. #>
    Clear-Host; $titleColor = "Cyan"; $optionColor = "Yellow"; $promptColor = "White"
    Write-Host ("="*60) -ForegroundColor $titleColor; Write-Host (" WinNetDiag - Network Diagnostics & Repair Tool (Menu)") -ForegroundColor $titleColor; Write-Host ("="*60) -ForegroundColor $titleColor
    Write-Host "`n Choose an option:`n" -ForegroundColor $promptColor
    Write-Host " [1] Basic Check" -ForegroundColor $optionColor; Write-Host "     (Checks, Basic Test, Light Fixes if needed)"
    Write-Host " [2] Medium Check" -ForegroundColor $optionColor; Write-Host "     (Basic Check + Adapter Reset if needed)"
    Write-Host " [3] Advanced Fix Attempt" -ForegroundColor $optionColor; Write-Host "     (Medium Check + Deep Reset Option - REBOOT!)"
    Write-Host " [4] Targeted Diagnostics" -ForegroundColor $optionColor; Write-Host "     (Latency/Route/Proxy/Hosts for specific target)"
    Write-Host " [5] Initial System Checks Only" -ForegroundColor $optionColor; Write-Host "     (Connections, Services, Firewall, Events)"
    Write-Host " [6] Show Active Connections Only" -ForegroundColor $optionColor
    Write-Host " [Q] Quit" -ForegroundColor $optionColor
    Write-Host ("-"*60) -ForegroundColor $titleColor
}

Function Show-InitialChecks {
    <# .SYNOPSIS Runs the initial system state checks. #>
    param([switch]$Quiet)
    $phaseTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){ Write-Host "`n[$phaseTime] Running Initial System State Checks..." -ForegroundColor Magenta }
    Show-IntuitiveConnections -Quiet:$Quiet; Check-NetworkServices -Quiet:$Quiet; Check-WindowsFirewall -Quiet:$Quiet; Check-NetworkEvents -Quiet:$Quiet
    if (-not $Quiet) { Write-Host "----------------------------------------------------------------------" }
}

Function Test-BasicConnectivity {
    <# .SYNOPSIS Performs essential tests for IPv4 and basic IPv6 connectivity. Returns $true if critical tests pass. #>
    [CmdletBinding()]
    param(
        # Use hardcoded defaults to ensure function works even if config load fails
        [string]$TargetHost = "www.google.com",
        [string]$ExternalIP = "8.8.8.8",
        [string]$IPv6TargetHost = "ipv6.google.com",
        [switch]$Quiet
    )
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; if (-not $Quiet){Write-Host "`n--- [$startTime] STARTING: Basic Connectivity Tests (IPv4 & IPv6) ---" -ForegroundColor Cyan}; $globalConnectivityOK = $true; $ipv4ConnectivityOK = $true; $ipv6Configured = $false; $ipv6ConnectivityOK = $true

    if (-not $Quiet){ Write-Host "`n[IPv4 Checks]" -ForegroundColor White }
    $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){Write-Host "[$stepTime - Step 1/6] Testing IPv4 Default Gateway..." -ForegroundColor Yellow}
    $gateway4 = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null}).IPv4DefaultGateway.NextHop
    if ($gateway4) { if (-not $Quiet){Write-Host "  INFO: IPv4 Gateway ($gateway4)." -ForegroundColor DarkGray}; Write-Host "  ACTION: Pinging..." -ForegroundColor DarkGray; $success = Test-NetConnection $gateway4 -InformationLevel Quiet -ErrorAction SilentlyContinue; if (-not $success) { $ipv4ConnectivityOK = $false; Write-Warning "  RESULT: FAILED." } else { Write-Host "  RESULT: SUCCESS." -ForegroundColor Green } }
    else { Write-Warning "  INFO: No IPv4 Default Gateway found."; $ipv4ConnectivityOK = $false }

    $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){Write-Host "`n[$stepTime - Step 2/6] Testing IPv4 DNS Servers..." -ForegroundColor Yellow}
    $dnsServers4 = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; $dns4Responded = $false
    if ($dnsServers4) { if (-not $Quiet){Write-Host "  INFO: IPv4 DNS Servers ($($dnsServers4 -join ', '))." -ForegroundColor DarkGray}; Write-Host "  ACTION: Checking port 53..." -ForegroundColor DarkGray; foreach ($dns in $dnsServers4) { if (Test-NetConnection $dns -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue) { if (-not $Quiet){Write-Host "    -> $dns responded." -ForegroundColor Green}; $dns4Responded = $true } else { Write-Warning "    -> $dns did NOT respond." } }; if (-not $dns4Responded) { Write-Warning "  RESULT: None responded." } else { Write-Host "  RESULT: >=1 responded." -ForegroundColor Green } }
    else { Write-Warning "  INFO: No IPv4 DNS Servers found." }

    $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){Write-Host "`n[$stepTime - Step 3/6] Testing IPv4 DNS Resolution ($TargetHost)..." -ForegroundColor Yellow}
    if ($dnsServers4 -and $dns4Responded) { if (-not $Quiet){Write-Host "  INFO: Attempting resolve '$TargetHost' via IPv4 DNS..." -ForegroundColor DarkGray}; Write-Host "  ACTION: Running Resolve-DnsName (A)..." -ForegroundColor DarkGray; if (Resolve-DnsName $TargetHost -Type A -ErrorAction SilentlyContinue) { Write-Host "  RESULT: SUCCESS." -ForegroundColor Green } else { Write-Warning "  RESULT: FAILED."; $ipv4ConnectivityOK = $false } } else { Write-Warning "  INFO: Skipping IPv4 DNS resolution test." }

    if (-not $Quiet){ Write-Host "`n[IPv6 Checks]" -ForegroundColor White }
    $ipv6Interfaces = Get-NetIPConfiguration | Where-Object {$_.IPv6Address.IPAddress -like 'fe80*' -or $_.IPv6Address.IPAddress -notlike '::1'}
    if ($ipv6Interfaces) {
        $ipv6Configured = $true; $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){Write-Host "[$stepTime - Step 4/6] Testing IPv6 Default Gateway..." -ForegroundColor Yellow}
        $gateway6 = ($ipv6Interfaces | Where-Object {$_.IPv6DefaultGateway -ne $null} | Select-Object -First 1).IPv6DefaultGateway.NextHop
        if ($gateway6) { if (-not $Quiet){Write-Host "  INFO: IPv6 Gateway ($gateway6)." -ForegroundColor DarkGray}; Write-Host "  ACTION: Pinging..." -ForegroundColor DarkGray; $success = Test-NetConnection $gateway6 -InformationLevel Quiet -ErrorAction SilentlyContinue; if (-not $success) { $ipv6ConnectivityOK = $false; Write-Warning "  RESULT: FAILED." } else { Write-Host "  RESULT: SUCCESS." -ForegroundColor Green } }
        else { Write-Warning "  INFO: No IPv6 Default Gateway found."; $ipv6ConnectivityOK = $false }

        $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){Write-Host "`n[$stepTime - Step 5/6] Testing IPv6 DNS Servers..." -ForegroundColor Yellow}
        $dnsServers6 = (Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses; $dns6Responded = $false
        if ($dnsServers6) { if (-not $Quiet){Write-Host "  INFO: IPv6 DNS Servers ($($dnsServers6 -join ', '))." -ForegroundColor DarkGray}; Write-Host "  ACTION: Checking port 53..." -ForegroundColor DarkGray; foreach ($dns in $dnsServers6) { if (Test-NetConnection $dns -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue) { if (-not $Quiet){Write-Host "    -> $dns responded." -ForegroundColor Green}; $dns6Responded = $true } else { Write-Warning "    -> $dns did NOT respond." } }; if (-not $dns6Responded) { Write-Warning "  RESULT: None responded."} else { Write-Host "  RESULT: >=1 responded." -ForegroundColor Green } }
        else { Write-Warning "  INFO: No IPv6 DNS Servers found." }

        $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){Write-Host "`n[$stepTime - Step 6/6] Testing IPv6 DNS Resolution & Connection ($IPv6TargetHost)..." -ForegroundColor Yellow}
        if ($dnsServers6 -and $dns6Responded) { if (-not $Quiet){Write-Host "  INFO: Attempting resolve & connect to '$IPv6TargetHost' via IPv6..." -ForegroundColor DarkGray}; Write-Host "  ACTION: Running Resolve-DnsName (AAAA) & Test-NetConnection..." -ForegroundColor DarkGray; $ipv6Resolved = $false; if (Resolve-DnsName $IPv6TargetHost -Type AAAA -ErrorAction SilentlyContinue) { Write-Host "    -> Resolution OK." -ForegroundColor Green; $ipv6Resolved = $true } else { Write-Warning "    -> Resolution FAILED." }; $ipv6Connected = $false; if (Test-NetConnection $IPv6TargetHost -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue) { Write-Host "    -> HTTPS Connection OK." -ForegroundColor Green; $ipv6Connected = $true } else { Write-Warning "    -> HTTPS Connection FAILED." }; if (-not $ipv6Resolved -or -not $ipv6Connected) { $ipv6ConnectivityOK = $false }; Write-Host "  RESULT: IPv6 Resolution=$ipv6Resolved, Connection=$ipv6Connected." }
        else { Write-Warning "  INFO: Skipping IPv6 resolution/connection test."; $ipv6ConnectivityOK = $false }
    } else { if (-not $Quiet){ Write-Host "INFO: No significant IPv6 config detected. Skipping." -ForegroundColor Yellow }; $ipv6ConnectivityOK = $true }

    $globalConnectivityOK = $ipv4ConnectivityOK -or ($ipv6Configured -and $ipv6ConnectivityOK) -or (-not $ipv6Configured -and $ipv4ConnectivityOK)
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $overallResult = if($globalConnectivityOK){'OK'}else{'FAILED'}; Write-Host "`n--- [$endTime] FINISHED: Basic Connectivity Tests (Overall Result: $overallResult) ---" -ForegroundColor Cyan; return $globalConnectivityOK
}

Function Apply-LightweightFixes {
    <# .SYNOPSIS Applies common network fixes that do not require a reboot. Uses PowerShell native commands. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([switch]$Quiet)
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; if (-not $Quiet){Write-Host "`n--- [$startTime] STARTING: Applying Lightweight Fixes ---" -ForegroundColor Cyan}; $actionsAttempted = $false
    $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n[$stepTime] Action: Flushing DNS Cache..." -ForegroundColor Yellow; if (-not $Quiet) { Write-Host "  INFO: Removing potentially stale name-to-IP mappings." -ForegroundColor DarkGray }
    try { Clear-DnsClientCache; Write-Host "  RESULT: SUCCESS." -ForegroundColor Green; $actionsAttempted = $true } catch { Write-Error "  RESULT: ERROR - $($_.Exception.Message)" }
    $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n[$stepTime] Action: Checking for & Renewing IP Address (if DHCP)..." -ForegroundColor Yellow
    $dhcpAdapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Get-NetIPConfiguration | Where-Object {$_.DhcpEnabled -eq $true}
    if ($dhcpAdapters) {
        if (-not $Quiet){ Write-Host "  INFO: Active DHCP adapter(s) found. Attempting restart..." -ForegroundColor DarkGray }
        foreach ($adapterConfig in $dhcpAdapters) {
            $adapter = Get-NetAdapter -InterfaceIndex $adapterConfig.InterfaceIndex; Write-Host "  ACTION: Attempting restart of adapter '$($adapter.Name)'..." -ForegroundColor DarkGray
            try { if ($pscmdlet.ShouldProcess($adapter.Name, "Restart Network Adapter (for DHCP Renew)")) { Restart-NetAdapter -InterfaceIndex $adapter.InterfaceIndex -Confirm:$false -ErrorAction Stop; Write-Host "  RESULT: Adapter '$($adapter.Name)' restart attempted." -ForegroundColor Green; $actionsAttempted = $true; Start-Sleep -Seconds 5 } }
            catch { Write-Warning "  RESULT: ERROR attempting restart for '$($adapter.Name)': $($_.Exception.Message)" }
        }
    } else { Write-Host "  INFO: No active DHCP adapters found or using static IP. Skipped." -ForegroundColor Yellow }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$endTime] FINISHED: Applying Lightweight Fixes ---" -ForegroundColor Cyan; return $actionsAttempted
}

Function Reset-NetworkAdapters {
     <# .SYNOPSIS Attempts to disable and re-enable active physical network adapters. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([switch]$Quiet)
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$startTime] STARTING: Attempting Network Adapter Reset ---" -ForegroundColor Cyan; $actionsSucceeded = $false
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Physical -eq $true}
    if ($adapters) {
        if (-not $Quiet){ Write-Host "  INFO: Found active physical adapter(s): $($adapters.Name -join ', ')." -ForegroundColor DarkGray }
        foreach ($adapter in $adapters) {
            $adapterName = $adapter.Name; $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n  [$stepTime] Action: Attempting disable/re-enable cycle for '$adapterName'..." -ForegroundColor Yellow
            try {
                if ($pscmdlet.ShouldProcess($adapterName, "Disable Adapter")) { Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop; Write-Host "    INFO: Adapter '$adapterName' disabled. Waiting 5 seconds..." -ForegroundColor DarkGray; Start-Sleep -Seconds 5 }
                if ($pscmdlet.ShouldProcess($adapterName, "Enable Adapter")) { Enable-NetAdapter -Name $adapterName -ErrorAction Stop; Write-Host "    RESULT: SUCCESS re-enabling '$adapterName'." -ForegroundColor Green; $actionsSucceeded = $true }
            } catch { Write-Error "    RESULT: ERROR during reset cycle for '$adapterName': $($_.Exception.Message)" }
        }
    } else { Write-Host "  INFO: No active physical network adapters found to reset." -ForegroundColor Yellow }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$endTime] FINISHED: Attempting Network Adapter Reset ---" -ForegroundColor Cyan; return $actionsSucceeded
}

Function Propose-DeepResets {
    <# .SYNOPSIS Offers to execute Winsock and TCP/IP stack resets (netsh). MANDATORY REBOOT REQUIRED. #>
    [CmdletBinding()]
    param( [switch]$ForceWithoutConfirmation = $false, [switch]$Quiet )
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$startTime] OPTION: Deep Resets (REBOOT REQUIRED) ---" -ForegroundColor Yellow
    Write-Warning "CRITICAL WARNING: The following actions reset core networking components (Winsock, TCP/IP)."; Write-Warning "A MANUAL REBOOT IS MANDATORY AFTERWARDS for changes to take full effect!"
    $confirmation = 'N'; if ($ForceWithoutConfirmation) { Write-Warning "  WARNING: -ForceDeepReset parameter detected. Executing resets WITHOUT confirmation!"; $confirmation = 'Y' } else { while ($confirmation -ne 'Y' -and $confirmation -ne 'N') { $confirmation = (Read-Host "Proceed with these resets? (Y/N)").ToUpper() } }
    $actionsExecuted = $false
    if ($confirmation -eq 'Y') {
        Write-Host "  INFO: User confirmed (or forced). Proceeding..." -ForegroundColor Yellow
        $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n  [$stepTime] Action: Resetting Winsock Catalog..." -ForegroundColor Yellow; if (-not $Quiet){ Write-Host "    INFO: May fix corruption related to network access interface." -ForegroundColor DarkGray }; Write-Host "    ACTION: Executing 'netsh winsock reset'..." -ForegroundColor DarkGray
        $resetWinsockOutput = netsh winsock reset; if (-not $Quiet){ Write-Host "    Command Output:`n$resetWinsockOutput" -ForegroundColor Gray }
        if ($LASTEXITCODE -eq 0) { Write-Host "    RESULT: SUCCESS. Reboot required." -ForegroundColor Green } else { Write-Warning "    RESULT: Command may have FAILED (Exit Code: $LASTEXITCODE). Reboot still recommended." }
        $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n  [$stepTime] Action: Resetting TCP/IP Stack..." -ForegroundColor Yellow; if (-not $Quiet){ Write-Host "    INFO: Resets TCP/IP configurations to defaults." -ForegroundColor DarkGray }; Write-Host "    ACTION: Executing 'netsh int ip reset'..." -ForegroundColor DarkGray
        $resetIPOutput = netsh int ip reset; if (-not $Quiet){ Write-Host "    Command Output:`n$resetIPOutput" -ForegroundColor Gray }
        if ($LASTEXITCODE -eq 0) { Write-Host "    RESULT: SUCCESS. Reboot required." -ForegroundColor Green } else { Write-Warning "    RESULT: Command may have FAILED (Exit Code: $LASTEXITCODE). Reboot still recommended." }
        Write-Host "-------------------------------------------------------------" -ForegroundColor Red; Write-Host " CRITICAL REMINDER: MANUALLY REBOOT THE COMPUTER NOW!       " -ForegroundColor Red -BackgroundColor White; Write-Host " Resets only take full effect after restarting the system.  " -ForegroundColor Red -BackgroundColor White; Write-Host "-------------------------------------------------------------" -ForegroundColor Red
        $actionsExecuted = $true; $script:rebootRequired = $true
    } else { Write-Host "  INFO: Deep reset operation cancelled/skipped by user." -ForegroundColor Yellow }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "--- [$endTime] FINISHED: Deep Resets Option (Actions Executed: $actionsExecuted) ---" -ForegroundColor Cyan; return $actionsExecuted
}

Function Check-NetworkServices {
     <# .SYNOPSIS Checks status of essential network services and optionally offers restart. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([switch]$Quiet)
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$startTime] STARTING: Checking Essential Network Services ---" -ForegroundColor Cyan;
    # Use hardcoded list temporarily to ensure script runs
    $servicesToCheck = @("Dhcp", "Dnscache", "NlaSvc")
    if (-not $Quiet){ Write-Host "  INFO: Checking status for: $($servicesToCheck -join ', ')." -ForegroundColor DarkGray }
    try {
        $serviceStatus = Get-Service -Name $servicesToCheck -ErrorAction Stop; $serviceStatus | Format-Table Name, Status, DisplayName -AutoSize; Write-Host "  RESULT: Service status listed above." -ForegroundColor Green
        $stoppedServices = $serviceStatus | Where-Object {$_.Status -ne 'Running'}
        if ($stoppedServices) {
            Write-Warning "  WARNING: One or more essential network services stopped: $($stoppedServices.Name -join ', ')"
            if (-not $Quiet) {
                $confirmRestart = ''; while ($confirmRestart -ne 'Y' -and $confirmRestart -ne 'N') { $confirmRestart = (Read-Host "Attempt to restart stopped essential service(s)? (Y/N)").ToUpper() }
                if ($confirmRestart -eq 'Y') {
                    foreach ($service in $stoppedServices) {
                        Write-Host "  ACTION: Attempting restart of service '$($service.Name)'..." -ForegroundColor Yellow
                        if ($pscmdlet.ShouldProcess($service.Name, "Restart Service")) {
                            try { Restart-Service -Name $service.Name -ErrorAction Stop; Write-Host "    RESULT: Restart command sent for '$($service.Name)'." -ForegroundColor Green }
                            catch { Write-Error "    RESULT: ERROR restarting '$($service.Name)': $($_.Exception.Message)" }
                        }
                    }
                } else { Write-Host "  INFO: Restart skipped by user." -ForegroundColor Yellow }
            } else { Write-Host "  INFO: Quiet mode, skipping restart prompt." -ForegroundColor DarkGray }
        }
    } catch { Write-Error "  RESULT: ERROR checking services: $($_.Exception.Message)" }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "--- [$endTime] FINISHED: Checking Essential Network Services ---" -ForegroundColor Cyan
}

Function Check-WindowsFirewall {
     <# .SYNOPSIS Checks the status of the Windows Firewall profiles. #>
    [CmdletBinding()]
    param([switch]$Quiet)
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$startTime] STARTING: Checking Windows Firewall Status ---" -ForegroundColor Cyan; if (-not $Quiet){ Write-Host "  INFO: Checking if Windows Firewall profiles are active." -ForegroundColor DarkGray }
    try { $profiles = Get-NetFirewallProfile; $profiles | Format-Table Name, Enabled -AutoSize; Write-Host "  RESULT: Firewall profile status listed above. 'Enabled=True' means active." -ForegroundColor Green; if ($profiles | Where-Object {$_.Enabled -ne $True}) { Write-Warning "  WARNING: One or more firewall profiles are disabled."} } catch { Write-Error "  RESULT: ERROR checking firewall status: $($_.Exception.Message)" }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "--- [$endTime] FINISHED: Checking Windows Firewall Status ---" -ForegroundColor Cyan
}

Function Check-NetworkEvents {
    <# .SYNOPSIS Searches for recent critical network-related errors/warnings in Windows Event Log. #>
    [CmdletBinding()]
    param(
        # Use hardcoded default temporarily
        [int]$LookbackHours = 24,
        [switch]$Quiet
     )
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$startTime] STARTING: Searching for Critical Network Events (Last $LookbackHours hours) ---" -ForegroundColor Cyan; if (-not $Quiet){ Write-Host "  INFO: Searching 'System' log for recent Errors/Critical Warnings from network providers." -ForegroundColor DarkGray }
    $startDate = (Get-Date).AddHours(-$LookbackHours); $providers = "*Tcpip*", "*NetBT*", "Microsoft-Windows-Dhcp-Client", "Microsoft-Windows-DNS-Client", "NlaSvc", "*Netwtw*", "*e2fexpress*", "*rtwlanu*", "*E1G*", "*b57nd*", "*RTL*", "*vmxnet*"
    $filter = @{ LogName = 'System'; StartTime = $startDate; Level = 2, 3; ProviderName = $providers }
    try { $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue; if ($events) { Write-Warning "  RESULT: Found $($events.Count) potentially relevant Error/Warning events:"; $events | Format-Table TimeCreated, ID, LevelDisplayName, ProviderName, Message -AutoSize -Wrap } else { Write-Host "  RESULT: No critical network events found matching criteria." -ForegroundColor Green } } catch { Write-Error "  RESULT: ERROR searching event log: $($_.Exception.Message)" }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "--- [$endTime] FINISHED: Searching for Critical Network Events ---" -ForegroundColor Cyan
}

Function Run-AdvancedDiagnostics {
     <# .SYNOPSIS Runs diagnostics targeted at a specific host/port. #>
     [CmdletBinding()]
     param( [string]$TargetHostOverride, [int]$TargetPortOverride, [switch]$Quiet )
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "`n--- [$startTime] STARTING: Advanced Diagnostics (Targeted) ---" -ForegroundColor Cyan
    $localTargetHost = $TargetHostOverride; $localTargetPort = $TargetPortOverride
    if (-not $localTargetHost -and (-not $Quiet)) { $localTargetHost = Read-Host "Enter Hostname/IP for targeted diagnostics"; if (-not $localTargetHost) { Write-Warning "No target provided. Skipping."; return $null }; $portInput = Read-Host "Enter Port (optional)"; if ($portInput -match '^\d+$') { $localTargetPort = [int]$portInput } }
    elseif (-not $localTargetHost -and $Quiet) { Write-Warning "INFO: Quiet mode and no -TargetHost provided. Skipping advanced diagnostics."; return $null }
    Write-Host "  INFO: Running advanced diagnostics for Target='$localTargetHost'" -ForegroundColor DarkGray; if ($localTargetPort) { Write-Host "  INFO: Targeting specific Port '$localTargetPort'" -ForegroundColor DarkGray }
    $resolvedTargetIP = $null
    $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n[$stepTime] Action: Attempting to resolve '$localTargetHost' to IP..." -ForegroundColor Yellow; if (-not $Quiet){ Write-Host "  INFO: Translating hostname to IP." -ForegroundColor DarkGray }
    try { if ($localTargetHost -as [ipaddress]) { $resolvedTargetIP = $localTargetHost; Write-Host "  INFO: '$localTargetHost' is already an IP." -ForegroundColor Gray } else { $dnsResultA = Resolve-DnsName -Name $localTargetHost -Type A -DnsOnly -ErrorAction SilentlyContinue | Select-Object -First 1; if ($dnsResultA) { $resolvedTargetIP = $dnsResultA.IPAddress; Write-Host "  RESULT: Resolved to IPv4: $resolvedTargetIP" -ForegroundColor Green } else { $dnsResultAAAA = Resolve-DnsName -Name $localTargetHost -Type AAAA -DnsOnly -ErrorAction SilentlyContinue | Select-Object -First 1; if ($dnsResultAAAA){ $resolvedTargetIP = $dnsResultAAAA.IPAddress; Write-Host "  RESULT: Resolved to IPv6: $resolvedTargetIP" -ForegroundColor Green } else { Write-Warning "  RESULT: FAILED to resolve '$localTargetHost' (A or AAAA)." } } } } catch { Write-Warning "  RESULT: ERROR during DNS resolution: $($_.Exception.Message)" }
    $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n[$stepTime] Action: Testing detailed connection to '$localTargetHost'" -ForegroundColor Yellow; if (-not $Quiet){ Write-Host "  INFO: Checking connectivity and latency." -ForegroundColor DarkGray }; $testParams = @{ ComputerName = $localTargetHost; InformationLevel = 'Detailed'; ErrorAction = 'SilentlyContinue' }; if ($localTargetPort) { $testParams.Add('Port', $localTargetPort) }
    $testResult = Test-NetConnection @testParams
    if ($testResult) { if (-not $Quiet){ Write-Host "  Test-NetConnection Result:" -ForegroundColor Gray; $testResult | Select-Object ComputerName,RemoteAddress,PingSucceeded,PingReplyDetails,TcpTestSucceeded,RemotePort | Format-List | Out-Host }; if ($testResult.PingSucceeded) { $latency = $testResult.PingReplyDetails.RoundtripTime; Write-Host "  RESULT: Ping OK (Latency: ${latency}ms)." -ForegroundColor Green; if ($latency -gt 150) { Write-Warning "    NOTE: Ping latency (${latency}ms) is somewhat high."} } elseif ($testResult.TcpTestSucceeded) { Write-Host "  RESULT: TCP test on port $localTargetPort SUCCESSFUL." -ForegroundColor Green } else { Write-Warning "  RESULT: FAILED Ping and/or TCP test. Check host/port/firewall." } } else { Write-Warning "  RESULT: FAILED Test-NetConnection execution. Host unreachable/unresolved?" }
    $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n[$stepTime] Action: Running Traceroute to '$localTargetHost'..." -ForegroundColor Yellow; if (-not $Quiet){ Write-Host "  INFO: Showing network path/hops." -ForegroundColor DarkGray }
    try { Write-Host "  Please wait..." -ForegroundColor DarkGray; Test-NetConnection -ComputerName $localTargetHost -TraceRoute -Hops 30 -InformationLevel Detailed -ErrorAction Stop | Out-Host; Write-Host "  RESULT: Traceroute finished. Analyze output for latency/*." -ForegroundColor Green } catch { Write-Warning "  RESULT: FAILED Traceroute. Cause: $($_.Exception.Message)" }
    $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n[$stepTime] Action: Checking Proxy Settings..." -ForegroundColor Yellow; if (-not $Quiet){ Write-Host "  INFO: Checking current user proxy config." -ForegroundColor DarkGray }
    try { $proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $proxyConfig = Get-ItemProperty -Path $proxyKey -ErrorAction Stop; if ($proxyConfig.ProxyEnable -eq 1) { Write-Warning "  RESULT: Manual Proxy ENABLED: $($proxyConfig.ProxyServer)." } elseif ($proxyConfig.AutoConfigURL) { Write-Warning "  RESULT: Proxy Auto-Config (PAC) Script ENABLED: $($proxyConfig.AutoConfigURL)." } else { Write-Host "  RESULT: Proxy appears DISABLED." -ForegroundColor Green } } catch { Write-Error "  RESULT: ERROR reading proxy settings: $($_.Exception.Message)" }
    $stepTime = Get-Date -Format 'HH:mm:ss'; Write-Host "`n[$stepTime] Action: Checking Hosts File..." -ForegroundColor Yellow; $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"; if (-not $Quiet){ Write-Host "  INFO: Checking $hostsPath for manual overrides." -ForegroundColor DarkGray }
    try { if (Test-Path $hostsPath) { $relevantEntries = Get-Content $hostsPath -ErrorAction Stop | Where-Object { $_ -match $localTargetHost -and $_.TrimStart() -notmatch '^#' }; if ($relevantEntries) { Write-Warning "  RESULT: ATTENTION! Active entries for '$localTargetHost' found in Hosts file:"; $relevantEntries | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow } } else { Write-Host "  RESULT: No active entries for '$localTargetHost' found." -ForegroundColor Green } } else { Write-Warning "  INFO: Hosts file not found." } } catch { Write-Error "  RESULT: ERROR reading hosts file: $($_.Exception.Message)" }
    if (-not $Quiet){ Write-Host "`n[$stepTime] INFO: Advanced diagnostics complete. Further suggestions..." -ForegroundColor Cyan; Write-Host "  - Analyze filtered connection list (if shown)."; Write-Host "  - Check application logs & Windows Event Viewer."; Write-Host "  - Consider bandwidth tests."; Write-Host "  - Investigate Firewalls & Security Software." }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "--- [$endTime] FINISHED: Advanced Diagnostics ---" -ForegroundColor Cyan; return $resolvedTargetIP
}

Function Show-IntuitiveConnections {
    <# .SYNOPSIS Displays active TCP connections intuitively. #>
    [CmdletBinding()]
    param( [string]$FilterByRemoteIP, [switch]$Quiet )
    $startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $sectionTitle = "--- [$startTime] STARTING: Active TCP Connection Check"; if (-not [string]::IsNullOrEmpty($FilterByRemoteIP)) { $sectionTitle += " [FILTERED by Remote IP: $FilterByRemoteIP]" }; $sectionTitle += " ---"; Write-Host "`n$sectionTitle" -ForegroundColor Cyan; if (-not $Quiet){ Write-Host "  INFO: Displaying current TCP connections..." -ForegroundColor DarkGray }
    $portMap = @{ 80='HTTP'; 443='HTTPS'; 21='FTP'; 22='SSH'; 23='Telnet'; 25='SMTP'; 53='DNS'; 110='POP3'; 135='RPC'; 139='NetBIOS'; 143='IMAP'; 445='SMB'; 3389='RDP'; 5900='VNC'; 1433='SQLSrv'; 1521='Oracle'; 3306='MySQL'; 5432='Postgres'; 8080='HTTP-Alt'; 8443='HTTPS-Alt' }
    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop | Select-Object *, @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
        if (-not [string]::IsNullOrEmpty($FilterByRemoteIP)) { $countBeforeFilter = $connections.Count; $connections = $connections | Where-Object { $_.RemoteAddress -eq $FilterByRemoteIP }; if (-not $Quiet){Write-Host "  INFO: Filtering $countBeforeFilter connections for Remote IP '$FilterByRemoteIP'." -ForegroundColor Magenta} }
        if ($connections.Count -eq 0) { if (-not [string]::IsNullOrEmpty($FilterByRemoteIP)){ Write-Host "  RESULT: No connections found TO remote IP '$FilterByRemoteIP'." -ForegroundColor Yellow } else { Write-Host "  RESULT: No active TCP connections found." -ForegroundColor Yellow } }
        else {
            if (-not $Quiet){ Write-Host "  ACTION: Processing $($connections.Count) connection(s)..." -ForegroundColor DarkGray }
            $formattedOutput = $connections | ForEach-Object {
                $readableState = switch ($_.State) { 'Listen' {'Listening'} 'SynSent' {'SYN Sent'} 'SynReceived' {'SYN Rcvd'} 'Established' {'Established'} 'FinWait1' {'FIN Wait 1'} 'FinWait2' {'FIN Wait 2'} 'CloseWait' {'Close Wait'} 'Closing' {'Closing'} 'LastAck' {'Last ACK'} 'TimeWait' {'Time Wait'} 'Bound' {'Bound'} default {$_.State} }
                $localInfo = switch ($_.LocalAddress) { '0.0.0.0' {'Any IP'} '::' {'Any IPv6'} '127.0.0.1' {'Localhost'} '::1' {'LocalhostIPv6'} default {$_.LocalAddress} }
                $localPort = $_.LocalPort; $localService = $portMap[$localPort]; if ($localService) { $localInfo += ":$localPort($localService)" } else { $localInfo += ":$localPort" }
                $remoteInfo = "N/A (Listening)"; if ($_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::') { $remoteInfo = $_.RemoteAddress; $remotePort = $_.RemotePort; $remoteService = $portMap[$remotePort]; if ($remoteService) { $remoteInfo += ":$remotePort($remoteService)" } else { $remoteInfo += ":$remotePort" } }
                $processInfo = "(PID:$($_.OwningProcess))"; if ($_.ProcessName) { $processInfo = "$($_.ProcessName) $processInfo" }
                [PSCustomObject]@{ State = $readableState; Local = $localInfo; Remote = $remoteInfo; OwningProcess = $processInfo }
            }
            Write-Host "  RESULT: Active TCP Connections Table:" -ForegroundColor Gray; $formattedOutput | Format-Table -AutoSize
        }
     } catch { Write-Error "  ERROR getting/processing TCP connections: $($_.Exception.Message)" }
    $endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; Write-Host "--- [$endTime] FINISHED: Active TCP Connection Check ---" -ForegroundColor Cyan
}

#endregion Helper Functions


# --- Main Script Execution Flow ---

# --- Initialization Block ---
Clear-Host
$scriptStartTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Host "======================================================================" -ForegroundColor Blue
Write-Host "              Network Diagnostics & Repair Tool (Menu)                " -ForegroundColor Blue
Write-Host "======================================================================"
Write-Host "Started: $scriptStartTime by $env:USERNAME@$env:COMPUTERNAME"
if (-not $Quiet) { Write-Host "Parameters Used: $($MyInvocation.BoundParameters.Keys -join ', ')" -ForegroundColor DarkGray }

# --- Load Configuration ---
$script:config = Load-Configuration -ScriptPath $PSScriptRoot -IsQuiet $Quiet
if (-not $Quiet) { Write-Host "----------------------------------------------------------------------" }

# --- Logging Setup ---
$logUser = $env:USERNAME; $logMachine = $env:COMPUTERNAME; $effectiveLogBasePath = $null
# Sanitize names for path safety
$invalidChars = [System.IO.Path]::GetInvalidFileNameChars() + [System.IO.Path]::GetInvalidPathChars() | Select-Object -Unique
$regexInvalidChars = '[{0}]' -f ([regex]::Escape(-join $invalidChars))
$logUser = ($logUser -replace $regexInvalidChars, '_')
$logMachine = ($logMachine -replace $regexInvalidChars, '_')

# Use parameter if provided, else default logic using config or hardcoded "Logs"
if (-not [string]::IsNullOrEmpty($CentralLogBasePath)) { $effectiveLogBasePath = $CentralLogBasePath; if (-not $Quiet){Write-Host "INFO: Using specified log base path: $effectiveLogBasePath" -ForegroundColor DarkGray} }
else { $scriptDir = $PSScriptRoot;
    # CORRECTION V1.9.2: Use hardcoded "Logs" here to bypass potential config load issue for this specific value
    $relativeLogFolder = "Logs"; # $script:config.Defaults.RelativeLogFolderName -or "Logs";
    if ($scriptDir) { $effectiveLogBasePath = Join-Path -Path $scriptDir -ChildPath $relativeLogFolder; if (-not $Quiet){Write-Host "INFO: Using default relative log base path: $effectiveLogBasePath" -ForegroundColor DarkGray} } else { $effectiveLogBasePath = Join-Path -Path $env:TEMP -ChildPath "WinNetDiagLogs"; Write-Warning "WARNING: Could not determine script path. Using fallback log path: $effectiveLogBasePath" } }
$machineLogPath = Join-Path -Path $effectiveLogBasePath -ChildPath $logMachine

# DEBUG Lines
if (-not $Quiet) {
    Write-Host "DEBUG: Effective Log Base Path = '$effectiveLogBasePath'" -ForegroundColor Yellow
    Write-Host "DEBUG: Machine Log Path = '$machineLogPath'" -ForegroundColor Yellow
}

# --- Log Rotation ---
Cleanup-OldLogs -MachineLogDir $machineLogPath -LogUser $logUser -RetentionDays ($script:config.Logging.LogRetentionDays -or 30) -IsQuiet $Quiet

# --- Start New Log ---
$logTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'; $logFileName = "$($logUser)_$($logTimestamp).log"
$fullLogPath = Join-Path -Path $machineLogPath -ChildPath $logFileName
$script:logPath = $null
try { if (-not (Test-Path -Path $machineLogPath -PathType Container)) { if (-not $Quiet){Write-Host "INFO: Creating log directory structure: $machineLogPath" -ForegroundColor DarkGray}; New-Item -Path $machineLogPath -ItemType Directory -Force -ErrorAction Stop | Out-Null }; Start-Transcript -Path $fullLogPath -Force -ErrorAction Stop; $script:logPath = $fullLogPath; if (-not $Quiet){Write-Host "INFO: Execution log started at: $script:logPath" -ForegroundColor DarkGray} }
catch { Write-Warning "CRITICAL WARNING: Failed to start logging at '$fullLogPath'. Check permissions. Script will continue without logging."}
if (-not $Quiet) { Write-Host "----------------------------------------------------------------------" }


# --- Main Menu Loop ---
$exitLoop = $false
do {
    Show-MainMenu
    $validChoice = $false; $choiceInput = ''
    while (-not $validChoice) {
        $choiceInput = Read-Host " Enter your choice"
        if ($choiceInput -match '^[1-6q]$') { $validChoice = $true }
        else { Write-Warning "Invalid choice '$choiceInput'. Please enter 1-6 or Q." }
    }
    $choice = $choiceInput.ToUpper()

    if (-not $Quiet) { Write-Host "`nExecuting Option: [$choice]" -ForegroundColor Green }

    $iterationConnectivityOK = $null; $iterationLightweightFixDone = $false; $iterationConnectivityAfterLightweight = $null
    $iterationAdapterResetDone = $false; $iterationConnectivityAfterAdapter = $null; $ipTargetResult = $null

    switch ($choice) {
        '1' { # [1] Basic Check
            if (-not $Quiet) { Write-Host "`nACTION: Running 'Basic' Check..." -ForegroundColor Magenta }
            Show-InitialChecks -Quiet:$Quiet
            $iterationConnectivityOK = Test-BasicConnectivity -Quiet:$Quiet
            if (-not $iterationConnectivityOK) {
                Write-Warning "ANALYSIS: Basic connectivity test FAILED."
                $iterationLightweightFixDone = Apply-LightweightFixes -Quiet:$Quiet
                if ($iterationLightweightFixDone) {
                    if (-not $Quiet){ Write-Host "`nINFO: Waiting 5s..." -ForegroundColor DarkGray }; Start-Sleep 5
                    $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){ Write-Host "`n[$stepTime] ACTION: Re-testing basic connectivity..." -ForegroundColor Yellow }; $iterationConnectivityAfterLightweight = Test-BasicConnectivity -Quiet:$Quiet
                    if ($iterationConnectivityAfterLightweight){ Write-Host "`nANALYSIS: Connectivity appears RESTORED after Lightweight Fixes!" -ForegroundColor Green }
                    else{ Write-Warning "`nANALYSIS: Connectivity STILL FAILED after Lightweight Fixes."}
                }
            } else { Write-Host "ANALYSIS: Basic connectivity test PASSED." -ForegroundColor Green }
        }
        '2' { # [2] Medium Check
             if (-not $Quiet) { Write-Host "`nACTION: Running 'Medium' Check..." -ForegroundColor Magenta }
            Show-InitialChecks -Quiet:$Quiet
            $iterationConnectivityOK = Test-BasicConnectivity -Quiet:$Quiet
            if (-not $iterationConnectivityOK) {
                Write-Warning "ANALYSIS: Basic connectivity test FAILED."
                $iterationLightweightFixDone = Apply-LightweightFixes -Quiet:$Quiet
                if ($iterationLightweightFixDone) {
                    if (-not $Quiet){ Write-Host "`nINFO: Waiting 5s..." -ForegroundColor DarkGray }; Start-Sleep 5
                    $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){ Write-Host "`n[$stepTime] ACTION: Re-testing basic connectivity..." -ForegroundColor Yellow }; $iterationConnectivityAfterLightweight = Test-BasicConnectivity -Quiet:$Quiet
                }

                if (($iterationConnectivityAfterLightweight -ne $null -and -not $iterationConnectivityAfterLightweight) -or (-not $iterationLightweightFixDone -and -not $iterationConnectivityOK)) {
                     Write-Warning "`nANALYSIS: Connectivity still failing. Attempting adapter reset..."
                     $iterationAdapterResetDone = Reset-NetworkAdapters -Quiet:$Quiet
                     if ($iterationAdapterResetDone) {
                        if (-not $Quiet){ Write-Host "`nINFO: Waiting 10s..." -ForegroundColor DarkGray }; Start-Sleep 10
                        $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){ Write-Host "`n[$stepTime] ACTION: Final basic connectivity re-test..." -ForegroundColor Yellow }; $iterationConnectivityAfterAdapter = Test-BasicConnectivity -Quiet:$Quiet
                        if ($iterationConnectivityAfterAdapter){ Write-Host "`nANALYSIS: Connectivity appears RESTORED after Adapter Reset!" -ForegroundColor Green }
                        else { Write-Warning "`nANALYSIS: Connectivity STILL failing after Adapter Reset." }
                     }
                } elseif ($iterationConnectivityAfterLightweight -eq $true) { Write-Host "`nANALYSIS: Connectivity appears RESTORED after Lightweight Fixes!" -ForegroundColor Green }
            } else { Write-Host "ANALYSIS: Basic connectivity test PASSED." -ForegroundColor Green }
        }
        '3' { # [3] Advanced Fix Attempt
            if (-not $Quiet) { Write-Host "`nACTION: Running 'Advanced Fix Attempt'..." -ForegroundColor Magenta }
            Show-InitialChecks -Quiet:$Quiet
            $iterationConnectivityOK = Test-BasicConnectivity -Quiet:$Quiet
            if (-not $iterationConnectivityOK) {
                 Write-Warning "ANALYSIS: Basic connectivity test FAILED."
                 $iterationLightweightFixDone = Apply-LightweightFixes -Quiet:$Quiet
                 if ($iterationLightweightFixDone) {
                     if (-not $Quiet){ Write-Host "`nINFO: Waiting 5s..." -ForegroundColor DarkGray }; Start-Sleep 5
                     $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){ Write-Host "`n[$stepTime] ACTION: Re-testing basic connectivity..." -ForegroundColor Yellow }; $iterationConnectivityAfterLightweight = Test-BasicConnectivity -Quiet:$Quiet
                 }

                if (($iterationConnectivityAfterLightweight -ne $null -and -not $iterationConnectivityAfterLightweight) -or (-not $iterationLightweightFixDone -and -not $iterationConnectivityOK)) {
                     Write-Warning "`nANALYSIS: Connectivity still failing. Attempting adapter reset..."
                     $iterationAdapterResetDone = Reset-NetworkAdapters -Quiet:$Quiet
                     if ($iterationAdapterResetDone) {
                         if (-not $Quiet){ Write-Host "`nINFO: Waiting 10s..." -ForegroundColor DarkGray }; Start-Sleep 10
                         $stepTime = Get-Date -Format 'HH:mm:ss'; if (-not $Quiet){ Write-Host "`n[$stepTime] ACTION: Final basic connectivity re-test..." -ForegroundColor Yellow }; $iterationConnectivityAfterAdapter = Test-BasicConnectivity -Quiet:$Quiet
                     }
                }

                if (($iterationConnectivityAfterAdapter -ne $null -and -not $iterationConnectivityAfterAdapter) -or `
                   (-not $iterationAdapterResetDone -and (($iterationConnectivityAfterLightweight -ne $null -and -not $iterationConnectivityAfterLightweight) -or (-not $iterationLightweightFixDone -and -not $iterationConnectivityOK))) ) {
                     Write-Warning "`nANALYSIS: All applicable non-reboot fixes failed. Proposing deep resets..."; $script:deepResetsExecuted = Propose-DeepResets -ForceWithoutConfirmation:$ForceDeepReset -Quiet:$Quiet
                } elseif (($iterationConnectivityAfterLightweight -eq $true) -or ($iterationConnectivityAfterAdapter -eq $true)) { Write-Host "`nANALYSIS: Connectivity appears RESTORED after fixes!" -ForegroundColor Green }

            } else { Write-Host "ANALYSIS: Basic connectivity test PASSED. No fixes needed." -ForegroundColor Green }
        }
        '4' { # [4] Targeted Diagnostics
            if (-not $Quiet) { Write-Host "`nACTION: Running 'Targeted Diagnostics'..." -ForegroundColor Magenta }
            $ipTargetResult = Run-AdvancedDiagnostics -TargetHostOverride $TargetHost -TargetPortOverride $TargetPort -Quiet:$Quiet
            if ($ipTargetResult) {
                if (-not $Quiet) { Write-Host "`nShowing connections filtered for target IP: $ipTargetResult" -ForegroundColor Cyan }
                Show-IntuitiveConnections -FilterByRemoteIP $ipTargetResult -Quiet:$Quiet
            } else { if (-not $Quiet) { Write-Host "`nNo specific IP resolved/provided for filtering." -ForegroundColor Yellow } }
        }
        '5' { # [5] Initial Checks Only
            if (-not $Quiet) { Write-Host "`nACTION: Running 'Initial System Checks Only'..." -ForegroundColor Magenta }
            Show-InitialChecks -Quiet:$Quiet
        }
        '6' { # [6] Show Connections Only
            if (-not $Quiet) { Write-Host "`nACTION: Running 'Show Active Connections Only'..." -ForegroundColor Magenta }
            Show-IntuitiveConnections -Quiet:$Quiet # Unfiltered
        }
        'Q' { # [Q] Quit
            Write-Host "`nExiting." -ForegroundColor Green
            $exitLoop = $true
        }
    }

    # Pause after action (unless quitting)
    if (-not $exitLoop) {
        if (-not $Quiet) { Read-Host "`nPress Enter to return to the menu..." }
        else { Start-Sleep -Seconds 1 }
    }

} until ($exitLoop)


# --- Script Finish ---
$scriptEndTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
if (-not $Quiet) { Write-Host "`nNetwork Diagnostics Script Finished at $scriptEndTime" -ForegroundColor Blue; Write-Host "======================================================================" -ForegroundColor Blue }

# Stop Logging
if ($script:logPath) { if (-not $Quiet){ Write-Host "INFO: Stopping log recording..." -ForegroundColor DarkGray }; try { Stop-Transcript } catch { Write-Warning "WARNING: Failed to stop transcript: $($_.Exception.Message)"}; if (-not $Quiet){ Write-Host "INFO: Full execution log saved to: $($script:logPath)" -ForegroundColor DarkGray } }
else { if (-not $Quiet){ Write-Host "INFO: Script finished (executed without logging)." } }
# --- End of Script ---
