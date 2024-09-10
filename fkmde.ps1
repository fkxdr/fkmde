# Check each status(prerequisite) for testing
Write-Host ""
Write-Host "Checking device configuration..."
Write-Host ""

# Get Windows Defender Real-Time Protection status
$DefenderStatus = Get-MpComputerStatus
Write-Host "Antivirus Engine Version :                                    $($DefenderStatus.AMEngineVersion )" -ForegroundColor Green
Write-Host "Antivirus Product Version :                                   $($DefenderStatus.AMProductVersion)" -ForegroundColor Green
Write-Host ""
try {
    if ($defenderStatus.RealTimeProtectionEnabled -eq $true) {
        Write-Host "Real-Time Protection Enabled :                                [OK] $($DefenderStatus.RealTimeProtectionEnabled)" -ForegroundColor Green
    } else {
        Write-Host "[6] Real-Time Protection Enabled :                                [NO] $($DefenderStatus.RealTimeProtectionEnabled)" -ForegroundColor Red
        $RealTimeProtectionDisabled = $true
    }
} catch [System.Exception] {
    Write-Host "[E] Real-Time Protection Enabled :                                [NO] The status is unknown." -ForegroundColor Red
    $RealTimeProtectionDisabled = $true
}

# MDE Sensor status
try {
    $MDEservice = Get-Service -Name "Sense" -ErrorAction Stop
    $MDEstatus = $MDEservice.Status

    if ($MDEstatus -eq "Running") {
        Write-Host "Microsoft Defender for Endpoint Sensor :                      [OK] Running" -ForegroundColor Green
    } elseif ($MDEstatus -eq "Stopped") {
        Write-Host "Microsoft Defender for Endpoint Sensor :                      [ERROR] Not Running" -ForegroundColor Red
        $MDENotRunning = $true
    }
} catch {
    Write-Host "Microsoft Defender for Endpoint Sensor :                      [ERROR] No Sense found" -ForegroundColor Red
    $MDENotRunning = $true
}

# MDE Network Protection status
try {
    $NetworkProtectionValue = (Get-MpPreference).EnableNetworkProtection
    
    if ($NetworkProtectionValue -eq 1) {
        Write-Host "Microsoft Defender for Endpoint Network Protection :          [OK] Enabled" -ForegroundColor Green
    } elseif ($NetworkProtectionValue -eq 0) {
        Write-Host "Microsoft Defender for Endpoint Network Protection :          [ERROR] Disabled" -ForegroundColor Red
        $NPDisabled = $true
    } elseif ($NetworkProtectionValue -eq 2) {
        Write-Host "Microsoft Defender for Endpoint Network Protection :          [OK] Audit" -ForegroundColor Green
    }
} catch [System.Exception] {
    Write-Host "Microsoft Defender for Endpoint Network Protection :          [ERROR] The status is unknown" -ForegroundColor Red
    $NPDisabled = $true
}

# Defender SmartScreen status
$SmartScreenValuePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (Test-Path $SmartScreenValuePath) {
    try {
        $SSvalue = Get-ItemPropertyValue -Path $SmartScreenValuePath -Name "SmartScreenEnabled"
        if ($SSvalue -eq "1") {
            Write-Host "Microsoft Defender SmartScreen : [OK] Enabled`n" -ForegroundColor Green
        } else {
            Write-Host "Microsoft Defender SmartScreen : [ERROR] Disabled`n" -ForegroundColor Red
            $SmartScreenDisabled = $true
        }
    } catch {
        Write-Host "Microsoft Defender SmartScreen :                              [WARNING] Property SmartScreenEnabled does not exist" -ForegroundColor Yellow
    }
} else {
    Write-Host "Microsoft Defender SmartScreen : [ERROR] Path not found or inaccessible" -ForegroundColor Yellow
}

# Check if any of the conditions are met to stop the script
if ($MDENotRunning) {
    Write-Host "[Action] Onboarding Microsoft Defender for Endpoint on the device is a prerequisite to run this script."
    Exit
} elseif ($NPDisabled -and $SmartScreenDisabled) {
    Write-Host "[Action] Enabling Network Protection or SmartScreen is a prerequisite to run this script."
    Exit
} elseif ($RealTimeProtectionDisabled) {
    Write-Host "[Action] Enabling Defender Antivirus - Real-Time Protection is a prerequisite to run this script."
    Exit
}

# Tamper Protection status
$TamperProtectionStatus = $DefenderStatus.IsTamperProtected
$TamperProtectionManage = $DefenderStatus.TamperProtectionSource

# Confirm if Tamper Protection is enabled or disabled
if ($TamperProtectionStatus -eq $true) {
    Write-Host "Tamper Protection Status :                                    [OK] Enabled" -ForegroundColor Green
} elseif ($TamperProtectionStatus -eq $false) {
    Write-Host "Tamper Protection Status :                                    [ERROR] Disabled" -ForegroundColor Yellow
} else {
    Write-Host "Tamper Protection Status :                                    [ERROR] Unknown - $tpStatus"  -ForegroundColor Red
}

# Confirm if Tamper Protection is managed by Microsoft or other
if ($TamperProtectionManage -eq "Intune") {
    Write-Host "Tamper Protection Source :                                    [OK] Intune" -ForegroundColor Green
} elseif ($TamperProtectionManage -eq "ATP") {
    Write-Host "Tamper Protection Source :                                    [OK] MDE Tenant" -ForegroundColor Green
} else {
    Write-Host "Tamper Protection Source :                                    [ERROR] Unknown - $tpManage"  -ForegroundColor Red
}


# Defender Preferences status
Write-Host ""
$DefenderPreferences = Get-MpPreference

# Checking IOAV Protection
if (-not $DefenderPreferences.DisableIOAVProtection) {
    Write-Host "IOAV Protection :                                             [OK] Enabled" -ForegroundColor Green
} else {
    Write-Host "IOAV Protection :                                             [ERROR] Disabled" -ForegroundColor Red
}

# Checking Email Scanning
if (-not $DefenderPreferences.DisableEmailScanning) {
    Write-Host "Email Scanning :                                              [OK] Enabled" -ForegroundColor Green
} else {
    Write-Host "Email Scanning :                                              [ERROR] Disabled" -ForegroundColor Red
}

# Checking Realtime Monitoring
if (-not $DefenderPreferences.DisableRealtimeMonitoring) {
    Write-Host "Realtime Monitoring :                                         [OK] Enabled" -ForegroundColor Green
} else {
    Write-Host "Realtime Monitoring :                                         [ERROR] Disabled" -ForegroundColor Red
}

# Checking Behavior Monitoring
if (-not $DefenderPreferences.DisableBehaviorMonitoring) {
    Write-Host "Behavior Monitoring :                                         [OK] Enabled" -ForegroundColor Green
} else {
    Write-Host "Behavior Monitoring :                                         [ERROR] Disabled" -ForegroundColor Red
}

# Check Microsoft Defender Exclusions
Write-Host ""
function Check-Exclusions {
    param ($exclusions)
    if ($exclusions -eq $null -or $exclusions -like "*N/A: Must be an administrator to view exclusions*") {
        return "[WARNING] No permissions to view Exclusions"
    } elseif ($exclusions.Count -eq 0) {
        return "[OK] No exclusions were found."
    } else {
        return "[ERROR] Exclusions were found."
    }
}

# Checking Exclusion Extensions
$exclusionExtensionsStatus = Check-Exclusions -exclusions $DefenderPreferences.ExclusionExtension
switch ($exclusionExtensionsStatus) {
    "[WARNING] No permissions to view Exclusions" {
        Write-Host "Exclusion Extensions :                                        $exclusionExtensionsStatus" -ForegroundColor Yellow
    }
    "[OK] No exclusions were found." {
        Write-Host "Exclusion Extensions :                                        $exclusionExtensionsStatus" -ForegroundColor Green
    }
    default {
        Write-Host "Exclusion Extensions :                                        $exclusionExtensionsStatus" -ForegroundColor Red
    }
}

# Checking Exclusion Paths
$exclusionPathsStatus = Check-Exclusions -exclusions $DefenderPreferences.ExclusionPath
switch ($exclusionPathsStatus) {
    "[WARNING] No permissions to view Exclusions" {
        Write-Host "Exclusion Paths :                                             $exclusionPathsStatus" -ForegroundColor Yellow
    }
    "[OK] No exclusions were found." {
        Write-Host "Exclusion Paths :                                             $exclusionPathsStatus" -ForegroundColor Green
    }
    default {
        Write-Host "Exclusion Paths :                                             $exclusionPathsStatus" -ForegroundColor Red
    }
}

# Bypass locked Exclusions by checking in Windows Events
Write-Host "Attempting to bypass exclusion list..."
$LogName = "Microsoft-Windows-Windows Defender/Operational"
$EventID = 5007
$Events = Get-WinEvent -LogName $LogName | Where-Object { $_.Id -eq $EventID }
$ExclusionEvents = $Events | Where-Object { $_.Message -match "Exclusions" }
$Pattern = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^`"]+)"
$foundExclusions = $false

foreach ($Event in $ExclusionEvents) {
    if ($Event.Message -match $Pattern) {
        Write-Host "  - $($Matches[1])"
        $foundExclusions = $true
    }
}

if (-not $foundExclusions) {
    Write-Host "Bypassed Exclusions:                                          [OK] None" -ForegroundColor Green
}


