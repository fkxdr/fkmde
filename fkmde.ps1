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
        Write-Host "Microsoft Defender SmartScreen :                              [ERROR] Property SmartScreenEnabled does not exist" -ForegroundColor Yellow
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
