param (
    [string]$Directory = "C:\Windows",  # Default to C:\Windows if not specified
    [int]$Depth = 1  # Default depth if not specified
)

# Path to MpCmdRun.exe
$MpPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"

# Function to disable or enable Windows Defender popups
function Toggle-DefenderPopup {
    param (
        [switch]$Disable
    )
    $keyPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.Defender.SecurityCenter"
    if ($Disable) {
        Write-Host "Disabling Windows Defender popups..."
        Reg.exe add $keyPath /v "Enabled" /t REG_DWORD /d "0" /f
    } else {
        Write-Host "Enabling Windows Defender popups..."
        Reg.exe delete $keyPath /v "Enabled" /f
    }
}

# Check if MpCmdRun.exe exists
if (-Not (Test-Path -Path $MpPath)) {
    Write-Host "Error: MpCmdRun.exe not found at $MpPath"
    return
}

# Check if the directory exists
if (-Not (Test-Path -Path $Directory -PathType Container)) {
    Write-Host "Error: Directory '$Directory' not found."
    return
}

# Disable Defender popups before scan
Toggle-DefenderPopup -Disable

# Start scanning the directories
$folders = Get-ChildItem -Path $Directory -Recurse -Directory -Depth ($Depth - 1) -ErrorAction SilentlyContinue | Sort-Object FullName
Write-Host "Found $($folders.Count) folders in $Directory within a depth of $Depth."
if ($folders.Count -eq 0) {
    Write-Host "No folders found."
    Toggle-DefenderPopup
    return
}

foreach ($folder in $folders) {
    $folderPath = $folder.FullName
    $output = & $MpPath -Scan -ScanType 3 -File "$folderPath\|*" 2>&1
    if ($output -match "was skipped") {
        Write-Host "[+] Folder excluded: $folderPath"
    }
    Write-Host -NoNewline "Processed $($folders.IndexOf($folder) + 1)/$($folders.Count) folders`r"
}

# Re-enable Defender popups after scan
Toggle-DefenderPopup

Write-Host "Enumeration complete."
