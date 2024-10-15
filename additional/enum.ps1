# Path to MpCmdRun.exe
$MpPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"

# Function to disable or enable Windows Defender popups
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

    foreach ($folder in $folders) {
        $folderPath = $folder.FullName
        $output = & $MpPath -Scan -ScanType 3 -File "$folderPath\|*" 2>&1

        if ($output -match "was skipped") {
            # You can remove this if you don't want to see folder exclusions.
            Write-Host "[+] Folder excluded: $folderPath"
        }

        # Update progress bar instead of writing a new line for every folder.
        $processedFolders++
        Write-Progress -Activity "Scanning Folders" -Status "Scanned $processedFolders of $totalFolders" -PercentComplete (($processedFolders / $totalFolders) * 100)
    }
}
catch {
    Write-Host "Error occurred during folder enumeration or scan: $_"
}

# Re-enable Defender popups after scan
Toggle-DefenderPopup
Write-Host "Enumeration complete."
