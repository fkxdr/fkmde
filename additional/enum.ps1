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

if (-Not (Test-Path -Path $MpPath)) {
    Write-Host "Error: MpCmdRun.exe not found at $MpPath"
    return
}
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
    $progressBarWidth = 50  # Width of the loading bar

    foreach ($folder in $folders) {
        $folderPath = $folder.FullName
        $output = & $MpPath -Scan -ScanType 3 -File "$folderPath\|*" 2>&1

        # Increment processed folder count
        $processedFolders++

        # Calculate percentage and number of blocks to show
        $percentage = ($processedFolders / $totalFolders) * 100
        $blocks = [int]($processedFolders / $totalFolders * $progressBarWidth)
        $loadingBar = ('#' * $blocks) + ('-' * ($progressBarWidth - $blocks))

        # Clear the current line and update the progress bar on the same line
        Write-Host -NoNewline "`r[$loadingBar] $processedFolders of $totalFolders folders scanned ($([math]::Round($percentage, 2))%) "

        if ($output -match "was skipped") {
            Write-Host "`n                                                     [KO] $folderPath" -ForegroundColor Red
        }
    }
    Write-Host "`r[$loadingBar] $processedFolders of $totalFolders folders scanned ($([math]::Round($percentage, 2))%)" 
}
catch {
    Write-Host "`nError occurred during folder enumeration or scan: $_"
}

# Re-enable Defender popups after scan
Toggle-DefenderPopup
