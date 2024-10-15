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
    $progressBarWidth = 50  # Width of the loading bar

    # Function to update the loading bar
    function Update-ProgressBar {
        param (
            [int]$Processed,
            [int]$Total
        )

        $percentage = ($Processed / $Total) * 100
        $blocks = [int]($Processed / $Total * $progressBarWidth)
        $loadingBar = ('#' * $blocks) + ('-' * ($progressBarWidth - $blocks))
        Write-Host -NoNewline "`r[$loadingBar] $Processed of $Total folders scanned ($([math]::Round($percentage, 2))%)"
    }

    # Update progress bar initially
    Update-ProgressBar -Processed $processedFolders -Total $totalFolders

    foreach ($folder in $folders) {
        $folderPath = $folder.FullName
        $output = & $MpPath -Scan -ScanType 3 -File "$folderPath\|*" 2>&1

        # Increment processed folder count
        $processedFolders++

        # Update the progress bar
        Update-ProgressBar -Processed $processedFolders -Total $totalFolders

        if ($output -match "was skipped") {
            # Add exclusion output below the progress bar without interrupting the bar
            Write-Host "`n[KO] $folderPath" -ForegroundColor Red
            # Reprint the progress bar to keep it visually above exclusions
            Update-ProgressBar -Processed $processedFolders -Total $totalFolders
        }
    }
}
catch {
    Write-Host "`nError occurred during folder enumeration or scan: $_"
}

# Re-enable Defender popups after scan
Toggle-DefenderPopup
Write-Host "`nEnumeration complete."
