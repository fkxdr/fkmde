$banner = @'
      _____         _____         _____         _____         _____
    .'     '.     .'     '.     .'     '.     .'     '.     .'     '.
   /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \
  |           | |           | |           | |           | |           |
  |  \     /  | |  \     /  | |  \     /  | |  \     /  | |  \     /  |
   \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /
    '._____.'     '._____.'     '._____.'     '._____.'     '._____.'       

   wmiprocess by @fkxdr
   https://github.com/fkxdr/fkxdr-mindmaps

'@

Write-Host $banner -ForegroundColor DarkGray

$TargetComputer = "localhost"
$Command = "powershell.exe -Command ""Add-Type -AssemblyName System.Windows.Forms; Write-Host 'Process creation successful from WMI test'; [System.Windows.Forms.MessageBox]::Show('Pwned with SYSTEM permissions.`n`nNo ASR rules have prevented this message-box and likely malicious code from being executed.`n`n(Block process creations originating from PSExec and WMI commands)', 'Security Alert - Vulnerable Asset', 'OK', 'Warning')"""

Write-Output "Attempting to create a process on $TargetComputer using WMI with command: $Command"
Write-Output ""
$WMIProcess = ([WMIClass]"\\$TargetComputer\root\cimv2:Win32_Process").Create($Command)

if ($WMIProcess.ReturnValue -eq 0) {
    Write-Output "Process creation successful: Command was launched."
} else {
    Write-Output "Process creation failed. Error code: $($WMIProcess.ReturnValue)"
}
