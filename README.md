# fkmde

![image](https://github.com/user-attachments/assets/8fa1fc4b-43c1-4789-8184-0138bd81d0b1)

`fkmde` is a specialized powershell script designed to evaluate the configuration and operational security of Microsoft Defender for Endpoint (MDE). It aids security professionals, system administrators, and penetration testers in identifying potential vulnerabilities and misconfigurations that might be exploited in a real-world attack.

## Features
- **Defender Full Audit**: Quickly assesses the status of real-time protection, active/passive mode, tamper protection, bitlocker, memory integrity and exclusion settings to detect overly permissive rules that might allow malware to bypass scanning.
- **Bypass Exclusions and ASR Rules**: Utilizes Event 1121 and 5007 to bypass the protected exclusions list in MDE.
- **Exclusion Enumeration**: Allows for low privilege exclusion enumeration, without relying on event log bypass.
- **Clop Ransomware Bypass**: The script uses techniques similar to those used by Clop Ransomware to disable and evade Microsoft Defender.

## Usage

```powershell
fkmde.ps1
fkmde.ps1 --kill
fkmde.ps1 --enum <path> [depth]
```

- **`--kill` Parameter**  
  This parameter triggers a script that implements techniques similar to those used by Clop Ransomware to disable and evade Microsoft Defender. The script is not hardcoded into `fkmde`, but dynamically fetched from an external source to avoid pre-execution detection. This should be used *only* in secure, isolated environments for research purposes.

- **`--enum <path> [depth]` Parameter**  
  This parameter performs a comprehensive enumeration of directories by using `MpCmdRun.exe`, scanning for exclusions or misconfigurations without relying on event logs or admin permissions. The script dynamically disables Windows Defender popup notifications during execution to provide a seamless experience without alerting users. Upon completion, it safely re-enables the notifications.
  
> [!NOTE]
> Any scripts tampering with the defender are not directly embedded in `fkmde`. Instead, they are loaded dynamically to minimize detection by Defender for Endpoint when the tool is used solely for enumeration purposes.

![image](https://github.com/user-attachments/assets/4fd4b81f-c8a0-4a35-a4f8-2a688df8c5a8)

![image](https://github.com/user-attachments/assets/f722aaed-7dec-47ac-92a4-344cbcd5a7d7)

![image](https://github.com/user-attachments/assets/82f87057-d573-43ce-8745-0382374b5dd0)

![image](https://github.com/user-attachments/assets/dd051244-e1aa-46aa-a0d5-0bd0298a234a)

## Disclaimer
This tool is intended for educational and security research purposes only. The author is not responsible for misuse or for any damage that may occur from using this tool. It is the end user's responsibility to comply with all applicable laws and regulations. The use of this tool against targets without prior mutual consent is illegal.

## Credits
- [VakninHai](https://x.com/VakninHai/status/1796628601535652289/photo/1) - Privilege Bypassing through Windows Event 5007
- [ViziosDe](https://raw.githubusercontent.com/ViziosDe/MDExclusionParser/main/Invoke-MDExclusionParser.ps1) - Privilege Bypassing through Windows Event 1121
- [Friends Security](https://github.com/Friends-Security/SharpExclusionFinder) - Exclusions through MpCmdRun.exe
