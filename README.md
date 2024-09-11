# fkmde

![image](https://github.com/user-attachments/assets/8fa1fc4b-43c1-4789-8184-0138bd81d0b1)

`fkmde` is a specialized powershell script designed to evaluate the configuration and operational security of Microsoft Defender for Endpoint (MDE). It aids security professionals, system administrators, and penetration testers in identifying potential vulnerabilities and misconfigurations that might be exploited in a real-world attack.

## Features
- **Defender Full Audit**: Quickly assesses the status of real-time protection, tamper protection and exclusion settings to detect overly permissive rules that might allow malware to bypass scanning.
- **Bypass Privilege for Exclusions**: Utilizes Event 5007 to bypass the protected exclusions list in MDE.
- **Bypass Privilege for ASR Rules**: Utilizes Event 1121 to bypass the protected list of exclusions in ASR
  
<br />

![image](https://github.com/user-attachments/assets/a26c305c-0b55-49d9-a6bf-18a0367a63cf)

## Disclaimer
This tool is intended for educational and security research purposes only. The author is not responsible for misuse or for any damage that may occur from using this tool. It is the end user's responsibility to comply with all applicable laws and regulations. The use of this tool against targets without prior mutual consent is illegal.

## Credits
- [VakninHai](https://x.com/VakninHai/status/1796628601535652289/photo/1) - Privilege Bypassing through Windows Event 5007
- [ViziosDe](https://raw.githubusercontent.com/ViziosDe/MDExclusionParser/main/Invoke-MDExclusionParser.ps1) - Privilege Bypassing through Windows Event 1121
