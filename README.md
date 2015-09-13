# Inveigh
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to assist penetration testers that find themselves limited to a Windows system. This can commonly occur while performing phishing attacks, USB drive attacks, VLAN pivoting, or simply being restricted to a Windows system as part of client imposed restrictions.

# Requirements
Tested minimums are PowerShell 2.0 and .NET 3.5.

# Notes
1. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/HTTPS/SMB NTLMv1/NTLMv2 challenge/response capture.
2. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets. 
3. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
4. HTTP challenge/response captures are performed with a dedicated listener.
5. The local LLMNR/NBNS services do not need to be disabled on the host system. 
6. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
7. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
8. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
9. Output files will be created in current working directory.
10. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.
11. SMB relay support is experimental at this point, use caution if employing on a pen test.

# Usage
Obtain an elevated administrator or SYSTEM shell. If necessary, use a method to bypass the PowerShell script execution policy.

To execute with default settings:  
Inveigh.ps1

To execute with features enabled/disabled:   
Inveigh.ps1 -IP 'local IP' -SpoofIP 'local or remote IP' -LLMNR Y/N -NBNS Y/N -NBNSTypes 00,03,20,1B -HTTP Y/N -HTTPS Y/N -SMB Y/N -Repeat Y/N -ForceWPADAuth Y/N -Output 0,1,2 -OutputDir 'valid folder path'

# Screenshot
![inveigh-screenshot2](https://cloud.githubusercontent.com/assets/5897462/9102520/62f199c4-3bc1-11e5-87a7-08837950a04f.PNG)
