# Inveigh
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to assist penetration testers that find themselves limited to a Windows system. This can commonly occur while performing phishing attacks, USB drive attacks, VLAN pivoting, or simply being restricted to a Windows system as part of client imposed restrictions.

# Notes
1. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/SMB NTLMv1/NTLMv2 challenge/response capture.
2. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets. 
3. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
4. HTTP challenge/response captures are performed with a dedicated listener.
5. The local LLMNR/NBNS services do not need to be disabled on the host system. 
6. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
7. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
8. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
9. Output files will be created in current working directory.
10. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.

# Usage
Obtain an elevated administrator or SYSTEM shell. If necessary, use a method to bypass script execution policy.

To execute with default settings:  
Inveigh.ps1 -i localip

To execute with features enabled/disabled:   
Inveigh.ps1 -i localip -LLMNR Y/N -NBNS Y/N -HTTP Y/N -HTTPS Y/N -SMB Y/N -Repeat Y/N -ForceWPADAuth Y/N

# Screenshot
![Inveigh](https://cloud.githubusercontent.com/assets/5897462/7216149/c49679ce-e5c2-11e4-9825-2abacc56e91f.PNG)
