# Inveigh
Inveigh is a PowerShell LLMNR/NBNS spoofer designed to assist penetration testers that find themselves limited to a Windows system. This can commonly occur while performing phishing attacks, USB attacks, VLAN pivoting, or even restrictions from the client.

# Notes
1. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/SMB NTLMv1/NTLMv2 challenge/response capture.
2. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets. 
3. SMB captures are performed through sniffing.
4. HTTP captures are performed with a listener.
5. The local LLMNR/NBNS services do not need to be disabled on the client system. 
6. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
7. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall.
8. Output files will be created in current working directory.
9. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.
10. Code is proof of concept level and may not work under some scenarios.

# Usage
With default settings  
Inveigh.ps1 -i localip

With features enabled/disabled  
Inveigh.ps1 -i localip -LLMNR Y/N -NBNS Y/N -HTTP Y/N -SMB Y/N

# Screenshot
![Inveigh](https://cloud.githubusercontent.com/assets/5897462/7216149/c49679ce-e5c2-11e4-9825-2abacc56e91f.PNG)
