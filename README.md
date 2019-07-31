![Inveigh_logo](https://user-images.githubusercontent.com/5897462/62184298-69b5d280-b32b-11e9-9002-7d4f94c59731.png)

Inveigh is a PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system.  

## 1.4 Release Blog
* https://blog.netspi.com/inveigh-whats-new-in-version-1-4/

## Wiki
* https://github.com/Kevin-Robertson/Inveigh/wiki

## Included In
* PowerShell Empire - https://github.com/PowerShellEmpire/Empire  
* PS>Attack - https://github.com/jaredhaight/psattack  
* p0wnedShell - https://github.com/Cn33liz/p0wnedShell  
* PowerUpSQL - https://github.com/NetSPI/PowerUpSQL  
* PoshC2 - https://github.com/nettitude/PoshC2  
* pupy - https://github.com/n1nj4sec/pupy  
* Merlin - https://github.com/Ne0nd0g/merlin  

## Special Thanks  
* Anyone that posted .NET packet sniffing examples  
* Responder - https://github.com/lgandx/Responder  
* Impacket - https://github.com/SecureAuthCorp/impacket  

## Overview

At its core, Inveigh is a .NET packet sniffer that listens for and responds to LLMNR/mDNS/NBNS/DNS requests while also capturing incoming NTLMv1/NTLMv2 authentication attempts over the Windows SMB service. The primary advantage of this packet sniffing method on Windows is that port conflicts with default running services are avoided. Inveigh also contains HTTP/HTTPS/Proxy listeners for capturing incoming authentication requests and performing attacks. Inveigh relies on creating multiple runspaces to load the sniffer, listeners, and control functions within a single shell and PowerShell process.

##### Inveigh running with elevated privilege
![inveigh1 4](https://user-images.githubusercontent.com/5897462/45662029-1b5e6300-bace-11e8-8180-32f8d377d48b.PNG)

Since the .NET packet sniffer requires elevated privilege, Inveigh also contains UDP listener based LLMNR/mDNS/NBNS/DNS functions. These listeners can provide the ability to perform spoofing with only unprivileged access. Port conflicts can be an issue with any running listeners bound to 0.0.0.0 on some versions of Windows. Server 2016 and Windows 10 seem to have relaxed rules around exclusive use of the LLMNR and mDNS ports. Inveigh can usually perform unprivileged NBNS spoofing on all versions of Windows. Most of Inveigh’s other features, with the primary exceptions of the packet sniffer’s SMB capture and HTTPS (due to certificate install privilege requirements), do not require elevated privilege. Note that an enabled local firewall blocking all relevant ports, and without a listed service with open firewall access suitable for migration, can still prevent Inveigh from working with just unprivileged access since privileged access will likely be needed to modify the firewall settings.

By default, Inveigh will attempt to detect the privilege level and load the corresponding functions. 

Inveigh provides NTLMv1/NTLMv2 HTTP/HTTPS/Proxy to SMB2.1 relay through the Inveigh Relay module. This module does not require elevated privilege, again with the exception of HTTPS, on the Inveigh host. 

##### Inveigh Relay running with all attacks enabled  
![inveigh_relay1 4](https://user-images.githubusercontent.com/5897462/45662094-72fcce80-bace-11e8-8bc5-b546eedcb241.PNG)

Inveigh Relay session attack requires SMB tools from Invoke-TheHash  

* https://github.com/Kevin-Robertson/Invoke-TheHash



