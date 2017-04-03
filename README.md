# **Inveigh**

Inveigh is a PowerShell LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system.  

## Wiki
* https://github.com/Kevin-Robertson/Inveigh/wiki

## Included In
* PowerShell Empire - https://github.com/PowerShellEmpire/Empire  
* PS>Attack - https://github.com/jaredhaight/psattack  
* p0wnedShell - https://github.com/Cn33liz/p0wnedShell  
* PowerUpSQL - https://github.com/NetSPI/PowerUpSQL  
* PoshC2 - https://github.com/nettitude/PoshC2  
* pupy - https://github.com/n1nj4sec/pupy  

## Special Thanks  
* Anyone that posted .NET packet sniffing examples  
* Responder - https://github.com/lgandx/Responder  
* Impacket - https://github.com/CoreSecurity/impacket  

## Overview

At its core, Inveigh is a .NET packet sniffer that listens and responds to LLMNR/mDNS/NBNS requests while also capturing incoming NTLMv1/NTLMv2 authentication attempts over the Windows SMB service. The primary advantage of this packet sniffing method on Windows is that port conflicts with default running services are avoided. Inveigh’s HTTP/HTTPS/Proxy based features are not provided through the packet sniffer, they are provided through TCP listeners. Inveigh relies on creating multiple runspaces to load the sniffer, listeners, and control functions within a single shell and PowerShell process.

##### Inveigh running with elevated privilege
![Inveigh](https://github.com/Kevin-Robertson/Inveigh/wiki/images/Inveigh.PNG)

Since the .NET packet sniffer requires elevated privilege, Inveigh also contains UDP listener based LLMNR/mDNS/NBNS functions. These listeners can provide the ability to perform spoofing with only unprivileged access. Port conflicts can still be an issue with any running Windows listeners bound to 0.0.0.0. This generally impacts LLMNR. On a system with the Windows LLMNR service running, Inveigh’s unprivileged LLMNR spoofer will not be able to start. Inveigh can generally perform unprivileged NBNS spoofing on systems with the NBNS service already running since it’s often not bound to 0.0.0.0. Most of Inveigh’s other features, with the primary exceptions of the packet sniffer’s SMB capture and HTTPS (due to certificate install privilege requirements), do not require elevated privilege. Note that an enabled local firewall blocking all relevant ports, and without a listed service with open firewall access suitable for migration, can still prevent Inveigh from working with just unprivileged access since privileged access will likely be needed to modify the firewall settings.  

By default, Inveigh will attempt to detect the privilege level and load the corresponding functions. 

##### Inveigh running without elevated privilege
![Unprivileged](https://github.com/Kevin-Robertson/Inveigh/wiki/images/Unpriv.PNG)

Inveigh provides NTLMv1/NTLMv2 HTTP/HTTPS/Proxy to SMB1/SMB2 relay through the Inveigh-Relay module. This module does not require elevated privilege, again with the exception of HTTPS, on the Inveigh host. However, since the module currently only has a PSExec type command execution attack, the relayed challenge/response will need to be from an account that has remote command execution privilege on the target. The Inveigh host itself can be targeted for relay if the goal is local privilege escalation.

##### Inveigh and Inveigh-Relay running together to execute an Empire 2.0 launcher
![Relay](https://github.com/Kevin-Robertson/Inveigh/wiki/images/Relay.PNG)
